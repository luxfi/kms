// Command kms-operator reconciles KMSSecret CRDs against Lux KMS via ZAP.
//
// In-cluster consumers fetch secrets over the native luxfi/zap binary
// protocol (port 9999 on the KMS pod) — no HTTP, no auth tokens, no REST
// round-trips. Reconcile loop:
//
//  1. List KMSSecret CRDs via dynamic client
//  2. For each: Dial Lux KMS at spec.hostAPI:9999 with secretsPath as default
//  3. List then Get every secret in the scope
//  4. Write/update the K8s Secret named in spec.managedSecretReference
//
// Replaces the legacy hanzoai/kms-operator (Infisical-flavor SDK over HTTP).
//
//	Env:
//	  RESYNC_INTERVAL  reconcile interval seconds (default 60)
//	  WATCH_NAMESPACE  if set, watch only that ns; otherwise cluster-wide
//	  ZAP_PORT         port appended to KMSSecret hostAPI host (default 9999)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luxfi/kms/pkg/zapclient"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var kmsSecretGVR = schema.GroupVersionResource{
	Group: "secrets.lux.network", Version: "v1alpha1", Resource: "kmssecrets",
}

func main() {
	resync := envInt("RESYNC_INTERVAL", 60)
	zapPort := envInt("ZAP_PORT", 9999)
	ns := os.Getenv("WATCH_NAMESPACE")

	cfg, err := getRestConfig()
	if err != nil {
		log.Fatalf("k8s config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("dynamic client: %v", err)
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	if ns == "" {
		log.Printf("kms-operator: ZAP transport, watching cluster-wide, resync=%ds zap_port=%d", resync, zapPort)
	} else {
		log.Printf("kms-operator: ZAP transport, watching ns=%s, resync=%ds zap_port=%d", ns, resync, zapPort)
	}

	go func() {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
		log.Print("kms-operator: liveness on :8080/healthz")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(resync)*time.Second-5*time.Second)
		reconcileAll(ctx, dyn, kc, ns, zapPort)
		cancel()
		time.Sleep(time.Duration(resync) * time.Second)
	}
}

func reconcileAll(ctx context.Context, dyn dynamic.Interface, kc kubernetes.Interface, ns string, zapPort int) {
	var list dynamic.ResourceInterface
	if ns == "" {
		list = dyn.Resource(kmsSecretGVR)
	} else {
		list = dyn.Resource(kmsSecretGVR).Namespace(ns)
	}
	objs, err := list.List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("kms-operator: list KMSSecrets: %v", err)
		return
	}
	log.Printf("kms-operator: reconciling %d KMSSecret(s)", len(objs.Items))
	for i := range objs.Items {
		o := &objs.Items[i]
		if err := reconcile(ctx, kc, o.Object, zapPort); err != nil {
			log.Printf("kms-operator: %s/%s: %v", o.GetNamespace(), o.GetName(), err)
		}
	}
}

func reconcile(ctx context.Context, kc kubernetes.Interface, obj map[string]any, zapPort int) error {
	meta, _ := obj["metadata"].(map[string]any)
	spec, _ := obj["spec"].(map[string]any)
	if meta == nil || spec == nil {
		return fmt.Errorf("malformed: missing metadata or spec")
	}
	name := str(meta, "name")
	ns := str(meta, "namespace")

	hostAPI := str(spec, "hostAPI")
	if hostAPI == "" {
		hostAPI = "http://zap.kms.svc.cluster.local"
	}
	zapAddr := zapAddrFromHost(hostAPI, zapPort)

	auth, _ := spec["authentication"].(map[string]any)
	ua, _ := auth["universalAuth"].(map[string]any)
	scope, _ := ua["secretsScope"].(map[string]any)
	if scope == nil {
		return fmt.Errorf("missing authentication.universalAuth.secretsScope")
	}
	env := strDefault(scope, "envSlug", "default")
	path := strDefault(scope, "secretsPath", "/")

	target, _ := spec["managedSecretReference"].(map[string]any)
	tName := str(target, "secretName")
	tNS := strDefault(target, "secretNamespace", ns)
	tType := strDefault(target, "secretType", "Opaque")
	if tName == "" {
		return fmt.Errorf("missing managedSecretReference.secretName")
	}

	zc, err := zapclient.Dial(ctx, zapAddr, path)
	if err != nil {
		return fmt.Errorf("zap dial %s: %w", zapAddr, err)
	}
	defer zc.Close()

	names, err := zc.ListAt(ctx, path, env)
	if err != nil {
		return fmt.Errorf("zap list path=%s env=%s: %w", path, env, err)
	}

	data := make(map[string][]byte, len(names))
	for _, n := range names {
		v, err := zc.GetAt(ctx, path, n, env)
		if err != nil {
			log.Printf("kms-operator: %s/%s: skip %s: %v", ns, name, n, err)
			continue
		}
		data[n] = []byte(v)
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tName,
			Namespace: tNS,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":         "lux-kms-operator",
				"kmssecret.secrets.lux.network/source": name,
			},
		},
		Type: corev1.SecretType(tType),
		Data: data,
	}

	existing, err := kc.CoreV1().Secrets(tNS).Get(ctx, tName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := kc.CoreV1().Secrets(tNS).Create(ctx, desired, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create %s/%s: %w", tNS, tName, err)
		}
		log.Printf("kms-operator: %s/%s -> created %s/%s with %d keys (zap)", ns, name, tNS, tName, len(data))
	case err != nil:
		return fmt.Errorf("get %s/%s: %w", tNS, tName, err)
	default:
		existing.Data = desired.Data
		existing.Type = desired.Type
		if existing.Labels == nil {
			existing.Labels = desired.Labels
		} else {
			for k, v := range desired.Labels {
				existing.Labels[k] = v
			}
		}
		if _, err := kc.CoreV1().Secrets(tNS).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update %s/%s: %w", tNS, tName, err)
		}
		log.Printf("kms-operator: %s/%s -> updated %s/%s with %d keys (zap)", ns, name, tNS, tName, len(data))
	}
	return nil
}

// zapAddrFromHost extracts the host from a URL or bare host string and
// joins it with the ZAP port. e.g. "http://api.kms.svc:80" + 9999
//                              → "api.kms.svc:9999".
func zapAddrFromHost(hostAPI string, port int) string {
	host := hostAPI
	if u, err := url.Parse(hostAPI); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
		if j := strings.IndexAny(host, "/:"); j >= 0 {
			host = host[:j]
		}
	} else if j := strings.IndexAny(host, "/:"); j >= 0 {
		host = host[:j]
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func getRestConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func strDefault(m map[string]any, k, def string) string {
	if v := str(m, k); v != "" {
		return v
	}
	return def
}
