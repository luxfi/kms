// Command kms-operator is a minimal reconciler for KMSSecret CRDs.
//
// Single binary, ~200 lines. No controller-runtime, no codegen. Lists
// KMSSecret CRDs every RESYNC_INTERVAL seconds, reconciles each by:
//
//  1. Loading machineIdentity creds from the referenced K8s Secret.
//  2. POST /v1/kms/auth/login → bearer token.
//  3. GET /v1/kms/orgs/{org}/secrets?env=&path= → secret list.
//  4. Writing/updating the K8s Secret named in spec.managedSecretReference.
//
// Replaces the legacy hanzoai/kms-operator (which spoke Infisical's API).
// CRD schema kept identical (secrets.lux.network/v1alpha1 KMSSecret) so
// existing manifests don't change.
//
//	Env vars:
//	  RESYNC_INTERVAL  reconcile interval seconds (default 60)
//	  WATCH_NAMESPACE  if set, watch only that ns; otherwise cluster-wide
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/luxfi/kms/pkg/client"

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
		log.Printf("kms-operator: watching KMSSecrets cluster-wide, resync=%ds", resync)
	} else {
		log.Printf("kms-operator: watching KMSSecrets in ns=%s, resync=%ds", ns, resync)
	}

	// Liveness endpoint.
	go func() {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok"}`))
		})
		log.Print("kms-operator: liveness on :8080/healthz")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("listen: %v", err)
		}
	}()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(resync)*time.Second-5*time.Second)
		reconcileAll(ctx, dyn, kc, ns)
		cancel()
		time.Sleep(time.Duration(resync) * time.Second)
	}
}

func reconcileAll(ctx context.Context, dyn dynamic.Interface, kc kubernetes.Interface, ns string) {
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
		if err := reconcile(ctx, dyn, kc, o.Object); err != nil {
			log.Printf("kms-operator: %s/%s: %v", o.GetNamespace(), o.GetName(), err)
		}
	}
}

func reconcile(ctx context.Context, dyn dynamic.Interface, kc kubernetes.Interface, obj map[string]any) error {
	name, _ := obj["metadata"].(map[string]any)["name"].(string)
	ns, _ := obj["metadata"].(map[string]any)["namespace"].(string)
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return fmt.Errorf("missing spec")
	}

	hostAPI := str(spec, "hostAPI")
	if hostAPI == "" {
		hostAPI = "http://kms.lux-kms-go.svc.cluster.local"
	}

	auth, _ := spec["authentication"].(map[string]any)
	ua, _ := auth["universalAuth"].(map[string]any)
	if ua == nil {
		return fmt.Errorf("only universalAuth is supported")
	}
	credsRef, _ := ua["credentialsRef"].(map[string]any)
	scope, _ := ua["secretsScope"].(map[string]any)

	credsName := str(credsRef, "secretName")
	credsNS := strDefault(credsRef, "secretNamespace", ns)
	credsK8sSec, err := kc.CoreV1().Secrets(credsNS).Get(ctx, credsName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read auth secret %s/%s: %w", credsNS, credsName, err)
	}
	clientID := string(credsK8sSec.Data["clientId"])
	clientSecret := string(credsK8sSec.Data["clientSecret"])
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("auth secret %s/%s missing clientId/clientSecret", credsNS, credsName)
	}

	c := client.NewKMSClient(ctx, client.Config{SiteUrl: hostAPI})
	if _, err := c.Auth().UniversalAuthLogin(clientID, clientSecret); err != nil {
		return fmt.Errorf("kms login: %w", err)
	}

	secrets, err := c.Secrets().List(client.ListSecretsOptions{
		ProjectSlug: str(scope, "projectSlug"),
		Environment: str(scope, "envSlug"),
		SecretPath:  strDefault(scope, "secretsPath", "/"),
		Recursive:   false,
	})
	if err != nil {
		return fmt.Errorf("kms list: %w", err)
	}

	target, _ := spec["managedSecretReference"].(map[string]any)
	tName := str(target, "secretName")
	tNS := strDefault(target, "secretNamespace", ns)
	tType := strDefault(target, "secretType", "Opaque")
	if tName == "" {
		return fmt.Errorf("missing managedSecretReference.secretName")
	}

	data := map[string][]byte{}
	for _, s := range secrets {
		data[s.SecretKey] = []byte(s.SecretValue)
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tName,
			Namespace: tNS,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "lux-kms-operator", "kmssecret.secrets.lux.network/source": name},
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
		log.Printf("kms-operator: %s/%s -> created %s/%s with %d keys", ns, name, tNS, tName, len(data))
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
		log.Printf("kms-operator: %s/%s -> updated %s/%s with %d keys", ns, name, tNS, tName, len(data))
	}
	return nil
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

// dump for debug only
var _ = json.Marshal
