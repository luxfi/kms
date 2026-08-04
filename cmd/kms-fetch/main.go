// Command kms-fetch materialises secrets from KMS into a tmpfs the main
// container reads, as an initContainer.
//
// It exists so that Kubernetes Secrets disappear. A Secret is a second copy of
// a credential, at rest, in etcd, replicated to every node that schedules the
// pod — and keeping it in sync with KMS needs a controller, a CRD, and a
// reconcile loop, each of which is another thing that can hold a stale value or
// answer an empty one. Fetching at boot removes all of it: the credential lives
// in KMS and nowhere else, and the pod carries at most one bootstrap identity.
//
// The transport is ZAP. The client this uses has no HTTP fallback, so there is
// one wire and it is the encrypted one.
//
//	env  KMS_ADDR      KMS ZAP host:port      (default zap.kms.svc.cluster.local:9999)
//	env  KMS_ENV       environment slug       (default "default")
//	env  KMS_SECRETS   what to fetch: NAME=path/key, comma-separated. REQUIRED.
//	env  OUT_DIR       where to write         (default /secrets)
//	env  WRITE_ENV_FILE  also write OUT_DIR/env as KEY=value  (default true)
//
// Each key lands in its own file mode 0400, plus an optional `env` aggregate a
// wrapper can source:
//
//	set -a; . /secrets/env; set +a
//
// The secret list is DATA — a values file, not code — so adding a secret to a
// service is an edit to its manifest and never a rebuild of this binary.
//
// Exit codes are distinct because an initContainer's failure is read from its
// exit status before anyone reads its log:
//
//	0  every secret resolved and written
//	2  bad configuration — nothing was attempted
//	3  could not reach KMS
//	4  a named secret could not be resolved
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luxfi/kms"
)

const (
	exitConfig = 2
	exitDial   = 3
	exitFetch  = 4

	dialTimeout  = 15 * time.Second
	fetchTimeout = 10 * time.Second
)

// spec is one entry of KMS_SECRETS: the file (and env var) name it lands under,
// and the KMS coordinate it comes from.
type spec struct {
	as   string // NAME — the filename written, and the env var in the aggregate
	path string // KMS path
	key  string // KMS secret name
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

type dialError struct{ err error }

func (e *dialError) Error() string { return "reach KMS: " + e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

type fetchError struct {
	as  string
	err error
}

func (e *fetchError) Error() string { return "fetch " + e.as + ": " + e.err.Error() }
func (e *fetchError) Unwrap() error { return e.err }

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "kms-fetch:", err)
		os.Exit(exitFor(err))
	}
}

func exitFor(err error) int {
	var c *configError
	var d *dialError
	var f *fetchError
	switch {
	case errors.As(err, &c):
		return exitConfig
	case errors.As(err, &d):
		return exitDial
	case errors.As(err, &f):
		return exitFetch
	default:
		return 1
	}
}

func run(ctx context.Context) error {
	raw := strings.TrimSpace(os.Getenv("KMS_SECRETS"))
	if raw == "" {
		return &configError{"KMS_SECRETS is required: a comma-separated NAME=path/key list"}
	}
	specs, err := parseSpecs(raw)
	if err != nil {
		return &configError{err.Error()}
	}

	outDir := envOr("OUT_DIR", "/secrets")
	env := envOr("KMS_ENV", "")
	addr := envOr("KMS_ADDR", "")

	// Everything is fetched BEFORE anything is written. A partial write leaves a
	// pod that starts with some of its credentials, which fails later and
	// somewhere else; failing here means the initContainer never completes and
	// the pod never runs at all.
	values := make(map[string]string, len(specs))
	for _, s := range specs {
		cfg := kms.Config{Addr: addr, Path: s.path, Env: env}

		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout+fetchTimeout)
		v, err := kms.GetWith(dialCtx, cfg, s.key)
		cancel()
		if err != nil {
			// A dial failure and a missing secret are different operator
			// problems: one is "KMS is unreachable", the other is "this name is
			// wrong". They get different exit codes so the distinction survives
			// into `kubectl get pod`.
			if isUnreachable(err) {
				return &dialError{err}
			}
			return &fetchError{as: s.as, err: err}
		}
		if v == "" {
			return &fetchError{as: s.as, err: errors.New("resolved to an empty value")}
		}
		values[s.as] = v
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	for as, v := range values {
		if err := writeAtomic(filepath.Join(outDir, as), []byte(v), 0o400); err != nil {
			return err
		}
	}

	if envOr("WRITE_ENV_FILE", "true") == "true" {
		names := make([]string, 0, len(values))
		for as := range values {
			names = append(names, as)
		}
		sort.Strings(names) // stable file, so a diff of it means a real change
		var b strings.Builder
		for _, as := range names {
			fmt.Fprintf(&b, "%s=%s\n", as, values[as])
		}
		if err := writeAtomic(filepath.Join(outDir, "env"), []byte(b.String()), 0o400); err != nil {
			return err
		}
	}
	return nil
}

// parseSpecs reads `NAME=path/key` entries. The last '/' splits the coordinate,
// so a path may have as many segments as it likes and the key may not contain
// one — which matches the store, where a name is a single segment.
func parseSpecs(raw string) ([]spec, error) {
	var out []spec
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		as, coord, ok := strings.Cut(part, "=")
		as, coord = strings.TrimSpace(as), strings.TrimSpace(coord)
		if !ok || as == "" || coord == "" {
			return nil, fmt.Errorf("%q is not NAME=path/key", part)
		}
		if strings.ContainsAny(as, `/\`) {
			return nil, fmt.Errorf("%q is not a usable filename", as)
		}
		if seen[as] {
			// Two entries writing one file: whichever won would be a coin toss.
			return nil, fmt.Errorf("%q is named twice", as)
		}
		seen[as] = true

		path, key := "", coord
		if i := strings.LastIndex(coord, "/"); i >= 0 {
			path, key = coord[:i], coord[i+1:]
		}
		if key == "" {
			return nil, fmt.Errorf("%q names no secret", part)
		}
		out = append(out, spec{as: as, path: path, key: key})
	}
	if len(out) == 0 {
		return nil, errors.New("no secrets named")
	}
	return out, nil
}

// writeAtomic writes via a temp file in the same directory and renames, so a
// reader never sees a half-written secret and a crash never leaves one.
func writeAtomic(dst string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".kms-fetch-*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", dst, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	if err := os.Chmod(name, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	if err := os.Rename(name, dst); err != nil {
		return fmt.Errorf("rename into %s: %w", dst, err)
	}
	return nil
}

// isUnreachable distinguishes "KMS did not answer" from "KMS answered, and the
// answer was no".
func isUnreachable(err error) bool {
	// Signatures are lowercase because the haystack is lowercased; "EOF" here
	// would never match and the caller would report a dead KMS as a bad name.
	s := strings.ToLower(err.Error())
	for _, sig := range []string{"dial", "connection refused", "no such host", "timeout", "deadline exceeded", "eof"} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
