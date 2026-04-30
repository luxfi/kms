package main

import "testing"

// TestNormalizeS3Endpoint covers the silent-disable bug fixed in
// startReplicator. A path-bearing or scheme-bearing endpoint must be
// reduced to bare host:port; minio.New rejects anything else with
// "Endpoint url cannot have fully qualified paths." and the historical
// behaviour was to silently disable replication.
func TestNormalizeS3Endpoint(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantHost string
		wantSSL  bool
	}{
		{"bare host:port", "s3.example:9000", "s3.example:9000", true},
		{"http scheme stripped, no SSL", "http://s3.example:9000", "s3.example:9000", false},
		{"https scheme stripped, SSL on", "https://s3.example:9000", "s3.example:9000", true},
		{"path stripped after http", "http://s3.example:9000/somebucket", "s3.example:9000", false},
		{"path stripped after https", "https://s3.example:9000/x/y/z", "s3.example:9000", true},
		{"trailing slash trimmed", "s3.example:9000/", "s3.example:9000", true},
		{"k8s svc DNS http", "http://s3.liquidity.svc.cluster.local:9000", "s3.liquidity.svc.cluster.local:9000", false},
		{"query stripped", "https://s3.example:9000/?versioning=on", "s3.example:9000", true},
		// Defensive: malformed input — return as-is so the operator sees
		// the original error from minio rather than a silently-mangled
		// host. Replication will still fail, but visibly.
		{"malformed scheme", "://broken", "://broken", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotHost, gotSSL := normalizeS3Endpoint(c.in)
			if gotHost != c.wantHost {
				t.Errorf("host: got %q want %q", gotHost, c.wantHost)
			}
			if gotSSL != c.wantSSL {
				t.Errorf("useSSL: got %v want %v", gotSSL, c.wantSSL)
			}
		})
	}
}

// TestFirstNonEmpty covers the credential-resolution fallback. The
// historical env var was REPLICATE_S3_ACCESS_KEY; AWS SDK chains and
// the operator-injected REPLICATE_S3_ACCESS_KEY_ID variant must take
// precedence in that order without one zeroing out another.
func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Errorf("all empty: got %q want empty", got)
	}
	if got := firstNonEmpty("a", "b", "c"); got != "a" {
		t.Errorf("first wins: got %q want a", got)
	}
	if got := firstNonEmpty("", "b", "c"); got != "b" {
		t.Errorf("second wins when first empty: got %q want b", got)
	}
	if got := firstNonEmpty("", "", "c"); got != "c" {
		t.Errorf("third wins when first two empty: got %q want c", got)
	}
}
