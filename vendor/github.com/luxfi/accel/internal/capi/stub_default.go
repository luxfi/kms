//go:build cgo && !lux_accel_real

// Package capi default-build stub implementations.
//
// One and only one of `stub_default.go` or `real.go` is in any given
// build. The selector is the `lux_accel_real` build tag:
//
//	go build ./...                          # this file is compiled,
//	                                        # every C entry returns
//	                                        # LUX_NO_BACKEND. Portable
//	                                        # CPU-only binary.
//
//	go build -tags lux_accel_real ./...     # real.go is compiled instead,
//	                                        # binary links -lluxaccel and
//	                                        # dispatches to the native
//	                                        # CUDA / Metal plugin.
//
// History: an earlier revision used `__attribute__((weak))` on every
// stub and tried to override at link time when libluxaccel was present.
// Modern linkers with --as-needed default resolved the references
// against the weak stubs (already in the Go object) and dropped the
// DT_NEEDED entry for libluxaccel entirely. Result: GPU paths silently
// ran on CPU. Audit on a Spark GB10 host (2026-06-05) measured 9-10%
// SM during a full ML-DSA bench that was supposed to be GPU-accelerated.
// The build-tag split removes the weak-symbol ambiguity: either the
// stub bodies compile, or the link to the real library does — never
// both.
//
// All stubs return LUX_NO_BACKEND. The Go-side ops dispatcher (see
// `crypto/backend.Resolve` in luxfi/crypto and `ops/lattice/lattice.go`
// in this module) maps LUX_NO_BACKEND to a per-element CPU fallback,
// so default-tag binaries remain functionally complete — just slower.
package capi

/*
#include <lux/accel/c_api.h>
#include <stdlib.h>
#include <string.h>

static const char* _stub_version(void) { return "stub-0.0.0"; }
static const char* _stub_error(void)   { return "no accel library (built without -tags lux_accel_real)"; }

lux_status lux_init(void)               { return LUX_NO_BACKEND; }
void       lux_shutdown(void)           {}
const char* lux_version(void)           { return _stub_version(); }
const char* lux_get_error(void)         { return _stub_error(); }

lux_status lux_load_backend(const char* p) { (void)p; return LUX_NO_BACKEND; }
int        lux_backend_count(void)         { return 0; }
lux_backend_type lux_backend_type_at(int i){ (void)i; return 0; }
int        lux_device_count(lux_backend_type b) { (void)b; return 0; }
lux_status lux_get_device_info(lux_backend_type b, int i, lux_device_info* o) {
    (void)b; (void)i;
    if (o) memset(o, 0, sizeof(*o));
    return LUX_NO_BACKEND;
}

lux_status lux_session_create(lux_session* s)                                          { if(s)*s=NULL; return LUX_NO_BACKEND; }
lux_status lux_session_create_with_backend(lux_backend_type b, lux_session* s)         { (void)b; if(s)*s=NULL; return LUX_NO_BACKEND; }
lux_status lux_session_create_with_device(lux_backend_type b, int d, lux_session* s)   { (void)b; (void)d; if(s)*s=NULL; return LUX_NO_BACKEND; }
void       lux_session_destroy(lux_session s)                                          { (void)s; }
lux_status lux_session_sync(lux_session s)                                             { (void)s; return LUX_NO_BACKEND; }
lux_status lux_session_get_device_info(lux_session s, lux_device_info* o) {
    (void)s;
    if (o) memset(o, 0, sizeof(*o));
    return LUX_NO_BACKEND;
}

lux_status lux_tensor_create(lux_session s, lux_dtype d, const size_t* sh, size_t nd, lux_tensor* t)                                 { (void)s; (void)d; (void)sh; (void)nd; if(t)*t=NULL; return LUX_NO_BACKEND; }
lux_status lux_tensor_create_with_data(lux_session s, lux_dtype d, const size_t* sh, size_t nd, const void* data, size_t len, lux_tensor* t) { (void)s; (void)d; (void)sh; (void)nd; (void)data; (void)len; if(t)*t=NULL; return LUX_NO_BACKEND; }
void       lux_tensor_destroy(lux_tensor t)                                                                                          { (void)t; }
size_t     lux_tensor_ndim(lux_tensor t)                                                                                             { (void)t; return 0; }
size_t     lux_tensor_shape(lux_tensor t, size_t d)                                                                                  { (void)t; (void)d; return 0; }
size_t     lux_tensor_numel(lux_tensor t)                                                                                            { (void)t; return 0; }
size_t     lux_tensor_bytes(lux_tensor t)                                                                                            { (void)t; return 0; }
lux_dtype  lux_tensor_dtype(lux_tensor t)                                                                                            { (void)t; return 0; }
lux_status lux_tensor_to_host(lux_tensor t, void* d, size_t n)                                                                       { (void)t; (void)d; (void)n; return LUX_NO_BACKEND; }
lux_status lux_tensor_from_host(lux_tensor t, const void* d, size_t n)                                                               { (void)t; (void)d; (void)n; return LUX_NO_BACKEND; }

// ML ops
lux_status lux_matmul(lux_session s, lux_tensor a, lux_tensor b, lux_tensor c)                                              { (void)s; (void)a; (void)b; (void)c; return LUX_NO_BACKEND; }
lux_status lux_relu(lux_session s, lux_tensor i, lux_tensor o)                                                              { (void)s; (void)i; (void)o; return LUX_NO_BACKEND; }
lux_status lux_gelu(lux_session s, lux_tensor i, lux_tensor o)                                                              { (void)s; (void)i; (void)o; return LUX_NO_BACKEND; }
lux_status lux_softmax(lux_session s, lux_tensor i, lux_tensor o, int ax)                                                   { (void)s; (void)i; (void)o; (void)ax; return LUX_NO_BACKEND; }
lux_status lux_layer_norm(lux_session s, lux_tensor i, lux_tensor g, lux_tensor b, lux_tensor o, float e)                   { (void)s; (void)i; (void)g; (void)b; (void)o; (void)e; return LUX_NO_BACKEND; }
lux_status lux_attention(lux_session s, lux_tensor q, lux_tensor k, lux_tensor v, lux_tensor o, float sc)                   { (void)s; (void)q; (void)k; (void)v; (void)o; (void)sc; return LUX_NO_BACKEND; }

// Crypto ops
lux_status lux_sha256(lux_session s, lux_tensor i, lux_tensor o)                                                            { (void)s; (void)i; (void)o; return LUX_NO_BACKEND; }
lux_status lux_keccak256(lux_session s, lux_tensor i, lux_tensor o)                                                         { (void)s; (void)i; (void)o; return LUX_NO_BACKEND; }
lux_status lux_poseidon(lux_session s, lux_tensor i, lux_tensor o)                                                          { (void)s; (void)i; (void)o; return LUX_NO_BACKEND; }
lux_status lux_ecdsa_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r)                  { (void)s; (void)m; (void)sg; (void)pk; (void)r; return LUX_NO_BACKEND; }
lux_status lux_ed25519_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r)                { (void)s; (void)m; (void)sg; (void)pk; (void)r; return LUX_NO_BACKEND; }
lux_status lux_bls_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r)                    { (void)s; (void)m; (void)sg; (void)pk; (void)r; return LUX_NO_BACKEND; }
lux_status lux_merkle_root(lux_session s, lux_tensor l, lux_tensor r)                                                       { (void)s; (void)l; (void)r; return LUX_NO_BACKEND; }

// ZK ops
lux_status lux_ntt(lux_session s, lux_tensor i, lux_tensor o, lux_tensor rt, uint64_t m)                                    { (void)s; (void)i; (void)o; (void)rt; (void)m; return LUX_NO_BACKEND; }
lux_status lux_intt(lux_session s, lux_tensor i, lux_tensor o, lux_tensor ir, uint64_t m)                                   { (void)s; (void)i; (void)o; (void)ir; (void)m; return LUX_NO_BACKEND; }
lux_status lux_msm(lux_session s, lux_tensor sc, lux_tensor ba, lux_tensor r)                                               { (void)s; (void)sc; (void)ba; (void)r; return LUX_NO_BACKEND; }
lux_status lux_poly_mul(lux_session s, lux_tensor a, lux_tensor b, lux_tensor c, uint64_t m)                                { (void)s; (void)a; (void)b; (void)c; (void)m; return LUX_NO_BACKEND; }

// Lattice / PQC ops
lux_status lux_kyber_keygen(lux_session s, lux_tensor pk, lux_tensor sk)                                                    { (void)s; (void)pk; (void)sk; return LUX_NO_BACKEND; }
lux_status lux_kyber_encaps(lux_session s, lux_tensor pk, lux_tensor ct, lux_tensor ss)                                     { (void)s; (void)pk; (void)ct; (void)ss; return LUX_NO_BACKEND; }
lux_status lux_kyber_decaps(lux_session s, lux_tensor ct, lux_tensor sk, lux_tensor ss)                                     { (void)s; (void)ct; (void)sk; (void)ss; return LUX_NO_BACKEND; }
lux_status lux_dilithium_sign(lux_session s, lux_tensor m, lux_tensor sk, lux_tensor sg)                                    { (void)s; (void)m; (void)sk; (void)sg; return LUX_NO_BACKEND; }
lux_status lux_dilithium_verify(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, int* v)                          { (void)s; (void)m; (void)sg; (void)pk; if(v)*v=0; return LUX_NO_BACKEND; }
lux_status lux_slhdsa_sign_batch(lux_session s, int mode, lux_tensor m, lux_tensor sk, lux_tensor sg)                       { (void)s; (void)mode; (void)m; (void)sk; (void)sg; return LUX_NO_BACKEND; }
lux_status lux_slhdsa_verify_batch(lux_session s, int mode, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r)       { (void)s; (void)mode; (void)m; (void)sg; (void)pk; (void)r; return LUX_NO_BACKEND; }
lux_status lux_mldsa_sign_batch(lux_session s, int mode, lux_tensor m, lux_tensor sk, lux_tensor sg)                        { (void)s; (void)mode; (void)m; (void)sk; (void)sg; return LUX_NO_BACKEND; }
lux_status lux_mldsa_verify_batch(lux_session s, int mode, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r)        { (void)s; (void)mode; (void)m; (void)sg; (void)pk; (void)r; return LUX_NO_BACKEND; }
lux_status lux_lattice_ntt_mldsa_batch(lux_session s, lux_tensor polys, int inv)                                            { (void)s; (void)polys; (void)inv; return LUX_NO_BACKEND; }

// FHE ops
lux_status lux_bfv_encrypt(lux_session s, lux_tensor p, lux_tensor pk, lux_tensor c)                                        { (void)s; (void)p; (void)pk; (void)c; return LUX_NO_BACKEND; }
lux_status lux_bfv_decrypt(lux_session s, lux_tensor c, lux_tensor sk, lux_tensor p)                                        { (void)s; (void)c; (void)sk; (void)p; return LUX_NO_BACKEND; }
lux_status lux_bfv_add(lux_session s, lux_tensor a, lux_tensor b, lux_tensor r)                                             { (void)s; (void)a; (void)b; (void)r; return LUX_NO_BACKEND; }
lux_status lux_bfv_multiply(lux_session s, lux_tensor a, lux_tensor b, lux_tensor rk, lux_tensor r)                         { (void)s; (void)a; (void)b; (void)rk; (void)r; return LUX_NO_BACKEND; }

// DEX ops
lux_status lux_constant_product_swap(lux_session s, lux_tensor rx, lux_tensor ry, lux_tensor ai, int d, lux_tensor ao, float f) { (void)s; (void)rx; (void)ry; (void)ai; (void)d; (void)ao; (void)f; return LUX_NO_BACKEND; }
lux_status lux_compute_twap(lux_session s, lux_tensor p, lux_tensor ts, uint64_t st, uint64_t en, lux_tensor tw)                { (void)s; (void)p; (void)ts; (void)st; (void)en; (void)tw; return LUX_NO_BACKEND; }
lux_status lux_match_orders(lux_session s, lux_tensor bi, lux_tensor ak, lux_tensor mt, lux_tensor pr, lux_tensor am)            { (void)s; (void)bi; (void)ak; (void)mt; (void)pr; (void)am; return LUX_NO_BACKEND; }
*/
import "C"
