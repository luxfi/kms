//go:build cgo && lux_accel_real

// Package capi real-build link directives.
//
// One and only one of `stub_default.go` or `real.go` is in any given
// build. The selector is the `lux_accel_real` build tag — see the
// header comment on stub_default.go for the design rationale.
//
// This file holds exactly two things:
//
//  1. `#cgo LDFLAGS: -lluxaccel` — link the binary against the real
//     native library. Combined with the `-L` search paths and rpaths
//     already declared in capi.go, the dynamic loader finds
//     libluxaccel.{so,dylib} at one of:
//
//       /usr/local/lib                       (canonical Linux install)
//       /opt/homebrew/lib                    (Apple Silicon Homebrew)
//       ${SRCDIR}/../../../../luxcpp/install/lib   (local checkout)
//
//  2. `#include <lux/accel/c_api.h>` — declares every `lux_*` entry
//     point as a normal (non-weak) extern. capi.go calls these from
//     Go via cgo wrappers; under this build tag the wrappers resolve
//     directly to libluxaccel's strong definitions, with no stub
//     bodies anywhere in the binary.
//
// Required host install (verified at boot via accel.Available()):
//
//   Linux  : /usr/local/lib/libluxaccel.so.0.1.2 (plus CUDA plugin
//            under $LUX_PLUGIN_PATH or /usr/local/lib/lux/plugins/)
//   Darwin : /opt/homebrew/lib/libluxaccel.dylib (plus Metal plugin
//            under /opt/homebrew/lib/lux/plugins/ or ~/.lux/plugins/)
//
// libluxaccel is self-contained: it links libluxgpu + libluxcrypto
// statically at build time inside luxcpp. Go consumers only need
// `-lluxaccel`.
package capi

/*
#cgo LDFLAGS: -lluxaccel

#include <lux/accel/c_api.h>
*/
import "C"
