// Copyright (C) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package mpc

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWallet_MarshalJSON_EmitsBothAddressFields pins the contract
// that MarshalJSON writes both keccakAddress (canonical) and
// ethAddress (deprecated) with the same value, so downstream
// consumers using either name see the address during the migration.
func TestWallet_MarshalJSON_EmitsBothAddressFields(t *testing.T) {
	addr := "0xABCDef0123456789aBcdEf0123456789ABCDeF01"
	w := Wallet{
		ID:            "w1",
		KeyType:       "ecdsa",
		KeccakAddress: &addr,
	}
	out, err := json.Marshal(&w)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"keccakAddress":"`+addr+`"`) {
		t.Fatalf("missing keccakAddress in output: %s", s)
	}
	if !strings.Contains(s, `"ethAddress":"`+addr+`"`) {
		t.Fatalf("missing ethAddress mirror in output: %s", s)
	}
}

// TestWallet_UnmarshalJSON_PopulatesBothFromEitherKey pins the
// contract that the deserializer accepts either the canonical or
// deprecated JSON key and ends up with both struct fields populated.
func TestWallet_UnmarshalJSON_PopulatesBothFromEitherKey(t *testing.T) {
	addr := "0xABCDef0123456789aBcdEf0123456789ABCDeF01"

	// Case 1: source uses the deprecated ethAddress key.
	src1 := `{"id":"w1","keyType":"ecdsa","ethAddress":"` + addr + `"}`
	var w1 Wallet
	if err := json.Unmarshal([]byte(src1), &w1); err != nil {
		t.Fatal(err)
	}
	if w1.KeccakAddress == nil || *w1.KeccakAddress != addr {
		t.Fatalf("KeccakAddress not mirrored from ethAddress: got %+v", w1.KeccakAddress)
	}
	if w1.EthAddress == nil || *w1.EthAddress != addr {
		t.Fatalf("EthAddress was lost: got %+v", w1.EthAddress)
	}

	// Case 2: source uses the canonical keccakAddress key.
	src2 := `{"id":"w2","keyType":"ecdsa","keccakAddress":"` + addr + `"}`
	var w2 Wallet
	if err := json.Unmarshal([]byte(src2), &w2); err != nil {
		t.Fatal(err)
	}
	if w2.EthAddress == nil || *w2.EthAddress != addr {
		t.Fatalf("EthAddress not mirrored from keccakAddress: got %+v", w2.EthAddress)
	}
	if w2.KeccakAddress == nil || *w2.KeccakAddress != addr {
		t.Fatalf("KeccakAddress was lost: got %+v", w2.KeccakAddress)
	}

	// Case 3: source has neither; both stay nil.
	src3 := `{"id":"w3","keyType":"bls"}`
	var w3 Wallet
	if err := json.Unmarshal([]byte(src3), &w3); err != nil {
		t.Fatal(err)
	}
	if w3.KeccakAddress != nil || w3.EthAddress != nil {
		t.Fatalf("expected both addresses nil, got keccak=%v eth=%v",
			w3.KeccakAddress, w3.EthAddress)
	}
}

// TestKeygenResult mirrors the Wallet contract — same dual-field
// bridge applied to the keygen response.
func TestKeygenResult_DualFieldBridge(t *testing.T) {
	addr := "0xdeadbeefcafebabedeadbeefcafebabedeadbeef"

	// Marshal: writing struct → JSON emits both keys.
	k := KeygenResult{ID: "k1", KeccakAddress: &addr}
	out, err := json.Marshal(&k)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"keccakAddress":"`+addr+`"`) ||
		!strings.Contains(s, `"ethAddress":"`+addr+`"`) {
		t.Fatalf("dual emit broken: %s", s)
	}

	// Unmarshal: reading JSON with only ethAddress fills both.
	src := `{"id":"k2","ethAddress":"` + addr + `"}`
	var k2 KeygenResult
	if err := json.Unmarshal([]byte(src), &k2); err != nil {
		t.Fatal(err)
	}
	if k2.KeccakAddress == nil || *k2.KeccakAddress != addr {
		t.Fatalf("KeccakAddress not mirrored: %v", k2.KeccakAddress)
	}
}
