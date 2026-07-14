// Copyright (C) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package mpc

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWallet_MarshalJSON_EmitsEVMAddress pins the canonical wire
// shape: only evmAddress, no legacy aliases.
func TestWallet_MarshalJSON_EmitsEVMAddress(t *testing.T) {
	addr := "0xABCDef0123456789aBcdEf0123456789ABCDeF01"
	w := Wallet{
		ID:         "w1",
		KeyType:    "ecdsa",
		EVMAddress: &addr,
	}
	out, err := json.Marshal(&w)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"evmAddress":"`+addr+`"`) {
		t.Fatalf("missing evmAddress in output: %s", s)
	}
	if strings.Contains(s, "keccakAddress") || strings.Contains(s, "ethAddress") {
		t.Fatalf("legacy address alias leaked into output: %s", s)
	}
}

// TestWallet_UnmarshalJSON_AcceptsEVMAddress pins the canonical wire
// shape on the read side.
func TestWallet_UnmarshalJSON_AcceptsEVMAddress(t *testing.T) {
	addr := "0xABCDef0123456789aBcdEf0123456789ABCDeF01"
	src := `{"id":"w1","keyType":"ecdsa","evmAddress":"` + addr + `"}`
	var w Wallet
	if err := json.Unmarshal([]byte(src), &w); err != nil {
		t.Fatal(err)
	}
	if w.EVMAddress == nil || *w.EVMAddress != addr {
		t.Fatalf("EVMAddress not populated: got %+v", w.EVMAddress)
	}
}

// TestKeygenResult_EVMAddress mirrors the Wallet contract.
func TestKeygenResult_EVMAddress(t *testing.T) {
	addr := "0xdeadbeefcafebabedeadbeefcafebabedeadbeef"

	// Marshal: only evmAddress emitted.
	k := KeygenResult{ID: "k1", EVMAddress: &addr}
	out, err := json.Marshal(&k)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// snake_case matches the mpcd ZAP keygen response (evm_address). camelCase
	// was the wire drift that silently decoded to empty — see wire_contract_test.go.
	if !strings.Contains(s, `"evm_address":"`+addr+`"`) {
		t.Fatalf("missing evm_address: %s", s)
	}
	if strings.Contains(s, "keccakAddress") || strings.Contains(s, "ethAddress") || strings.Contains(s, "evmAddress") {
		t.Fatalf("legacy alias leaked: %s", s)
	}

	// Unmarshal: evm_address populates EVMAddress.
	src := `{"id":"k2","evm_address":"` + addr + `"}`
	var k2 KeygenResult
	if err := json.Unmarshal([]byte(src), &k2); err != nil {
		t.Fatal(err)
	}
	if k2.EVMAddress == nil || *k2.EVMAddress != addr {
		t.Fatalf("EVMAddress not populated: %v", k2.EVMAddress)
	}
}
