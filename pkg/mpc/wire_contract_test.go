package mpc

// wire_contract_test.go — pins the KMS↔MPC ZAP wire to the mpcd server
// contract so the two hand-maintained copies of the wire can't silently drift
// again. The shapes below are transcribed from luxfi/mpc
// pkg/api/zap_kms_server.go (kmsZapSignRequest, kmsZapKeygenRequest) and
// pkg/api/server.go (KeygenResult) as of mpc v1.17.9. If the KMS-side structs
// drift from these, these tests fail in CI — which is the guard that was
// missing when Sign silently sent {key_type,wallet_id,message} while the
// daemon required {vault_id,wallet_id,payload}.

import (
	"encoding/json"
	"testing"
)

// mpcdSignRequest mirrors luxfi/mpc pkg/api/zap_kms_server.go kmsZapSignRequest.
// The daemon rejects the request unless vault_id AND wallet_id are non-empty
// and reads the message bytes from `payload`.
type mpcdSignRequest struct {
	VaultID  string `json:"vault_id"`
	WalletID string `json:"wallet_id"`
	Payload  []byte `json:"payload"`
}

// mpcdKeygenResult mirrors luxfi/mpc pkg/api/server.go KeygenResult (the body
// the daemon marshals back for OpKMSKeygen).
type mpcdKeygenResult struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey string `json:"ecdsa_pub_key"`
	EDDSAPubKey string `json:"eddsa_pub_key"`
	EVMAddress  string `json:"evm_address,omitempty"`
}

func TestSignRequest_SatisfiesMPCDContract(t *testing.T) {
	// A KMS SignRequest, marshaled exactly as ZapClient.Sign sends it, must
	// deserialize into the daemon's request shape with all required fields set.
	req := SignRequest{
		VaultID:  "zoo",
		WalletID: "zoo-treasury-v1",
		KeyType:  "secp256k1",
		Payload:  []byte("message-to-sign"),
	}
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal SignRequest: %v", err)
	}

	var got mpcdSignRequest
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("daemon cannot decode SignRequest: %v", err)
	}
	if got.VaultID == "" {
		t.Fatalf("vault_id empty on the wire — daemon rejects with %q", "vault_id and wallet_id required")
	}
	if got.WalletID == "" {
		t.Fatalf("wallet_id empty on the wire — daemon rejects")
	}
	if len(got.Payload) == 0 {
		t.Fatalf("payload empty on the wire — daemon rejects with %q (regression: message vs payload)", "payload required")
	}
	if string(got.Payload) != "message-to-sign" {
		t.Fatalf("payload round-trip mismatch: %q", string(got.Payload))
	}
}

func TestKeygenResult_DecodesMPCDResponse(t *testing.T) {
	// The daemon's snake_case keygen response must populate the KMS struct.
	// camelCase tags (the drift) silently produced an all-empty result.
	daemon := mpcdKeygenResult{
		WalletID:    "zoo-treasury-v1",
		ECDSAPubKey: "502a9a8e4b5a4869f5a290bd087fd3b87ae3866948dc53ba7fe224d940c96776",
		EDDSAPubKey: "",
		EVMAddress:  "0x8756621734fe274fdc426381c9a4f9dec8656243",
	}
	wire, err := json.Marshal(daemon)
	if err != nil {
		t.Fatalf("marshal daemon result: %v", err)
	}

	var got KeygenResult
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("KMS cannot decode daemon keygen response: %v", err)
	}
	if got.WalletID != daemon.WalletID {
		t.Fatalf("wallet_id not decoded (camelCase drift?): got %q", got.WalletID)
	}
	if got.ECDSAPubkey == nil || *got.ECDSAPubkey != daemon.ECDSAPubKey {
		t.Fatalf("ecdsa_pub_key not decoded (camelCase drift?): got %v", got.ECDSAPubkey)
	}
	if got.EVMAddress == nil || *got.EVMAddress != daemon.EVMAddress {
		t.Fatalf("evm_address not decoded: got %v", got.EVMAddress)
	}
}

func TestZapErrorString_SurfacesDaemonError(t *testing.T) {
	// The daemon's error frame must become a real error, never a silent empty
	// result. This is the structural guard against the false-green.
	if msg := zapErrorString([]byte(`{"error":"vault_id and wallet_id required"}`)); msg != "vault_id and wallet_id required" {
		t.Fatalf("daemon error not surfaced: got %q", msg)
	}
	// A valid SignResult carries no "error" field → must NOT be flagged.
	okBody, _ := json.Marshal(SignResult{R: "ab", S: "cd", Signature: "ef"})
	if msg := zapErrorString(okBody); msg != "" {
		t.Fatalf("valid SignResult misflagged as error: %q", msg)
	}
	// Empty object is not an error.
	if msg := zapErrorString([]byte(`{}`)); msg != "" {
		t.Fatalf("empty object misflagged as error: %q", msg)
	}
}
