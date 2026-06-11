// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package constants

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

// Const variables to be exported
const (
	// Network IDs (P-Chain) - these identify the PRIMARY NETWORK
	// mainnet, testnet, devnet: proper public networks (can run locally with validators)
	// Network IDs (P-Chain) — identify the primary network
	MainnetID  uint32 = 1    // Production
	TestnetID  uint32 = 2    // Staging
	DevnetID   uint32 = 3    // Development
	LocalID    uint32 = 1337 // Local single/multi-node dev
	UnitTestID uint32 = 369

	// Aliases
	LuxMainnetID = MainnetID
	LuxTestnetID = TestnetID

	// CustomID means any network ID not in {1, 2, 3, 1337}.
	// Requires --genesis-file to provide configuration.
	CustomID uint32 = 0

	// Chain IDs (C-Chain EVM) — for wallets/dApps
	MainnetChainID uint32 = 96369
	TestnetChainID uint32 = 96368
	DevnetChainID  uint32 = 96370
	LocalChainID   uint32 = 31337 // EVM chain ID for localnet (Anvil convention)

	// Q-Chain shares the primary network ID (1/2/3/1337).
	// No separate network IDs — Q-Chain is a primary-network chain like P, X, C.

	// Network name strings
	MainnetName  = "mainnet"
	TestnetName  = "testnet"
	DevnetName   = "devnet"
	LocalName    = "local"  // canonical local dev (1337)
	CustomName   = "custom" // any user-defined network outside well-known IDs
	UnitTestName = "testing"

	// HRP (Human Readable Part) for bech32 addresses
	// Determines address prefix: P-lux1..., X-test1..., P-local1...
	MainnetHRP  = "lux"    // P-lux1..., X-lux1...
	TestnetHRP  = "test"   // P-test1..., X-test1...
	DevnetHRP   = "dev"    // P-dev1..., X-dev1...
	LocalHRP    = "local"  // P-local1..., X-local1... (network 1337)
	CustomHRP   = "custom" // P-custom1..., X-custom1... (any other network ID)
	UnitTestHRP = "testing"
)

// Variables to be exported
var (
	PrimaryNetworkID = ids.Empty
	PlatformChainID  = ids.PChainID // P-Chain: 11111111111111111111111111111111P

	// Chain IDs - these identify specific chains WITHIN a network
	// NOT to be confused with Network IDs
	// Native chains have a recognizable pattern: all zeros except last byte which is the chain letter
	// These are provided by the ids package for consistent display across the ecosystem
	CChainID = ids.CChainID // C-Chain: 11111111111111111111111111111111C
	XChainID = ids.XChainID // X-Chain: 11111111111111111111111111111111X
	QChainID = ids.QChainID // Q-Chain: 11111111111111111111111111111111Q
	AChainID = ids.AChainID // A-Chain: 11111111111111111111111111111111A
	BChainID = ids.BChainID // B-Chain: 11111111111111111111111111111111B
	TChainID = ids.TChainID // T-Chain: 11111111111111111111111111111111T
	ZChainID = ids.ZChainID // Z-Chain: 11111111111111111111111111111111Z (Zero-knowledge)
	GChainID = ids.GChainID // G-Chain: 11111111111111111111111111111111G (Graph/dgraph)
	KChainID = ids.KChainID // K-Chain: 11111111111111111111111111111111K (KMS)
	DChainID = ids.DChainID // D-Chain: 11111111111111111111111111111111D (DEX)

	// NetworkIDToNetworkName maps network IDs to human-readable names.
	// CustomID (0) is the sentinel for "any user-defined network" and
	// gets the name "custom" — addresses on such a network look like
	// `X-custom1...`, `P-custom1...`. Any unknown ID also falls back to
	// CustomName via NetworkName().
	NetworkIDToNetworkName = map[uint32]string{
		MainnetID:      MainnetName, // 1
		TestnetID:      TestnetName, // 2
		DevnetID:       DevnetName,  // 3
		LocalID:        LocalName,   // 1337
		CustomID:       CustomName,  // 0 — user-defined sentinel
		UnitTestID:     UnitTestName,
		MainnetChainID: MainnetName,
		TestnetChainID: TestnetName,
		DevnetChainID:  DevnetName,
	}

	// NetworkNameToNetworkID maps names to network IDs.
	NetworkNameToNetworkID = map[string]uint32{
		MainnetName:  MainnetID,
		TestnetName:  TestnetID,
		DevnetName:   DevnetID,
		LocalName:    LocalID,
		CustomName:   CustomID,
		UnitTestName: UnitTestID,
	}

	// NetworkIDToHRP maps network IDs to bech32 address prefix.
	// 1 → P-lux1..., 2 → P-test1..., 3 → P-dev1..., 1337 → P-local1...,
	// 0 (or any unknown ID) → P-custom1... via GetHRP fallback.
	NetworkIDToHRP = map[uint32]string{
		MainnetID:      MainnetHRP, // lux
		TestnetID:      TestnetHRP, // test
		DevnetID:       DevnetHRP,  // dev
		LocalID:        LocalHRP,   // local
		CustomID:       CustomHRP,  // custom
		UnitTestID:     UnitTestHRP,
		MainnetChainID: MainnetHRP,
		TestnetChainID: TestnetHRP,
		DevnetChainID:  DevnetHRP,
	}

	// NetworkHRPToNetworkID maps HRP back to network ID.
	// "custom" maps to CustomID (0); user-supplied custom networks with
	// IDs other than 0 still encode addresses with the "custom" HRP, so
	// reverse-mapping any "custom"-prefixed address back to a numeric
	// ID requires the network ID to be specified out-of-band (genesis
	// file, RPC parameter, etc.) since the HRP itself is not unique.
	NetworkHRPToNetworkID = map[string]uint32{
		MainnetHRP:  MainnetID,
		TestnetHRP:  TestnetID,
		DevnetHRP:   DevnetID,
		LocalHRP:    LocalID,
		CustomHRP:   CustomID,
		UnitTestHRP: UnitTestID,
	}

	// ProductionNetworkIDs are networks that should use production-grade settings
	ProductionNetworkIDs = set.Of(MainnetID, TestnetID, MainnetChainID, TestnetChainID)

	ValidNetworkPrefix = "network-"

	ErrParseNetworkName = errors.New("failed to parse network name")
	ErrNetworkNotFound  = errors.New("network not found in registry")
	ErrUnknownChain     = errors.New("unknown chain name")
)

// IsCustom reports whether the networkID falls outside the well-known
// {Mainnet, Testnet, Devnet, Local, UnitTest, Mainnet/Testnet/Devnet
// chainID} set — i.e. it is a user-defined "custom" primary network
// (e.g. a private testnet on ID 42, or the explicit CustomID sentinel
// of 0). Custom networks use the "custom" HRP, so addresses on them
// look like P-custom1..., X-custom1...
func IsCustom(networkID uint32) bool {
	switch networkID {
	case MainnetID, TestnetID, DevnetID, LocalID, UnitTestID,
		MainnetChainID, TestnetChainID, DevnetChainID:
		return false
	}
	return true
}

// GetHRP returns the Human-Readable-Part of bech32 addresses for a
// networkID. Falls back to CustomHRP for any non-well-known ID, so
// users running a private network on, say, ID 42 get P-custom1...
// addresses without having to register their ID anywhere.
func GetHRP(networkID uint32) string {
	if hrp, ok := NetworkIDToHRP[networkID]; ok {
		return hrp
	}
	return CustomHRP
}

// NetworkName returns a human readable name for the network with
// ID [networkID]. Well-known IDs return their canonical name
// ("mainnet", "testnet", "devnet", "local", "custom"). Any other
// non-well-known ID returns "network-<id>" so two distinct user
// networks on different IDs remain distinguishable in logs.
func NetworkName(networkID uint32) string {
	if name, exists := NetworkIDToNetworkName[networkID]; exists {
		return name
	}
	if IsCustom(networkID) {
		// Non-zero custom IDs include the numeric suffix so they're
		// distinguishable in logs / RPC output. The CustomID sentinel
		// (0) is already in the table above and returns plain "custom".
		return fmt.Sprintf("network-%d", networkID)
	}
	return fmt.Sprintf("network-%d", networkID)
}

// NetworkID returns the ID of the network with name [networkName]
func NetworkID(networkName string) (uint32, error) {
	networkName = strings.ToLower(networkName)
	if id, exists := NetworkNameToNetworkID[networkName]; exists {
		return id, nil
	}

	idStr := networkName
	if strings.HasPrefix(networkName, ValidNetworkPrefix) {
		idStr = networkName[len(ValidNetworkPrefix):]
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrParseNetworkName, networkName)
	}
	return uint32(id), nil
}
