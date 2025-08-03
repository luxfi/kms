package util

import (
	"context"

	kmsSdk "github.com/kms/go-sdk"
)

type ResourceVariables struct {
	KMSClient kmsSdk.KMSClientInterface
	CancelCtx       context.CancelFunc
	AuthDetails     AuthenticationDetails
}
