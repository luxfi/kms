package keys

import "github.com/luxfi/kms/pkg/mpc"

func newTestMPCClient(url string) *mpc.Client {
	return mpc.NewClient(url, "test-token")
}
