package keys

import "github.com/luxfi/kms/pkg/mpc"

func newTestMPCClient(url string) *mpc.Client {
	c, err := mpc.NewClient(url, "test-token")
	if err != nil {
		panic(err)
	}
	return c
}
