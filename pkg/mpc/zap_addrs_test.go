package mpc

import (
	"reflect"
	"testing"
)

func TestSplitAddrs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "mpc-0:9653", []string{"mpc-0:9653"}},
		{"csv", "mpc-0:9653,mpc-1:9663,mpc-2:9673",
			[]string{"mpc-0:9653", "mpc-1:9663", "mpc-2:9673"}},
		{"csv with spaces", "mpc-0:9653 , mpc-1:9663 ,mpc-2:9673",
			[]string{"mpc-0:9653", "mpc-1:9663", "mpc-2:9673"}},
		{"empty entries dropped", "mpc-0:9653,,mpc-2:9673",
			[]string{"mpc-0:9653", "mpc-2:9673"}},
		{"trailing comma", "mpc-0:9653,", []string{"mpc-0:9653"}},
		{"only spaces", "   ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := splitAddrs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitAddrs(%q): got %#v want %#v", tc.in, got, tc.want)
			}
		})
	}
}
