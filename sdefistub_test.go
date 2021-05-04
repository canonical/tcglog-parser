// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"crypto"
	"testing"
)

func TestComputeSystemdEFIStubEventDataDigest(t *testing.T) {
	for _, data := range []struct {
		desc     string
		alg      crypto.Hash
		str      string
		expected []byte
	}{
		{
			desc: "1",
			alg:  crypto.SHA256,
			str:  "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run systemd.debug-shell=1",
			expected: []byte{0xb4, 0xac, 0x96, 0x81, 0x74, 0x9d, 0xbf, 0x5b, 0xa3, 0xbd, 0x9e, 0x06, 0x57, 0xec, 0x22, 0x7f,
				0x84, 0x04, 0x21, 0x38, 0x5e, 0x25, 0xb8, 0xb7, 0xa0, 0xa4, 0xcb, 0xeb, 0x51, 0xa9, 0xed, 0x06},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			digest := ComputeSystemdEFIStubEventDataDigest(data.alg, data.str)
			if !bytes.Equal(digest, data.expected) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}
