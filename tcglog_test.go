// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

func decodeHexString(c *C, str string) []byte {
	b, err := hex.DecodeString(str)
	c.Assert(err, IsNil)
	return b
}
