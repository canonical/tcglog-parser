// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type eventdataSuite struct{}

var _ = Suite(&eventdataSuite{})

func (s *eventdataSuite) TestOpaqueEventDataWrite1(c *C) {
	w := new(bytes.Buffer)

	d := OpaqueEventData("foo")
	c.Check(d.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte(d))
}

func (s *eventdataSuite) TestOpaqueEventDataWrite2(c *C) {
	w := new(bytes.Buffer)

	d := OpaqueEventData("bar")
	c.Check(d.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte(d))
}

func (s *eventdataSuite) TestOpaqueEventDataString(c *C) {
	event := OpaqueEventData([]byte{1, 2, 3, 4})
	c.Check(event.String(), Equals, "")

	event = OpaqueEventData([]byte("foo"))
	c.Check(event.String(), Equals, "foo")

	event = OpaqueEventData([]byte("bar\x00"))
	c.Check(event.String(), Equals, "bar")

	event = OpaqueEventData([]byte("fo\x7fo"))
	c.Check(event.String(), Equals, "")
}

func (s *eventdataSuite) TestComputeEventDigest(c *C) {
	c.Check(ComputeEventDigest(crypto.SHA256, []byte("foo")), DeepEquals, decodeHexString(c, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"))
	c.Check(ComputeEventDigest(crypto.SHA1, []byte("bar")), DeepEquals, decodeHexString(c, "62cdb7020ff920e5aa642c3d4066950dd1f01f4d"))
}
