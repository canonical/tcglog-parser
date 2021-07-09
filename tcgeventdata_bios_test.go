// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type tcgeventdataBiosSuite struct{}

var _ = Suite(&tcgeventdataBiosSuite{})

func (s *tcgeventdataBiosSuite) TestSpecIdEvent00String(c *C) {
	event := SpecIdEvent00{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       1,
		VendorInfo:       []byte("foo")}
	c.Check(event.String(), Equals, "PCClientSpecIdEvent{ platformClass=0, specVersionMinor=2, specVersionMajor=1, specErrata=1 }")
}

func (s *tcgeventdataBiosSuite) TestSpecIdEvent00WriteWithVendorInfo(c *C) {
	event := SpecIdEvent00{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       1,
		VendorInfo:       []byte("foo")}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303000000000000201010003666f6f"))
}

func (s *tcgeventdataBiosSuite) TestSpecIdEvent00Write(c *C) {
	event := SpecIdEvent00{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       1}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303000000000000201010000"))
}
