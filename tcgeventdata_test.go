// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type tcgeventdataSuite struct{}

var _ = Suite(&tcgeventdataSuite{})

func (s *tcgeventdataSuite) TestStringEventDataString(c *C) {
	event := StringEventData("foo")
	c.Check(event.String(), Equals, "foo")

	event = StringEventData("bar")
	c.Check(event.String(), Equals, "bar")
}

func (s *tcgeventdataSuite) TestStringEventDataWrite1(c *C) {
	event := StringEventData("foo")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte("foo"))
}

func (s *tcgeventdataSuite) TestStringEventDataWrite2(c *C) {
	event := StringEventData("bar")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte("bar"))
}

func (s *tcgeventdataSuite) TestomputeStringEventDigest(c *C) {
	c.Check(ComputeStringEventDigest(crypto.SHA256, "foo"), DeepEquals, decodeHexString(c, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"))
	c.Check(ComputeStringEventDigest(crypto.SHA1, "bar"), DeepEquals, decodeHexString(c, "62cdb7020ff920e5aa642c3d4066950dd1f01f4d"))
}

func (s *tcgeventdataSuite) TestSeparatorEventDataIsError(c *C) {
	var event SeparatorEventData

	event.Value = SeparatorEventNormalValue
	c.Check(event.IsError(), Equals, false)

	event.Value = SeparatorEventAltNormalValue
	c.Check(event.IsError(), Equals, false)

	event.Value = SeparatorEventErrorValue
	c.Check(event.IsError(), Equals, true)
}

func (s *tcgeventdataSuite) TestNewErrorSeparatorEventData(c *C) {
	event := NewErrorSeparatorEventData([]byte("1234"))
	c.Check(event.Value, Equals, SeparatorEventErrorValue)
	c.Check(event.Bytes(), DeepEquals, []byte("1234"))
}

func (s *tcgeventdataSuite) TestSeparatorEventDataString(c *C) {
	event := &SeparatorEventData{Value: SeparatorEventNormalValue}
	c.Check(event.String(), Equals, "")

	event.Value = SeparatorEventAltNormalValue
	c.Check(event.String(), Equals, "")

	event = NewErrorSeparatorEventData([]byte("foo"))
	c.Check(event.String(), Equals, "ERROR: 0x666f6f")
}

func (s *tcgeventdataSuite) TestSeparatorEventDataWrite1(c *C) {
	event := SeparatorEventData{Value: SeparatorEventNormalValue}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "00000000"))
}

func (s *tcgeventdataSuite) TestSeparatorEventDataWrite2(c *C) {
	event := SeparatorEventData{Value: SeparatorEventAltNormalValue}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "ffffffff"))
}

func (s *tcgeventdataSuite) TestSeparatorEventDataWrite3(c *C) {
	event := NewErrorSeparatorEventData([]byte("bar"))

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "626172"))
}

func (s *tcgeventdataSuite) TestComputeSeparatorEventDigest(c *C) {
	c.Check(ComputeSeparatorEventDigest(crypto.SHA256, SeparatorEventNormalValue), DeepEquals, decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"))
	c.Check(ComputeSeparatorEventDigest(crypto.SHA1, SeparatorEventNormalValue), DeepEquals, decodeHexString(c, "9069ca78e7450a285173431b3e52c5c25299e473"))
	c.Check(ComputeSeparatorEventDigest(crypto.SHA256, SeparatorEventAltNormalValue), DeepEquals, decodeHexString(c, "ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e"))
	c.Check(ComputeSeparatorEventDigest(crypto.SHA256, SeparatorEventErrorValue), DeepEquals, decodeHexString(c, "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataSeparator(c *C) {
	event, err := DecodeEventDataSeparator([]byte{0x0, 0x0, 0x0, 0x0}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")})
	c.Assert(err, IsNil)
	c.Check(event.Bytes(), DeepEquals, []byte{0x0, 0x0, 0x0, 0x0})
	c.Check(event.Value, Equals, SeparatorEventNormalValue)

	event, err = DecodeEventDataSeparator([]byte{0x5a, 0x5a}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450")})
	c.Assert(err, IsNil)
	c.Check(event.Bytes(), DeepEquals, []byte{0x5a, 0x5a})
	c.Check(event.Value, Equals, SeparatorEventErrorValue)

	_, err = DecodeEventDataSeparator([]byte{0x0, 0x0, 0x0}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")})
	c.Assert(err, ErrorMatches, "data is the wrong size")

	_, err = DecodeEventDataSeparator([]byte{0x0, 0x0, 0x0, 0x1}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")})
	c.Assert(err, ErrorMatches, "invalid separator value: 16777216")
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent00(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303000000000000201010000")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent00)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(1))
	c.Check(event.VendorInfo, DeepEquals, []byte{})
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent00WithVendorInfo(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303000000000000201010003666f6f")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent00)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(1))
	c.Check(event.VendorInfo, DeepEquals, []byte("foo"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent02(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303200000000000201020200")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent02)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(2))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.VendorInfo, DeepEquals, []byte{})
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent02WithVendorInfo(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303200000000000201020203626172")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent02)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(2))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.VendorInfo, DeepEquals, []byte("bar"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent03(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200000")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent03)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(0))
	c.Check(event.SpecVersionMajor, Equals, uint8(2))
	c.Check(event.SpecErrata, Equals, uint8(0))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.DigestSizes, DeepEquals, []EFISpecIdEventAlgorithmSize{
		{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
		{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}})
	c.Check(event.VendorInfo, DeepEquals, []byte{})
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent03WithVendorInfo(c *C) {
	data := decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200004a5a5a5a5")
	e, err := DecodeEventDataNoAction(data)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent03)
	c.Assert(ok, Equals, true)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(0))
	c.Check(event.SpecVersionMajor, Equals, uint8(2))
	c.Check(event.SpecErrata, Equals, uint8(0))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.DigestSizes, DeepEquals, []EFISpecIdEventAlgorithmSize{
		{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
		{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}})
	c.Check(event.VendorInfo, DeepEquals, []byte{0xa5, 0xa5, 0xa5, 0xa5})
}
