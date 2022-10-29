// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type eventSuite struct{}

var _ = Suite(&eventSuite{})

func (s *eventSuite) TestEventWrite(c *C) {
	event := Event{
		PCRIndex:  0,
		EventType: EventTypeNoAction,
		Digests:   DigestMap{tpm2.HashAlgorithmSHA1: make(Digest, tpm2.HashAlgorithmSHA1.Size())},
		Data: &SpecIdEvent03{
			SpecVersionMajor: 2,
			UintnSize:        2,
			DigestSizes: []EFISpecIdEventAlgorithmSize{
				{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
				{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}}}}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "000000000300000000000000000000000000000000000000000000002500000053706563204944204576656e74303300000000000002000202000000040014000b00200000"))
}

func (s *eventSuite) TestReadEvent(c *C) {
	event, err := ReadEvent(
		bytes.NewReader(decodeHexString(c, "000000000300000000000000000000000000000000000000000000002500000053706563204944204576656e74303300000000000002000202000000040014000b00200000")),
		&LogOptions{})
	c.Assert(err, IsNil)

	c.Check(event.PCRIndex, Equals, PCRIndex(0))
	c.Check(event.EventType, Equals, EventTypeNoAction)
	c.Check(event.Digests, DeepEquals, DigestMap{tpm2.HashAlgorithmSHA1: make(Digest, tpm2.HashAlgorithmSHA1.Size())})

	data, ok := event.Data.(*SpecIdEvent03)
	c.Assert(ok, Equals, true)

	c.Check(data.PlatformClass, Equals, uint32(0))
	c.Check(data.SpecVersionMinor, Equals, uint8(0))
	c.Check(data.SpecVersionMajor, Equals, uint8(2))
	c.Check(data.SpecErrata, Equals, uint8(0))
	c.Check(data.UintnSize, Equals, uint8(2))
	c.Check(data.DigestSizes, DeepEquals, []EFISpecIdEventAlgorithmSize{
		{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: uint16(tpm2.HashAlgorithmSHA1.Size())},
		{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: uint16(tpm2.HashAlgorithmSHA256.Size())}})
	c.Check(data.VendorInfo, DeepEquals, []byte{})
}

func (s *eventSuite) TestEventWriteCryptoAgile(c *C) {
	digestSizes := []EFISpecIdEventAlgorithmSize{
		{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
		{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}}

	data := EFIVariableData{
		VariableName: efi.GlobalVariable,
		UnicodeName:  "BootOrder",
		VariableData: []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0x00}}

	event := Event{
		PCRIndex:  1,
		EventType: EventTypeEFIVariableBoot,
		Digests: DigestMap{
			tpm2.HashAlgorithmSHA1:   ComputeEventDigest(crypto.SHA1, data.VariableData),
			tpm2.HashAlgorithmSHA256: ComputeEventDigest(crypto.SHA256, data.VariableData)},
		Data: &data}

	w := new(bytes.Buffer)
	c.Check(event.WriteCryptoAgile(w, digestSizes), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "01000000020000800200000004005fa6e9a74105c1e2297cce17c68288c84a8bda070b009d0689"+
		"e46d7c710571256af5b8e8638f0dbc6b008f5ea4688c1c70f3005943e43800000061dfe48bca93d211aa0d00e098032b8c09000000000000000600000000000"+
		"00042006f006f0074004f007200640065007200030000000100"))
	c.Logf("%x", w.Bytes())
}

func (s *eventSuite) TestReadEventiCryptoAgile(c *C) {
	event, err := ReadEventCryptoAgile(
		bytes.NewReader(decodeHexString(c, "01000000020000800200000004005fa6e9a74105c1e2297cce17c68288c84a8bda070b009d0689"+
			"e46d7c710571256af5b8e8638f0dbc6b008f5ea4688c1c70f3005943e43800000061dfe48bca93d211aa0d00e098032b8c09000000000000000600000000000"+
			"00042006f006f0074004f007200640065007200030000000100")),
		[]EFISpecIdEventAlgorithmSize{
			{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: uint16(tpm2.HashAlgorithmSHA1.Size())},
			{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: uint16(tpm2.HashAlgorithmSHA256.Size())}},
		&LogOptions{})
	c.Assert(err, IsNil)

	c.Check(event.PCRIndex, Equals, PCRIndex(1))
	c.Check(event.EventType, Equals, EventTypeEFIVariableBoot)

	data, ok := event.Data.(*EFIVariableData)
	c.Assert(ok, Equals, true)

	c.Check(data.VariableName, Equals, efi.GlobalVariable)
	c.Check(data.UnicodeName, Equals, "BootOrder")
	c.Check(data.VariableData, DeepEquals, []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0x00})
}
