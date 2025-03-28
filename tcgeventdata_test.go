// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

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

func (s *tcgeventdataSuite) TestNullTerminatedStringEventDataString(c *C) {
	event := NullTerminatedStringEventData("foo")
	c.Check(event.String(), Equals, "foo")

	event = NullTerminatedStringEventData("bar")
	c.Check(event.String(), Equals, "bar")
}

func (s *tcgeventdataSuite) TestNullTerminatedStringEventDataWrite1(c *C) {
	event := NullTerminatedStringEventData("foo")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte("foo\x00"))
}

func (s *tcgeventdataSuite) TestNullTerminatedStringEventDataWrite2(c *C) {
	event := NullTerminatedStringEventData("bar")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte("bar\x00"))
}

func (s *tcgeventdataSuite) TestNullTerminatedUCS2StringEventDataString(c *C) {
	event := NullTerminatedUCS2StringEventData("⅒")
	c.Check(event.String(), Equals, "⅒")

	event = NullTerminatedUCS2StringEventData("⅙")
	c.Check(event.String(), Equals, "⅙")
}

func (s *tcgeventdataSuite) TestNullTerminatedUCS2StringEventDataWrite1(c *C) {
	event := NullTerminatedUCS2StringEventData("⅒")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte{0x52, 0x21, 0x00, 0x00})
}

func (s *tcgeventdataSuite) TestNullTerminatedUCS2StringEventDataWrite2(c *C) {
	event := NullTerminatedUCS2StringEventData("⅙")

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte{0x59, 0x21, 0x00, 0x00})
}

func (s *tcgeventdataSuite) TestComputeStringEventDigest(c *C) {
	c.Check(ComputeStringEventDigest(crypto.SHA256, "foo"), DeepEquals, decodeHexString(c, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"))
	c.Check(ComputeStringEventDigest(crypto.SHA1, "bar"), DeepEquals, decodeHexString(c, "62cdb7020ff920e5aa642c3d4066950dd1f01f4d"))
}

func (s *tcgeventdataSuite) TestComputeNullTerminatedUCS2StringEventDigest(c *C) {
	c.Check(ComputeNullTerminatedUCS2StringEventDigest(crypto.SHA256, "⅒"), DeepEquals, decodeHexString(c, "f647e5f2248cdf468b4740b2451346eeebd71cb74068f4c11a61511226f6c4c9"))
	c.Check(ComputeNullTerminatedUCS2StringEventDigest(crypto.SHA1, "⅙"), DeepEquals, decodeHexString(c, "1773e59232aa507adb8eae9aac4d5b72162f53e1"))
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

func (s *tcgeventdataSuite) TestSeparatorEventDataString(c *C) {
	event := &SeparatorEventData{Value: SeparatorEventNormalValue}
	c.Check(event.String(), Equals, "")

	event.Value = SeparatorEventAltNormalValue
	c.Check(event.String(), Equals, "")

	event = &SeparatorEventData{Value: SeparatorEventErrorValue, ErrorInfo: []byte("foo")}
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
	event := &SeparatorEventData{Value: SeparatorEventErrorValue, ErrorInfo: []byte("bar")}

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

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{0x0, 0x0, 0x0, 0x0})
	c.Check(event.Value, Equals, SeparatorEventNormalValue)

	event, err = DecodeEventDataSeparator([]byte{0x5a, 0x5a}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450")})
	c.Assert(err, IsNil)

	data, err = event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte{0x5a, 0x5a})
	c.Check(event.Value, Equals, SeparatorEventErrorValue)

	_, err = DecodeEventDataSeparator([]byte{0x0, 0x0, 0x0}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")})
	c.Assert(err, ErrorMatches, "data is the wrong size")

	_, err = DecodeEventDataSeparator([]byte{0x0, 0x0, 0x0, 0x1}, DigestMap{tpm2.HashAlgorithmSHA256: decodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")})
	c.Assert(err, ErrorMatches, "invalid separator value: 16777216")
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent00(c *C) {
	srcData := decodeHexString(c, "53706563204944204576656e74303000000000000201010000")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent00)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(1))
	c.Check(event.VendorInfo, DeepEquals, []byte{})
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent00WithVendorInfo(c *C) {
	srcData := decodeHexString(c, "53706563204944204576656e74303000000000000201010003666f6f")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent00)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(1))
	c.Check(event.VendorInfo, DeepEquals, []byte("foo"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent02(c *C) {
	srcData := decodeHexString(c, "53706563204944204576656e74303200000000000201020200")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent02)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(2))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.VendorInfo, DeepEquals, []byte{})
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent02WithVendorInfo(c *C) {
	srcData := decodeHexString(c, "53706563204944204576656e74303200000000000201020203626172")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent02)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(event.PlatformClass, Equals, uint32(0))
	c.Check(event.SpecVersionMinor, Equals, uint8(2))
	c.Check(event.SpecVersionMajor, Equals, uint8(1))
	c.Check(event.SpecErrata, Equals, uint8(2))
	c.Check(event.UintnSize, Equals, uint8(2))
	c.Check(event.VendorInfo, DeepEquals, []byte("bar"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionSpecIdEvent03(c *C) {
	srcData := decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200000")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent03)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
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
	srcData := decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200004a5a5a5a5")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*SpecIdEvent03)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
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

func (s *tcgeventdataSuite) TestDecodeEventDataNoActionHCRTMCompMeas(c *C) {
	srcData := decodeHexString(c, "482d4352544d20436f6d704d6561730006482d4352544d002200000b21268e6804daa48d4a6a36960bda877f39a567510482cbc7fc0d41e3e6b06b2b")
	e, err := DecodeEventDataNoAction(srcData)
	c.Assert(err, IsNil)

	event, ok := e.(*HCRTMComponentEventData)
	c.Assert(ok, Equals, true)

	data, err := event.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(event.ComponentDescription, Equals, "H-CRTM")
	c.Check(event.MeasurementFormatType, Equals, HCRTMMeasurementFormatDigest)
	c.Check(event.ComponentMeasurement, DeepEquals, decodeHexString(c, "000b21268e6804daa48d4a6a36960bda877f39a567510482cbc7fc0d41e3e6b06b2b"))

	var digest tpm2.TaggedHash
	_, err = mu.UnmarshalFromBytes(event.ComponentMeasurement, &digest)
	c.Check(err, IsNil)
	c.Check(digest.HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digest.Digest(), DeepEquals, tpm2.Digest(decodeHexString(c, "21268e6804daa48d4a6a36960bda877f39a567510482cbc7fc0d41e3e6b06b2b")))
}

func (s *tcgeventdataSuite) TestDecodeEventDataActionGood(c *C) {
	srcData := []byte(EFICallingEFIApplicationEvent)
	e, err := DecodeEventDataAction(srcData)
	c.Assert(err, IsNil)

	data, err := e.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(e.String(), Equals, string(EFICallingEFIApplicationEvent))
}

func (s *tcgeventdataSuite) TestDecodeEventDataActionBad(c *C) {
	data := []byte{0x02, 0xf6, 0x01}
	_, err := DecodeEventDataAction(data)
	c.Check(err, ErrorMatches, `data does not contain printable ASCII that is not NULL terminated`)
}

func (s *tcgeventdataSuite) TestDecodeEventDataCompactHashGood(c *C) {
	srcData := []byte("Dell Configuration Information 1")
	e, err := DecodeEventDataCompactHash(srcData)
	c.Assert(err, IsNil)

	data, err := e.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(e.String(), Equals, string("Dell Configuration Information 1"))
}

func (s *tcgeventdataSuite) TestDecodeEventDataCompactHashBad(c *C) {
	data := []byte{0x02, 0xf6, 0x01}
	_, err := DecodeEventDataCompactHash(data)
	c.Check(err, ErrorMatches, `data does not contain printable ASCII that is not NULL terminated`)
}

func (s *tcgeventdataSuite) TestDecodeEventDataPostCodeString(c *C) {
	srcData := []byte("POST CODE")
	e, err := DecodeEventDataPostCode(srcData)
	c.Assert(err, IsNil)

	ev, ok := e.(StringEventData)
	c.Assert(ok, Equals, true)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(ev.String(), Equals, "POST CODE")
}

func (s *tcgeventdataSuite) TestDecodeEventDataPostCodeWithBlob(c *C) {
	srcData := []byte{0x00, 0x10, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00}
	e, err := DecodeEventDataPostCode(srcData)
	c.Assert(err, IsNil)

	ev, ok := e.(*EFIPlatformFirmwareBlob)
	c.Assert(ok, Equals, true)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(ev.String(), Equals, "UEFI_PLATFORM_FIRMWARE_BLOB { BlobBase: 0xff171000, BlobLength:6619136 }")

	c.Check(uint64(ev.BlobBase), Equals, uint64(4279701504))
	c.Check(ev.BlobLength, Equals, uint64(6619136))
}

func (s *tcgeventdataSuite) TestDecodeEventDataPostCode2String(c *C) {
	srcData := []byte("SMM CODE")
	e, err := DecodeEventDataPostCode2(srcData)
	c.Assert(err, IsNil)

	ev, ok := e.(StringEventData)
	c.Assert(ok, Equals, true)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(ev.String(), Equals, "SMM CODE")
}

func (s *tcgeventdataSuite) TestDecodeEventDataPostCode2WithBlob(c *C) {
	srcData := []byte{0x09, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x43, 0x4f, 0x44, 0x45, 0x00, 0x00, 0xc2, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}
	e, err := DecodeEventDataPostCode2(srcData)
	c.Assert(err, IsNil)

	ev, ok := e.(*EFIPlatformFirmwareBlob2)
	c.Assert(ok, Equals, true)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	c.Check(ev.String(), Equals, "UEFI_PLATFORM_FIRMWARE_BLOB2 { BlobDescription:\"POST CODE\", BlobBase: 0xffc20000, BlobLength:393216 }")

	c.Check(ev.BlobDescription, Equals, "POST CODE")
	c.Check(uint64(ev.BlobBase), Equals, uint64(4290904064))
	c.Check(ev.BlobLength, Equals, uint64(393216))
}

func (s *tcgeventdataSuite) TestTaggedEventString(c *C) {
	ev := &TaggedEvent{
		EventID: 105,
		Data:    []byte("foo"),
	}
	c.Check(ev.String(), Equals, `TCG_PCClientTaggedEvent {
	taggedEventID: 105,
	taggedEventData:
		00000000  66 6f 6f                                          |foo|
		,
}`)

	ev = &TaggedEvent{
		EventID: 5761,
		Data:    []byte("bar"),
	}
	c.Check(ev.String(), Equals, `TCG_PCClientTaggedEvent {
	taggedEventID: 5761,
	taggedEventData:
		00000000  62 61 72                                          |bar|
		,
}`)
}

func (s *tcgeventdataSuite) TestTaggedEventWrite1(c *C) {
	ev := &TaggedEvent{
		EventID: 105,
		Data:    []byte("foo"),
	}
	w := new(bytes.Buffer)
	c.Check(ev.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "6900000003000000666f6f"))
}

func (s *tcgeventdataSuite) TestTaggedEventWrite2(c *C) {
	ev := &TaggedEvent{
		EventID: 5761,
		Data:    []byte("bar"),
	}
	w := new(bytes.Buffer)
	c.Check(ev.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "8116000003000000626172"))
}

func (s *tcgeventdataSuite) TestComputeTaggedEventDigest(c *C) {
	c.Check(ComputeTaggedEventDigest(crypto.SHA256, &TaggedEvent{EventID: 105, Data: []byte("foo")}), DeepEquals, decodeHexString(c, "716e9d513087b01e1a12d3bff8203cda2928d1f7995d882bfd8652f3f6e0ae76"))
	c.Check(ComputeTaggedEventDigest(crypto.SHA1, &TaggedEvent{EventID: 5761, Data: []byte("bar")}), DeepEquals, decodeHexString(c, "a03dbcfe30a3846c0963df1553bbfb25bcea13b2"))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMContentsHCRTM(c *C) {
	srcData := []byte("H-CRTM measured S-CRTM contents\x00")
	ev, err := DecodeEventDataSCRTMContents(srcData)
	c.Assert(err, IsNil)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	str, ok := ev.(NullTerminatedStringEventData)
	c.Check(ok, Equals, true)
	c.Check(str, Equals, NullTerminatedStringEventData("H-CRTM measured S-CRTM contents"))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMContentsPlatformBlob(c *C) {
	srcData := []byte{0x00, 0x10, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00}
	ev, err := DecodeEventDataSCRTMContents(srcData)
	c.Assert(err, IsNil)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	blob, ok := ev.(*EFIPlatformFirmwareBlob)
	c.Check(ok, Equals, true)
	c.Check(blob.BlobBase, Equals, efi.PhysicalAddress(4279701504))
	c.Check(blob.BlobLength, Equals, uint64(6619136))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMContentsPlatformBlob2(c *C) {
	srcData := []byte{0x0f, 0x53, 0x2d, 0x43, 0x52, 0x54, 0x4d, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x00, 0x00, 0xc2, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}
	ev, err := DecodeEventDataSCRTMContents(srcData)
	c.Assert(err, IsNil)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	blob, ok := ev.(*EFIPlatformFirmwareBlob2)
	c.Check(ok, Equals, true)
	c.Check(blob.BlobDescription, Equals, "S-CRTM contents")
	c.Check(blob.BlobBase, Equals, efi.PhysicalAddress(4290904064))
	c.Check(blob.BlobLength, Equals, uint64(393216))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMVersionUCS2(c *C) {
	srcData := []byte{0x31, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x33, 0x00, 0x00, 0x00}
	ev, err := DecodeEventDataSCRTMVersion(srcData)
	c.Assert(err, IsNil)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, srcData)
	str, ok := ev.(NullTerminatedUCS2StringEventData)
	c.Check(ok, Equals, true)
	c.Check(str, Equals, NullTerminatedUCS2StringEventData("1.03"))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMVersionGUID(c *C) {
	expectedGuid := efi.MakeGUID(0xec7aa64a, 0xbd0b, 0x4e7e, 0x91dd, [...]byte{0xf5, 0x74, 0x74, 0xfe, 0x03, 0x2d})
	ev, err := DecodeEventDataSCRTMVersion(expectedGuid[:])
	c.Assert(err, IsNil)

	data, err := ev.Bytes()
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, expectedGuid[:])
	guid, ok := ev.(GUIDEventData)
	c.Check(ok, Equals, true)
	c.Check(guid, Equals, GUIDEventData(expectedGuid))
}

func (s *tcgeventdataSuite) TestDecodeSCRTMVersionInvalid(c *C) {
	data := []byte{0x1, 0x2, 0x3}
	_, err := DecodeEventDataSCRTMVersion(data)
	c.Assert(err, ErrorMatches, `event data is not a NULL-terminated UCS2 string or a EFI_GUID`)
}

func (s *tcgeventdataSuite) TestDecodeEventDataOmitBootDeviceEventsGood(c *C) {
	data := []byte{0x42, 0x4f, 0x4f, 0x54, 0x20, 0x41, 0x54, 0x54, 0x45, 0x4d, 0x50, 0x54, 0x53, 0x20, 0x4f, 0x4d, 0x49, 0x54, 0x54, 0x45, 0x44}
	ev, err := DecodeEventDataOmitBootDeviceEvents(data)
	c.Assert(err, IsNil)
	c.Check(ev, Equals, BootAttemptsOmitted)
}

func (s *tcgeventdataSuite) TestDecodeEventDataOmitBootDeviceEventsUnexpectedData(c *C) {
	data := []byte{0x66, 0x6f, 0x6f}
	_, err := DecodeEventDataOmitBootDeviceEvents(data)
	c.Check(err, ErrorMatches, `data contains unexpected contents`)
}
