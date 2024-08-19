// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	. "github.com/canonical/tcglog-parser"
)

type tcgeventdataEfiSuite struct{}

var _ = Suite(&tcgeventdataEfiSuite{})

func (s *tcgeventdataEfiSuite) TestSpecIdEvent02String(c *C) {
	event := SpecIdEvent02{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       2,
		UintnSize:        2,
		VendorInfo:       []byte("bar")}
	c.Check(event.String(), Equals, "EfiSpecIdEvent{ platformClass=0, specVersionMinor=2, specVersionMajor=1, specErrata=2, uintnSize=2 }")
}

func (s *tcgeventdataEfiSuite) TestSpecIdEvent02Write(c *C) {
	event := SpecIdEvent02{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       2,
		UintnSize:        2}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303200000000000201020200"))
}

func (s *tcgeventdataEfiSuite) TestSpecIdEvent02WriteWithVendorInfo(c *C) {
	event := SpecIdEvent02{
		PlatformClass:    0,
		SpecVersionMinor: 2,
		SpecVersionMajor: 1,
		SpecErrata:       2,
		UintnSize:        2,
		VendorInfo:       []byte("bar")}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303200000000000201020203626172"))
}

func (s *tcgeventdataEfiSuite) TestSpecIdEvent03String(c *C) {
	event := SpecIdEvent03{
		PlatformClass:    0,
		SpecVersionMinor: 0,
		SpecVersionMajor: 2,
		SpecErrata:       0,
		UintnSize:        2,
		DigestSizes: []EFISpecIdEventAlgorithmSize{
			{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
			{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}},
		VendorInfo: []byte("bar")}
	c.Check(event.String(), Equals, "EfiSpecIdEvent{ platformClass=0, specVersionMinor=0, specVersionMajor=2, specErrata=0, uintnSize=2, digestSizes=[{ algorithmId=0x0004, digestSize=20 }, { algorithmId=0x000b, digestSize=32 }] }")
}

func (s *tcgeventdataEfiSuite) TestSpecIdEvent03Write(c *C) {
	event := SpecIdEvent03{
		PlatformClass:    0,
		SpecVersionMinor: 0,
		SpecVersionMajor: 2,
		SpecErrata:       0,
		UintnSize:        2,
		DigestSizes: []EFISpecIdEventAlgorithmSize{
			{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
			{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}}}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200000"))
}

func (s *tcgeventdataEfiSuite) TestSpecIdEvent03WriteWithVendorInfo(c *C) {
	event := SpecIdEvent03{
		PlatformClass:    0,
		SpecVersionMinor: 0,
		SpecVersionMajor: 2,
		SpecErrata:       0,
		UintnSize:        2,
		DigestSizes: []EFISpecIdEventAlgorithmSize{
			{AlgorithmId: tpm2.HashAlgorithmSHA1, DigestSize: 20},
			{AlgorithmId: tpm2.HashAlgorithmSHA256, DigestSize: 32}},
		VendorInfo: []byte("bar")}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "53706563204944204576656e74303300000000000002000202000000040014000b00200003626172"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIVariableDataDigest1(c *C) {
	c.Check(ComputeEFIVariableDataDigest(crypto.SHA256, "dbx", efi.ImageSecurityDatabaseGuid,
		decodeHexString(c, "2616c4c14c509240aca941f9369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
		DeepEquals,
		decodeHexString(c, "1963d580fcc0cede165e23837b55335eebe18750c0b795883386026ea071e3c6"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIVariableDataDigest2(c *C) {
	c.Check(ComputeEFIVariableDataDigest(crypto.SHA256, "SecureBoot", efi.GlobalVariable, []byte{0x01}),
		DeepEquals,
		decodeHexString(c, "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIVariableDataDigest3(c *C) {
	c.Check(ComputeEFIVariableDataDigest(crypto.SHA1, "SecureBoot", efi.GlobalVariable, []byte{0x01}),
		DeepEquals,
		decodeHexString(c, "d4fdd1f14d4041494deb8fc990c45343d2277d08"))
}

func (s *tcgeventdataEfiSuite) TestEFIVariableDataWrite1(c *C) {
	event := EFIVariableData{
		VariableName: efi.ImageSecurityDatabaseGuid,
		UnicodeName:  "dbx",
		VariableData: decodeHexString(c, "2616c4c14c509240aca941f9369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f03000000000000004c0000000000000064006200780026"+
		"16c4c14c509240aca941f9369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae"+
		"41e4649b934ca495991b7852b855"))
}

func (s *tcgeventdataEfiSuite) TestEFIVariableDataWrite2(c *C) {
	event := EFIVariableData{
		VariableName: efi.GlobalVariable,
		UnicodeName:  "SecureBoot",
		VariableData: []byte{0x01}}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c0a00000000000000010000000000000053006500630075007200650042006f006f00740001"))
}

func (s *tcgeventdataEfiSuite) TestEFIVariableDataString1(c *C) {
	event := EFIVariableData{
		VariableName: efi.ImageSecurityDatabaseGuid,
		UnicodeName:  "db",
		VariableData: decodeHexString(c, "2616c4c14c509240aca941f9369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}
	c.Check(event.String(), Equals, "UEFI_VARIABLE_DATA{ VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f, UnicodeName: \"db\", VariableData:\n"+
		"\t00000000  26 16 c4 c1 4c 50 92 40  ac a9 41 f9 36 93 43 28  |&...LP.@..A.6.C(|\n"+
		"\t00000010  4c 00 00 00 00 00 00 00  30 00 00 00 a3 a8 ba a0  |L.......0.......|\n"+
		"\t00000020  1d 04 a8 48 bc 87 c3 6d  12 1b 5e 3d e3 b0 c4 42  |...H...m..^=...B|\n"+
		"\t00000030  98 fc 1c 14 9a fb f4 c8  99 6f b9 24 27 ae 41 e4  |.........o.$'.A.|\n"+
		"\t00000040  64 9b 93 4c a4 95 99 1b  78 52 b8 55              |d..L....xR.U|\n"+
		"\t}")
}

func (s *tcgeventdataEfiSuite) TestEFIVariableDataString2(c *C) {
	event := EFIVariableData{
		VariableName: efi.GlobalVariable,
		UnicodeName:  "SecureBoot",
		VariableData: []byte{0x01}}
	c.Check(event.String(), Equals, "UEFI_VARIABLE_DATA{ VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c, UnicodeName: \"SecureBoot\", VariableData:\n"+
		"\t00000000  01                                                |.|\n"+
		"\t}")
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIVariable1(c *C) {
	data := decodeHexString(c, "cbb219d73a3d9645a3bcdad00e67656f03000000000000004c000000000000006400620078002616c4c14c509240aca941f9"+
		"369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	event, err := DecodeEventDataEFIVariable(data)
	c.Assert(err, IsNil)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.VariableName, Equals, efi.ImageSecurityDatabaseGuid)
	c.Check(event.UnicodeName, Equals, "dbx")
	c.Check(event.VariableData, DeepEquals, decodeHexString(c, "2616c4c14c509240aca941f9369343284c0000000000000030000000a3a8baa01d04a848bc87c36d121b5e3de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIVariable2(c *C) {
	data := decodeHexString(c, "61dfe48bca93d211aa0d00e098032b8c0a00000000000000010000000000000053006500630075007200650042006f006f00740001")
	event, err := DecodeEventDataEFIVariable(data)
	c.Assert(err, IsNil)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.VariableName, Equals, efi.GlobalVariable)
	c.Check(event.UnicodeName, Equals, "SecureBoot")
	c.Check(event.VariableData, DeepEquals, []byte{0x01})
}

func (s *tcgeventdataEfiSuite) TestEFIImageLoadEventString(c *C) {
	event := EFIImageLoadEvent{
		LocationInMemory: 0x6556c018,
		LengthInMemory:   955072,
		DevicePath: efi.DevicePath{
			&efi.ACPIDevicePathNode{
				HID: 0x0a0341d0,
				UID: 0x0},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x1d},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x0},
			&efi.NVMENamespaceDevicePathNode{
				NamespaceID:   0x1,
				NamespaceUUID: 0x0},
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	c.Check(event.String(), Equals, "UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x000000006556c018, ImageLengthInMemory: 955072, "+
		"ImageLinkTimeAddress: 0x0000000000000000, "+
		"DevicePath: \\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1,00-00-00-00-00-00-00-00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960)\\\\EFI\\ubuntu\\shimx64.efi }")
}

func (s *tcgeventdataEfiSuite) TestEFIImageLoadEventWrite(c *C) {
	event := EFIImageLoadEvent{
		LocationInMemory: 0x6556c018,
		LengthInMemory:   955072,
		DevicePath: efi.DevicePath{
			&efi.ACPIDevicePathNode{
				HID: 0x0a0341d0,
				UID: 0x0},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x1d},
			&efi.PCIDevicePathNode{
				Function: 0x0,
				Device:   0x0},
			&efi.NVMENamespaceDevicePathNode{
				NamespaceID:   0x1,
				NamespaceUUID: 0x0},
			&efi.HardDriveDevicePathNode{
				PartitionNumber: 1,
				PartitionStart:  0x800,
				PartitionSize:   0x100000,
				Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals,
		decodeHexString(c, "18c0566500000000c0920e000000000000000000000000008a0000000000000002010c00d041030a0000000001010600001d01"+
			"01060000000317100001000000000000000000000004012a0001000000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b960020204"+
			"0434005c004500460049005c007500620075006e00740075005c007300680069006d007800360034002e0065006600690000007fff0400"))
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIImageLoad1(c *C) {
	data := decodeHexString(c, "18a03d560000000080371a000000000000000000000000003800000000000000040434005c004500460049005c007500620075"+
		"006e00740075005c0067007200750062007800360034002e0065006600690000007fff0400")
	event, err := DecodeEventDataEFIImageLoad(data)
	c.Assert(err, IsNil)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.LocationInMemory, Equals, efi.PhysicalAddress(0x563da018))
	c.Check(event.LengthInMemory, Equals, uint64(1718144))
	c.Check(event.LinkTimeAddress, Equals, uint64(0))
	c.Check(event.DevicePath, DeepEquals, efi.DevicePath{
		efi.FilePathDevicePathNode("\\EFI\\ubuntu\\grubx64.efi")})
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIImageLoad2(c *C) {
	data := decodeHexString(c, "18c0566500000000c0920e000000000000000000000000008a0000000000000002010c00d041030a0000000001010600001d01"+
		"01060000000317100001000000000000000000000004012a0001000000000800000000000000001000000000007b94de66b2fd2545b75230d66bb2b960020204"+
		"0434005c004500460049005c007500620075006e00740075005c007300680069006d007800360034002e0065006600690000007fff0400")
	event, err := DecodeEventDataEFIImageLoad(data)
	c.Assert(err, IsNil)

	c.Check(event.Bytes(), DeepEquals, data)
	c.Check(event.LocationInMemory, Equals, efi.PhysicalAddress(0x6556c018))
	c.Check(event.LengthInMemory, Equals, uint64(955072))
	c.Check(event.LinkTimeAddress, Equals, uint64(0))
	c.Check(event.DevicePath, DeepEquals, efi.DevicePath{
		&efi.ACPIDevicePathNode{
			HID: 0x0a0341d0,
			UID: 0x0},
		&efi.PCIDevicePathNode{
			Function: 0x0,
			Device:   0x1d},
		&efi.PCIDevicePathNode{
			Function: 0x0,
			Device:   0x0},
		&efi.NVMENamespaceDevicePathNode{
			NamespaceID:   0x1,
			NamespaceUUID: 0x0},
		&efi.HardDriveDevicePathNode{
			PartitionNumber: 1,
			PartitionStart:  0x800,
			PartitionSize:   0x100000,
			Signature:       efi.GUIDHardDriveSignature(efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60})),
			MBRType:         efi.GPT},
		efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")})
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIGPT(c *C) {
	data := decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee0000000022000000000000008e52"+
		"77ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b030000000000000028732ac11ff8d211ba4b00a0"+
		"c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000000000000000000000000000450046004900200053007900730074006500"+
		"6d00200050006100720074006900740069006f006e000000000000000000000000000000000000000000000000000000000000000000af3dc60f83847247"+
		"8e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe726000000000000000000000000000000000000000000000000000000"+
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af3dc60f"+
		"838472478e793d69d8477de421f54ac6f114f24eadb520b59ca2335a00e8260000000000ff4f77ee00000000000000000000000000000000000000000000"+
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	event, err := DecodeEventDataEFIGPT(data)
	c.Assert(err, IsNil)

	c.Check(event.Hdr, DeepEquals, efi.PartitionTableHeader{
		HeaderSize:               92,
		MyLBA:                    1,
		AlternateLBA:             4000797359,
		FirstUsableLBA:           34,
		LastUsableLBA:            4000797326,
		DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
		PartitionEntryLBA:        2,
		NumberOfPartitionEntries: 128,
		SizeOfPartitionEntry:     128,
		PartitionEntryArrayCRC32: 189081846})
	c.Check(event.Partitions, DeepEquals, []*efi.PartitionEntry{
		{
			PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
			UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
			StartingLBA:         2048,
			EndingLBA:           1050623,
			Attributes:          0,
			PartitionName:       "EFI System Partition",
		},
		{
			PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
			UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
			StartingLBA:         1050624,
			EndingLBA:           2549759,
			Attributes:          0,
			PartitionName:       "",
		},
		{
			PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
			UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
			StartingLBA:         2549760,
			EndingLBA:           4000796671,
			Attributes:          0,
			PartitionName:       "",
		}})
}

func (s *tcgeventdataEfiSuite) TestEFIGPTDataString(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}
	c.Check(event.String(), Equals, "UEFI_GPT_DATA{\n"+
		"\tHdr: EFI_PARTITION_TABLE_HEADER{ MyLBA: 0x1, AlternateLBA: 0xee7752af, FirstUsableLBA: 0x22, LastUsableLBA: 0xee77528e, DiskGUID: a4ae73c2-0e2f-4513-bd3c-456da7f7f0fd, PartitionEntryLBA: 0x2, NumberOfPartitionEntries: 128, SizeOfPartitionEntry: 0x80, PartitionEntryArrayCRC32: 0x0b4528f6 },\n"+
		"\tPartitions: [\n"+
		"\t\tEFI_PARTITION_ENTRY{ PartitionTypeGUID: c12a7328-f81f-11d2-ba4b-00a0c93ec93b, UniquePartitionGUID: 66de947b-fdb2-4525-b752-30d66bb2b960, StartingLBA: 0x800, EndingLBA: 0x1007ff, Attributes: 0x0000000000000000, PartitionName: \"EFI System Partition\" }\n"+
		"\t\tEFI_PARTITION_ENTRY{ PartitionTypeGUID: 0fc63daf-8483-4772-8e79-3d69d8477de4, UniquePartitionGUID: 631b17dc-edb7-4d1d-a761-6dce3efce415, StartingLBA: 0x100800, EndingLBA: 0x26e7ff, Attributes: 0x0000000000000000, PartitionName: \"\" }\n"+
		"\t\tEFI_PARTITION_ENTRY{ PartitionTypeGUID: 0fc63daf-8483-4772-8e79-3d69d8477de4, UniquePartitionGUID: c64af521-14f1-4ef2-adb5-20b59ca2335a, StartingLBA: 0x26e800, EndingLBA: 0xee774fff, Attributes: 0x0000000000000000, PartitionName: \"\" }\n"+
		"\t]\n"+
		"}")
}

func (s *tcgeventdataEfiSuite) TestEFIGPTDataWrite(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}

	w := new(bytes.Buffer)
	c.Check(event.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals,
		decodeHexString(c, "4546492050415254000001005c000000edeb4e64000000000100000000000000af5277ee0000000022000000000000008e52"+
			"77ee00000000c273aea42f0e1345bd3c456da7f7f0fd02000000000000008000000080000000f628450b030000000000000028732ac11ff8d211ba4b00a0"+
			"c93ec93b7b94de66b2fd2545b75230d66bb2b9600008000000000000ff071000000000000000000000000000450046004900200053007900730074006500"+
			"6d00200050006100720074006900740069006f006e000000000000000000000000000000000000000000000000000000000000000000af3dc60f83847247"+
			"8e793d69d8477de4dc171b63b7ed1d4da7616dce3efce4150008100000000000ffe726000000000000000000000000000000000000000000000000000000"+
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af3dc60f"+
			"838472478e793d69d8477de421f54ac6f114f24eadb520b59ca2335a00e8260000000000ff4f77ee00000000000000000000000000000000000000000000"+
			"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIGPTDataDigestSHA256(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}

	digest, err := ComputeEFIGPTDataDigest(crypto.SHA256, &event)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, decodeHexString(c, "c3c8e818ce95406d10fdeee4964a0439f48f2f9c3ba22fadf857d501cb8fba36"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIGPTDataDigestSHA1(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}

	digest, err := ComputeEFIGPTDataDigest(crypto.SHA1, &event)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, decodeHexString(c, "4243b31b1b3a540afd2df40ab96f272bdab403f3"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIGPT2DataDigestSHA256(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf0, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}

	digest, err := ComputeEFIGPT2DataDigest(crypto.SHA256, &event)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, decodeHexString(c, "007d3af33a1f72dc640a5e30f39752fdcd0ec7e51dd3c9c0b70dd90d09352406"))
}

func (s *tcgeventdataEfiSuite) TestComputeEFIGPT2DataDigestSHA256DifferentGUIDs(c *C) {
	event := EFIGPTData{
		Hdr: efi.PartitionTableHeader{
			HeaderSize:               92,
			MyLBA:                    1,
			AlternateLBA:             4000797359,
			FirstUsableLBA:           34,
			LastUsableLBA:            4000797326,
			DiskGUID:                 efi.MakeGUID(0xa4ae73c2, 0x0e2f, 0x4513, 0xbd3c, [...]uint8{0x45, 0x6d, 0xa7, 0xf7, 0xf1, 0xfd}),
			PartitionEntryLBA:        2,
			NumberOfPartitionEntries: 128,
			SizeOfPartitionEntry:     128,
			PartitionEntryArrayCRC32: 189081846},
		Partitions: []*efi.PartitionEntry{
			{
				PartitionTypeGUID:   efi.MakeGUID(0xc12a7328, 0xf81f, 0x11d2, 0xba4b, [...]uint8{0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}),
				UniquePartitionGUID: efi.MakeGUID(0xc64af521, 0x14f1, 0x4ef2, 0xadb5, [...]uint8{0x20, 0xb5, 0x9c, 0xa2, 0x33, 0x5a}),
				StartingLBA:         2048,
				EndingLBA:           1050623,
				Attributes:          0,
				PartitionName:       "EFI System Partition",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				StartingLBA:         1050624,
				EndingLBA:           2549759,
				Attributes:          0,
				PartitionName:       "",
			},
			{
				PartitionTypeGUID:   efi.MakeGUID(0x0fc63daf, 0x8483, 0x4772, 0x8e79, [...]uint8{0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}),
				UniquePartitionGUID: efi.MakeGUID(0x631b17dc, 0xedb7, 0x4d1d, 0xa761, [...]uint8{0x6d, 0xce, 0x3e, 0xfc, 0xe4, 0x15}),
				StartingLBA:         2549760,
				EndingLBA:           4000796671,
				Attributes:          0,
				PartitionName:       "",
			}}}

	digest, err := ComputeEFIGPT2DataDigest(crypto.SHA256, &event)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, decodeHexString(c, "007d3af33a1f72dc640a5e30f39752fdcd0ec7e51dd3c9c0b70dd90d09352406"))
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataPlatformFirmwareBlob(c *C) {
	data := []byte{0x00, 0x10, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00}
	e, err := DecodeEventDataEFIPlatformFirmwareBlob(data)
	c.Assert(err, IsNil)

	c.Check(e.String(), Equals, "UEFI_PLATFORM_FIRMWARE_BLOB{BlobBase: 0xff171000, BlobLength:6619136}")
	c.Check(e.Bytes(), DeepEquals, data)

	c.Check(e.BlobBase, Equals, efi.PhysicalAddress(4279701504))
	c.Check(e.BlobLength, Equals, uint64(6619136))
}

func (s *tcgeventdataEfiSuite) TestPlatformFirmwareBlobWrite(c *C) {
	ev := &EFIPlatformFirmwareBlob{
		BlobBase:   0xff171000,
		BlobLength: 6619136,
	}

	w := new(bytes.Buffer)
	c.Check(ev.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte{0x00, 0x10, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataPlatformFirmwareBlob2(c *C) {
	data := []byte{0x09, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x43, 0x4f, 0x44, 0x45, 0x00, 0x00, 0xc2, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}

	e, err := DecodeEventDataEFIPlatformFirmwareBlob2(data)
	c.Assert(err, IsNil)

	c.Check(e.String(), Equals, "UEFI_PLATFORM_FIRMWARE_BLOB2{BlobDescription:\"POST CODE\", BlobBase: 0xffc20000, BlobLength:393216}")
	c.Check(e.Bytes(), DeepEquals, data)

	c.Check(e.BlobDescription, Equals, "POST CODE")
	c.Check(e.BlobBase, Equals, efi.PhysicalAddress(4290904064))
	c.Check(e.BlobLength, Equals, uint64(393216))

}

func (s *tcgeventdataEfiSuite) TestPlatformFirmwareBlob2Write(c *C) {
	ev := &EFIPlatformFirmwareBlob2{
		BlobDescription: "POST CODE",
		BlobBase:        0xffc20000,
		BlobLength:      393216,
	}

	w := new(bytes.Buffer)
	c.Check(ev.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte{0x09, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x43, 0x4f, 0x44, 0x45, 0x00, 0x00, 0xc2, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataHandoffTablePointers(c *C) {
	data := []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x16, 0xf9, 0x3f, 0x20, 0x62, 0x6f, 0x44,
		0x8d, 0x98, 0xbf, 0x08, 0xfe, 0x7c, 0xcb, 0x9f, 0x98, 0x6b, 0x57, 0x66, 0x00, 0x00, 0x00, 0x00,
	}
	e, err := DecodeEventDataEFIHandoffTablePointers(data)
	c.Assert(err, IsNil)

	c.Check(e.String(), Equals,
		`UEFI_HANDOFF_TABLE_POINTERS{
	TableEntries: [
		UEFI_CONFIGURATION_TABLE{VendorGuid: 3ff916f2-6220-446f-8d98-bf08fe7ccb9f, VendorTable: 0x66576b98}
	]
}`)
	c.Check(e.Bytes(), DeepEquals, data)

	c.Assert(len(e.TableEntries), Equals, 1)
	c.Check(e.TableEntries[0].VendorGuid, Equals, efi.MakeGUID(0x3ff916f2, 0x6220, 0x446f, 0x8d98, [...]byte{0xbf, 0x08, 0xfe, 0x7c, 0xcb, 0x9f}))
	c.Check(e.TableEntries[0].VendorTable, Equals, uintptr(0x66576b98))
}

func (s *tcgeventdataEfiSuite) TestHandoffTablePointersWrite(c *C) {
	ev := EFIHandoffTablePointers{
		TableEntries: []EFIConfigurationTable{
			{
				VendorGuid:  efi.MakeGUID(0x3ff916f2, 0x6220, 0x446f, 0x8d98, [...]byte{0xbf, 0x08, 0xfe, 0x7c, 0xcb, 0x9f}),
				VendorTable: 0x66576b98,
			},
		},
	}

	w := new(bytes.Buffer)
	c.Check(ev.Write(w), IsNil)
	c.Check(w.Bytes(), DeepEquals, []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x16, 0xf9, 0x3f, 0x20, 0x62, 0x6f, 0x44,
		0x8d, 0x98, 0xbf, 0x08, 0xfe, 0x7c, 0xcb, 0x9f, 0x98, 0x6b, 0x57, 0x66, 0x00, 0x00, 0x00, 0x00,
	})
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIHCRTMEvent(c *C) {
	data := []byte("HCRTM")
	e, err := DecodeEventDataEFIHCRTMEvent(data)
	c.Assert(err, IsNil)

	c.Check(e.String(), Equals, "HCRTM")
}

func (s *tcgeventdataEfiSuite) TestDecodeEventDataEFIHCRTMEventNotASCII(c *C) {
	data := []byte("😇\x00")
	_, err := DecodeEventDataEFIHCRTMEvent(data)
	c.Check(err, ErrorMatches, `data does not contain printable ASCII`)
}

func (s *tcgeventdataEfiSuite) TestComputeGUIDEventDataDigestSHA256(c *C) {
	digest := ComputeGUIDEventDataDigest(crypto.SHA256, efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}))
	c.Check(digest, DeepEquals, decodeHexString(c, "59b1f92051a43fea7ac3a846f2714c3e041a4153d581acd585914bcff2ad2781"))
}

func (s *tcgeventdataEfiSuite) TestComputeGUIDEventDataDigestSHA384(c *C) {
	digest := ComputeGUIDEventDataDigest(crypto.SHA384, efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}))
	c.Check(digest, DeepEquals, decodeHexString(c, "cb8fefb4f37b16be04f12330c558bed126333d37ea612dfe1132c0002ce627fb8788417d721622e1e136493dadb22c89"))
}

func (s *tcgeventdataEfiSuite) TestComputeGUIDEventDataDigestSHA256_2(c *C) {
	digest := ComputeGUIDEventDataDigest(crypto.SHA256, efi.MakeGUID(0xee993080, 0x5197, 0x4d4e, 0xb63c, [...]byte{0xf1, 0xf7, 0x41, 0x3e, 0x33, 0xce}))
	c.Check(digest, DeepEquals, decodeHexString(c, "9887eee09413e1bac0376540f43816be7e43e719e9a21a907fe2e03c61dd7ce6"))
}
