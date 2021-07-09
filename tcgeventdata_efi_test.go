// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"

	"github.com/canonical/go-efilib"
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
	c.Check(event.String(), Equals, "UEFI_VARIABLE_DATA{ VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f, UnicodeName: \"db\" }")
}

func (s *tcgeventdataEfiSuite) TestEFIVariableDataString2(c *C) {
	event := EFIVariableData{
		VariableName: efi.GlobalVariable,
		UnicodeName:  "SecureBoot",
		VariableData: []byte{0x01}}
	c.Check(event.String(), Equals, "UEFI_VARIABLE_DATA{ VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c, UnicodeName: \"SecureBoot\" }")
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
				Signature:       efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
				MBRType:         efi.GPT},
			efi.FilePathDevicePathNode("\\EFI\\ubuntu\\shimx64.efi")}}
	c.Check(event.String(), Equals, "UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x000000006556c018, ImageLengthInMemory: 955072, "+
		"ImageLinkTimeAddress: 0x0000000000000000, "+
		"DevicePath: \\PciRoot(0x0)\\Pci(0x1d,0x0)\\Pci(0x0,0x0)\\NVMe(0x1-0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00)\\HD(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960,0x0000000000000800,0x0000000000100000)\\\\EFI\\ubuntu\\shimx64.efi }")
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
				Signature:       efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
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
			Signature:       efi.MakeGUID(0x66de947b, 0xfdb2, 0x4525, 0xb752, [...]uint8{0x30, 0xd6, 0x6b, 0xb2, 0xb9, 0x60}),
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
	c.Check(event.String(), Equals, "UEFI_GPT_DATA{ DiskGUID: a4ae73c2-0e2f-4513-bd3c-456da7f7f0fd, "+
		"Partitions: [{ PartitionTypeGUID: c12a7328-f81f-11d2-ba4b-00a0c93ec93b, UniquePartitionGUID: 66de947b-fdb2-4525-b752-30d66bb2b960, PartitionName: \"EFI System Partition\" }, "+
		"{ PartitionTypeGUID: 0fc63daf-8483-4772-8e79-3d69d8477de4, UniquePartitionGUID: 631b17dc-edb7-4d1d-a761-6dce3efce415, PartitionName: \"\" }, "+
		"{ PartitionTypeGUID: 0fc63daf-8483-4772-8e79-3d69d8477de4, UniquePartitionGUID: c64af521-14f1-4ef2-adb5-20b59ca2335a, PartitionName: \"\" }] }")
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
