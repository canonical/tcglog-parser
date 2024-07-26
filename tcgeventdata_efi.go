// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
)

// UEFI_VARIABLE_DATA specifies the number of *characters* for a UTF-16 sequence rather than the size of
// the buffer. Extract a UTF-16 sequence of the correct length, given a buffer and the number of characters.
// The returned buffer can be passed to utf16.Decode.
func extractUTF16Buffer(r io.ReadSeeker, nchars uint64) ([]uint16, error) {
	var out []uint16

	for i := nchars; i > 0; i-- {
		var c uint16
		if err := binary.Read(r, binary.LittleEndian, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
		if c >= surr1 && c < surr2 {
			if err := binary.Read(r, binary.LittleEndian, &c); err != nil {
				return nil, err
			}
			if c < surr2 || c >= surr3 {
				// Invalid surrogate sequence. utf16.Decode doesn't consume this
				// byte when inserting the replacement char
				if _, err := r.Seek(-1, io.SeekCurrent); err != nil {
					return nil, err
				}
				continue
			}
			// Valid surrogate sequence
			out = append(out, c)
		}
	}

	return out, nil
}

// SpecIdEvent02 corresponds to the TCG_EfiSpecIdEventStruct type and is the
// event data for a Specification ID Version EV_NO_ACTION event on EFI platforms
// for TPM family 1.2.
type SpecIdEvent02 struct {
	rawEventData
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	VendorInfo       []byte
}

func (e *SpecIdEvent02) String() string {
	return fmt.Sprintf("EfiSpecIdEvent{ platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, specErrata=%d, uintnSize=%d }",
		e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata, e.UintnSize)
}

func (e *SpecIdEvent02) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("Spec ID Event02"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.PlatformClass); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMinor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMajor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecErrata); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.UintnSize); err != nil {
		return err
	}
	return writeLengthPrefixed[uint8](w, e.VendorInfo)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//
//	(section 7.4 "EV_NO_ACTION Event Types")
func decodeSpecIdEvent02(data []byte, r io.Reader) (out *SpecIdEvent02, err error) {
	d := &SpecIdEvent02{rawEventData: data}

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformClass); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMinor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMajor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecErrata); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.UintnSize); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	vendorInfo, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.VendorInfo = vendorInfo

	return d, nil
}

// EFISpecIdEventAlgorithmSize represents a digest algorithm and its length and corresponds to the
// TCG_EfiSpecIdEventAlgorithmSize type.
type EFISpecIdEventAlgorithmSize struct {
	AlgorithmId tpm2.HashAlgorithmId
	DigestSize  uint16
}

// SpecIdEvent03 corresponds to the TCG_EfiSpecIdEvent type and is the
// event data for a Specification ID Version EV_NO_ACTION event on EFI platforms
// for TPM family 2.0.
type SpecIdEvent03 struct {
	rawEventData
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	DigestSizes      []EFISpecIdEventAlgorithmSize // The digest algorithms contained within this log
	VendorInfo       []byte
}

func (e *SpecIdEvent03) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "EfiSpecIdEvent{ platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, specErrata=%d, uintnSize=%d, digestSizes=[",
		e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata, e.UintnSize)
	for i, algSize := range e.DigestSizes {
		if i > 0 {
			builder.WriteString(", ")
		}
		fmt.Fprintf(&builder, "{ algorithmId=0x%04x, digestSize=%d }",
			uint16(algSize.AlgorithmId), algSize.DigestSize)
	}
	builder.WriteString("] }")
	return builder.String()
}

func (e *SpecIdEvent03) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("Spec ID Event03"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.PlatformClass); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMinor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMajor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecErrata); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.UintnSize); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint32](w, e.DigestSizes); err != nil {
		return err
	}
	return writeLengthPrefixed[uint8](w, e.VendorInfo)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(secion 9.4.5.1 "Specification ID Version Event")
func decodeSpecIdEvent03(data []byte, r io.Reader) (out *SpecIdEvent03, err error) {
	d := &SpecIdEvent03{rawEventData: data}

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformClass); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMinor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMajor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecErrata); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.UintnSize); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	digestSizes, err := readLengthPrefixed[uint32, EFISpecIdEventAlgorithmSize](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.DigestSizes = digestSizes
	vendorInfo, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.VendorInfo = vendorInfo

	return d, nil
}

// StartupLocalityEventData is the event data for a StartupLocality EV_NO_ACTION event.
type StartupLocalityEventData struct {
	rawEventData
	StartupLocality uint8
}

func (e *StartupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent{ StartupLocality: %d }", e.StartupLocality)
}

func (e *StartupLocalityEventData) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("StartupLocality"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	return binary.Write(w, binary.LittleEndian, e.StartupLocality)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(section 9.4.5.3 "Startup Locality Event")
func decodeStartupLocalityEvent(data []byte, r io.Reader) (*StartupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(r, binary.LittleEndian, &locality); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &StartupLocalityEventData{rawEventData: data, StartupLocality: locality}, nil
}

// SP800_155_PlatformIdEventData corresponds to the event data for a SP800-155 Event
// EV_NO_ACTION event
type SP800_155_PlatformIdEventData struct {
	rawEventData
	VendorId              uint32
	ReferenceManifestGuid efi.GUID
}

func (e *SP800_155_PlatformIdEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event{ VendorId: %d, ReferenceManifestGuid: %s }", e.VendorId, e.ReferenceManifestGuid)
}

func (e *SP800_155_PlatformIdEventData) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("SP800-155 Event"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, e.VendorId); err != nil {
		return err
	}
	_, err := w.Write(e.ReferenceManifestGuid[:])
	return err
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(section 9.4.5.2 "BIOS Integrity Measurement Reference Manifest Event")
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//
//	(section 7.4 "EV_NO_ACTION Event Types")
func decodeBIMReferenceManifestEvent(data []byte, r io.Reader) (*SP800_155_PlatformIdEventData, error) {
	var d struct {
		VendorId uint32
		Guid     efi.GUID
	}
	if err := binary.Read(r, binary.LittleEndian, &d); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &SP800_155_PlatformIdEventData{rawEventData: data, VendorId: d.VendorId, ReferenceManifestGuid: d.Guid}, nil
}

// SP800_155_PlatformIdEventData2 corresponds to the event data for a SP800-155 Event2
// EV_NO_ACTION event
type SP800_155_PlatformIdEventData2 struct {
	rawEventData
	PlatformManufacturerId uint32
	ReferenceManifestGuid  efi.GUID
	PlatformManufacturer   string
	PlatformModel          string
	PlatformVersion        string
	FirmwareManufacturer   string
	FirmwareManufacturerId uint32
	FirmwareVersion        string
}

func (d *SP800_155_PlatformIdEventData2) String() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "SP800_155_PlatformId_Event2{")
	fmt.Fprintf(w, "\tPlatformManufacturerId: %d\n", d.PlatformManufacturerId)
	fmt.Fprintf(w, "\tReferenceManifestGUID: %v\n", d.ReferenceManifestGuid)
	fmt.Fprintf(w, "\tPlatformManufacturer: %s\n", d.PlatformManufacturer)
	fmt.Fprintf(w, "\tPlatformModel: %s\n", d.PlatformModel)
	fmt.Fprintf(w, "\tPlatformVersion: %s\n", d.PlatformVersion)
	fmt.Fprintf(w, "\tFirmwareManufacturer: %s\n", d.FirmwareManufacturer)
	fmt.Fprintf(w, "\tFirmwareManufacturerId: %d\n", d.FirmwareManufacturerId)
	fmt.Fprintf(w, "\tFirmwareVersion: %s\n", d.FirmwareVersion)
	fmt.Fprintf(w, "}")
	return w.String()
}

func (d *SP800_155_PlatformIdEventData2) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("SP800-155 Event2"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, d.PlatformManufacturerId); err != nil {
		return err
	}
	if _, err := w.Write(d.ReferenceManifestGuid[:]); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformManufacturer), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformModel), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformVersion), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.FirmwareManufacturer), 0x00)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.FirmwareManufacturerId); err != nil {
		return err
	}
	return writeLengthPrefixed[uint8](w, append([]byte(d.FirmwareVersion), 0x00))
}

func decodeBIMReferenceManifestEvent2(data []byte, r io.Reader) (*SP800_155_PlatformIdEventData2, error) {
	d := &SP800_155_PlatformIdEventData2{rawEventData: data}

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	guid, err := efi.ReadGUID(r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.ReferenceManifestGuid = guid

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformManufacturer is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformManufacturer contains invalid ASCII")
	}
	d.PlatformManufacturer = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformModel is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformModel contains invalid ASCII")
	}
	d.PlatformModel = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformVersion is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformVersion contains invalid ASCII")
	}
	d.PlatformVersion = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("FirmwareManufacturer is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("FirmwareManufacturer contains invalid ASCII")
	}
	d.FirmwareManufacturer = string(data)

	if err := binary.Read(r, binary.LittleEndian, &d.FirmwareManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("FirmwareVersion is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("FirmwareVersion contains invalid ASCII")
	}
	d.FirmwareVersion = string(data)

	return d, nil
}

type LocatorType uint32

const (
	LocatorTypeRaw        LocatorType = 0
	LocatorTypeURI        LocatorType = 1
	LocatorTypeDevicePath LocatorType = 2
	LocatorTypeVariable   LocatorType = 3
)

// SP800_155_PlatformIdEventData3 corresponds to the event data for a SP800-155 Event3
// EV_NO_ACTION event
type SP800_155_PlatformIdEventData3 struct {
	rawEventData
	PlatformManufacturerId  uint32
	ReferenceManifestGuid   efi.GUID
	PlatformManufacturer    string
	PlatformModel           string
	PlatformVersion         string
	FirmwareManufacturer    string
	FirmwareManufacturerId  uint32
	FirmwareVersion         string
	RIMLocatorType          LocatorType
	RIMLocator              []byte
	PlatformCertLocatorType LocatorType
	PlatformCertLocator     []byte
}

func (d *SP800_155_PlatformIdEventData3) String() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "SP800_155_PlatformId_Event3{")
	fmt.Fprintf(w, "\tPlatformManufacturerId: %d\n", d.PlatformManufacturerId)
	fmt.Fprintf(w, "\tReferenceManifestGUID: %v\n", d.ReferenceManifestGuid)
	fmt.Fprintf(w, "\tPlatformManufacturer: %s\n", d.PlatformManufacturer)
	fmt.Fprintf(w, "\tPlatformModel: %s\n", d.PlatformModel)
	fmt.Fprintf(w, "\tPlatformVersion: %s\n", d.PlatformVersion)
	fmt.Fprintf(w, "\tFirmwareManufacturer: %s\n", d.FirmwareManufacturer)
	fmt.Fprintf(w, "\tFirmwareManufacturerId: %d\n", d.FirmwareManufacturerId)
	fmt.Fprintf(w, "\tFirmwareVersion: %s\n", d.FirmwareVersion)

	printLocator := func(name string, t LocatorType, data []byte) {
		switch t {
		case LocatorTypeRaw:
			fmt.Fprintf(w, "\t%s:<raw>\n", name)
		case LocatorTypeURI:
			fmt.Fprintf(w, "\t%s:uri:%s\n", name, string(bytes.TrimSuffix(data, []byte{0x00})))
		case LocatorTypeDevicePath:
			path, err := efi.ReadDevicePath(bytes.NewReader(data))
			if err != nil {
				fmt.Fprintf(w, "\t%s:devicepath:%v\n", name, err)
			} else {
				fmt.Fprintf(w, "\t%s:devicepath:%s\n", name, path)
			}
		case LocatorTypeVariable:
			r := bytes.NewReader(data)
			guid, err := efi.ReadGUID(r)
			if err != nil {
				fmt.Fprintf(w, "\t%s:variable:%v\n", name, err)
			}
			name, err := io.ReadAll(r)
			if err != nil {
				fmt.Fprintf(w, "\t%s:variable:%v\n", name, err)
			}
			name = bytes.TrimSuffix(name, []byte{0x00})
			fmt.Fprintf(w, "\t%s:variable:%v-%s\n", name, guid, string(name))
		}
	}
	printLocator("RIMLocator", d.RIMLocatorType, d.RIMLocator)
	printLocator("PlatformCertLocator", d.PlatformCertLocatorType, d.PlatformCertLocator)

	fmt.Fprintf(w, "}")
	return w.String()
}

func (d *SP800_155_PlatformIdEventData3) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("SP800-155 Event3"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, d.PlatformManufacturerId); err != nil {
		return err
	}
	if _, err := w.Write(d.ReferenceManifestGuid[:]); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformManufacturer), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformModel), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.PlatformVersion), 0x00)); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.FirmwareManufacturer), 0x00)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.FirmwareManufacturerId); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, append([]byte(d.FirmwareVersion), 0x00)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.RIMLocatorType); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint32](w, d.RIMLocator); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.PlatformCertLocatorType); err != nil {
		return err
	}
	return writeLengthPrefixed[uint32](w, d.PlatformCertLocator)
}

func decodeBIMReferenceManifestEvent3(data []byte, r io.Reader) (*SP800_155_PlatformIdEventData3, error) {
	d := &SP800_155_PlatformIdEventData3{rawEventData: data}

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	guid, err := efi.ReadGUID(r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.ReferenceManifestGuid = guid

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformManufacturer is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformManufacturer contains invalid ASCII")
	}
	d.PlatformManufacturer = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformModel is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformModel contains invalid ASCII")
	}
	d.PlatformModel = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("PlatformVersion is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("PlatformVersion contains invalid ASCII")
	}
	d.PlatformVersion = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("FirmwareManufacturer is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("FirmwareManufacturer contains invalid ASCII")
	}
	d.FirmwareManufacturer = string(data)

	if err := binary.Read(r, binary.LittleEndian, &d.FirmwareManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if !bytes.HasSuffix(data, []byte{0x00}) {
		return nil, errors.New("FirmwareVersion is not NULL terminated")
	}
	data = bytes.TrimSuffix(data, []byte{0x00})
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data) {
		return nil, fmt.Errorf("FirmwareVersion contains invalid ASCII")
	}
	d.FirmwareVersion = string(data)

	if err := binary.Read(r, binary.LittleEndian, &d.RIMLocatorType); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	data, err = readLengthPrefixed[uint32, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.RIMLocator = data

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformCertLocatorType); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	data, err = readLengthPrefixed[uint32, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.PlatformCertLocator = data

	return d, nil
}

// EFIVariableData corresponds to the EFI_VARIABLE_DATA type and is the event data associated with the measurement of an
// EFI variable. This is not informative.
type EFIVariableData struct {
	rawEventData
	VariableName efi.GUID
	UnicodeName  string
	VariableData []byte
}

func (e *EFIVariableData) String() string {
	return fmt.Sprintf("UEFI_VARIABLE_DATA{ VariableName: %s, UnicodeName: \"%s\", VariableData:\n\t%s}",
		e.VariableName, e.UnicodeName, strings.Replace(hex.Dump(e.VariableData), "\n", "\n\t", -1))
}

func (e *EFIVariableData) Write(w io.Writer) error {
	if _, err := w.Write(e.VariableName[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(utf8.RuneCount([]byte(e.UnicodeName)))); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.VariableData))); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, convertStringToUtf16(e.UnicodeName)); err != nil {
		return err
	}
	_, err := w.Write(e.VariableData)
	return err
}

// ComputeEFIVariableDataDigest computes the EFI_VARIABLE_DATA digest associated with the supplied
// parameters
func ComputeEFIVariableDataDigest(alg crypto.Hash, name string, guid efi.GUID, data []byte) []byte {
	h := alg.New()
	varData := EFIVariableData{VariableName: guid, UnicodeName: name, VariableData: data}
	varData.Write(h)
	return h.Sum(nil)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func decodeEventDataEFIVariable(data []byte) (*EFIVariableData, error) {
	r := bytes.NewReader(data)

	d := &EFIVariableData{rawEventData: data}

	variableName, err := efi.ReadGUID(r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.VariableName = variableName

	var unicodeNameLength uint64
	if err := binary.Read(r, binary.LittleEndian, &unicodeNameLength); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	var variableDataLength uint64
	if err := binary.Read(r, binary.LittleEndian, &variableDataLength); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	utf16Name, err := extractUTF16Buffer(r, unicodeNameLength)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.UnicodeName = convertUtf16ToString(utf16Name)

	d.VariableData = make([]byte, variableDataLength)
	if _, err := io.ReadFull(r, d.VariableData); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return d, nil
}

type rawEFIImageLoadEventHdr struct {
	LocationInMemory   efi.PhysicalAddress
	LengthInMemory     uint64
	LinkTimeAddress    uint64
	LengthOfDevicePath uint64
}

// EFIImageLoadEvent corresponds to UEFI_IMAGE_LOAD_EVENT and is informative.
type EFIImageLoadEvent struct {
	rawEventData
	LocationInMemory efi.PhysicalAddress
	LengthInMemory   uint64
	LinkTimeAddress  uint64
	DevicePath       efi.DevicePath
}

func (e *EFIImageLoadEvent) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.LocationInMemory, e.LengthInMemory, e.LinkTimeAddress, e.DevicePath)
}

func (e *EFIImageLoadEvent) Write(w io.Writer) error {
	dpw := new(bytes.Buffer)
	if err := e.DevicePath.Write(dpw); err != nil {
		return xerrors.Errorf("cannot write device path: %w", err)
	}

	ev := rawEFIImageLoadEventHdr{
		LocationInMemory:   e.LocationInMemory,
		LengthInMemory:     e.LengthInMemory,
		LinkTimeAddress:    e.LinkTimeAddress,
		LengthOfDevicePath: uint64(dpw.Len())}
	if err := binary.Write(w, binary.LittleEndian, &ev); err != nil {
		return err
	}

	_, err := dpw.WriteTo(w)
	return err
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 4 "Measuring PE/COFF Image Files")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.3 "UEFI_IMAGE_LOAD_EVENT Structure")
func decodeEventDataEFIImageLoad(data []byte) (*EFIImageLoadEvent, error) {
	r := bytes.NewReader(data)

	var e rawEFIImageLoadEventHdr
	if err := binary.Read(r, binary.LittleEndian, &e); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	lr := io.LimitReader(r, int64(e.LengthOfDevicePath))
	path, err := efi.ReadDevicePath(lr)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &EFIImageLoadEvent{
		rawEventData:     data,
		LocationInMemory: e.LocationInMemory,
		LengthInMemory:   e.LengthInMemory,
		LinkTimeAddress:  e.LinkTimeAddress,
		DevicePath:       path}, nil
}

// EFIGPTData corresponds to UEFI_GPT_DATA and is the event data for EV_EFI_GPT_EVENT and
// EV_EFI_GPT_EVENT2 events. When used for EV_EFI_GPT_EVENT2 events, the platform firmware
// zeroes out the DiskGUID field in the header and the UniquePartitionGUID field in each
// partition entry.
type EFIGPTData struct {
	rawEventData
	Hdr        efi.PartitionTableHeader
	Partitions []*efi.PartitionEntry
}

func (e *EFIGPTData) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{\n\tHdr: %s,\n\tPartitions: [", &e.Hdr)
	for _, part := range e.Partitions {
		fmt.Fprintf(&builder, "\n\t\t%s", part)
	}
	fmt.Fprintf(&builder, "\n\t]\n}")
	return builder.String()
}

func (e *EFIGPTData) Write(w io.Writer) error {
	if err := e.Hdr.Write(w); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.Partitions))); err != nil {
		return err
	}

	for _, entry := range e.Partitions {
		w2 := new(bytes.Buffer)
		if err := entry.Write(w2); err != nil {
			return err
		}
		if w2.Len() > int(e.Hdr.SizeOfPartitionEntry) {
			return errors.New("SizeOfPartitionEntry too small")
		}

		b := make([]byte, e.Hdr.SizeOfPartitionEntry)
		copy(b, w2.Bytes())

		if _, err := w.Write(b); err != nil {
			return err
		}
	}

	return nil
}

func decodeEventDataEFIGPT(data []byte) (*EFIGPTData, error) {
	r := bytes.NewReader(data)

	d := &EFIGPTData{rawEventData: data}

	// UEFI_GPT_DATA.UEFIPartitionHeader
	hdr, err := efi.ReadPartitionTableHeader(r, false)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.Hdr = *hdr

	// UEFI_GPT_DATA.NumberOfPartitions
	var numberOfParts uint64
	if err := binary.Read(r, binary.LittleEndian, &numberOfParts); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	if numberOfParts > math.MaxUint32 {
		return nil, errors.New("invalid EFI_GPT_DATA.NumberOfPartitons")
	}

	// UEFI_GPT_DATA.Partitions
	partitions, err := efi.ReadPartitionEntries(r, uint32(numberOfParts), hdr.SizeOfPartitionEntry)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.Partitions = partitions

	return d, nil
}

// ComputeEFIGPTDataDigest computes a UEFI_GPT_DATA digest from the supplied data.
func ComputeEFIGPTDataDigest(alg crypto.Hash, data *EFIGPTData) ([]byte, error) {
	h := alg.New()
	if err := data.Write(h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// EFIConfigurationTable corresponds to UEFI_CONFIGURATION_TABLE
type EFIConfigurationTable struct {
	VendorGuid  efi.GUID
	VendorTable uintptr
}

func (t EFIConfigurationTable) String() string {
	return fmt.Sprintf("UEFI_CONFIGURATION_TABLE{VendorGuid: %v, VendorTable: %#x}", t.VendorGuid, t.VendorTable)
}

func (t *EFIConfigurationTable) Write(w io.Writer) error {
	if _, err := w.Write(t.VendorGuid[:]); err != nil {
		return err
	}

	switch ptrSize() {
	case 4:
		return binary.Write(w, binary.LittleEndian, uint32(t.VendorTable))
	case 8:
		return binary.Write(w, binary.LittleEndian, uint64(t.VendorTable))
	default:
		panic("not reached")
	}
}

// EFIHandoffTablePointers corresponds to UEFI_HANDOFF_TABLE_POINTERS and is the event data for EV_EFI_HANDOFF_TABLES events.
// This is informative.
type EFIHandoffTablePointers struct {
	rawEventData
	TableEntries []EFIConfigurationTable
}

func (e *EFIHandoffTablePointers) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_HANDOFF_TABLE_POINTERS{\n\tTableEntries: [")
	for _, entry := range e.TableEntries {
		fmt.Fprintf(&builder, "\n\t\t%s", entry)
	}
	fmt.Fprintf(&builder, "\n\t]\n}")
	return builder.String()
}

func (e *EFIHandoffTablePointers) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.TableEntries))); err != nil {
		return err
	}
	for _, table := range e.TableEntries {
		if err := table.Write(w); err != nil {
			return err
		}
	}

	return nil
}

func decodeEventDataEFIHandoffTablePointers(data []byte) (out *EFIHandoffTablePointers, err error) {
	r := bytes.NewReader(data)

	out = &EFIHandoffTablePointers{rawEventData: data}

	var nTables uint64
	if err := binary.Read(r, binary.LittleEndian, &nTables); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	out.TableEntries = make([]EFIConfigurationTable, 0, nTables)

	for i := uint64(0); i < nTables; i++ {
		vendorGuid, err := efi.ReadGUID(r)
		if err != nil {
			return nil, ioerr.EOFIsUnexpected(err)
		}

		var vendorTable uintptr
		switch ptrSize() {
		case 4:
			var x uint32
			if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
				return nil, ioerr.EOFIsUnexpected(err)
			}
			vendorTable = uintptr(x)
		case 8:
			var x uint64
			if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
				return nil, ioerr.EOFIsUnexpected(err)
			}
			vendorTable = uintptr(x)
		default:
			panic("not reached")
		}

		out.TableEntries = append(out.TableEntries, EFIConfigurationTable{
			VendorGuid:  vendorGuid,
			VendorTable: vendorTable,
		})
	}

	return out, nil
}

// EFIHandoffTablePointers2 corresponds to UEFI_HANDOFF_TABLE_POINTERS2 and is the event data for EV_EFI_HANDOFF_TABLES2 events.
// This is informative.
type EFIHandoffTablePointers2 struct {
	rawEventData
	TableDescription string
	TableEntries     []EFIConfigurationTable
}

func (e *EFIHandoffTablePointers2) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_HANDOFF_TABLE_POINTERS2{\n\tTableDescription: %q,\n\tTableEntries: [", e.TableDescription)
	for _, entry := range e.TableEntries {
		fmt.Fprintf(&builder, "\n\t\t%s", entry)
	}
	fmt.Fprintf(&builder, "\n\t]\n}")
	return builder.String()
}

func (e *EFIHandoffTablePointers2) Write(w io.Writer) error {
	if err := writeLengthPrefixed[uint8](w, []byte(e.TableDescription)); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.TableEntries))); err != nil {
		return err
	}
	for _, table := range e.TableEntries {
		if err := table.Write(w); err != nil {
			return err
		}
	}

	return nil
}

func decodeEventDataEFIHandoffTablePointers2(data []byte) (out *EFIHandoffTablePointers2, err error) {
	r := bytes.NewReader(data)

	out = &EFIHandoffTablePointers2{rawEventData: data}

	desc, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(desc) {
		return nil, fmt.Errorf("TableDescription contains invalid ASCII")
	}
	out.TableDescription = string(desc)

	var nTables uint64
	if err := binary.Read(r, binary.LittleEndian, &nTables); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	out.TableEntries = make([]EFIConfigurationTable, 0, nTables)

	for i := uint64(0); i < nTables; i++ {
		vendorGuid, err := efi.ReadGUID(r)
		if err != nil {
			return nil, ioerr.EOFIsUnexpected(err)
		}

		var vendorTable uintptr
		switch ptrSize() {
		case 4:
			var x uint32
			if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
				return nil, ioerr.EOFIsUnexpected(err)
			}
			vendorTable = uintptr(x)
		case 8:
			var x uint64
			if err := binary.Read(r, binary.LittleEndian, &x); err != nil {
				return nil, ioerr.EOFIsUnexpected(err)
			}
			vendorTable = uintptr(x)
		default:
			panic("not reached")
		}

		out.TableEntries = append(out.TableEntries, EFIConfigurationTable{
			VendorGuid:  vendorGuid,
			VendorTable: vendorTable,
		})
	}

	return out, nil
}

// EFIPlatformFirmwareBlob corresponds to UEFI_PLATFORM_FIRMWARE_BLOB and is the event data for EV_EFI_PLATFORM_FIRMWARE_BLOB
// and some EV_POST_CODE events. This is informative.
type EFIPlatformFirmwareBlob struct {
	rawEventData
	BlobBase   efi.PhysicalAddress
	BlobLength uint64
}

func (b *EFIPlatformFirmwareBlob) String() string {
	return fmt.Sprintf("UEFI_PLATFORM_FIRMWARE_BLOB{BlobBase: %#x, BlobLength:%d}", b.BlobBase, b.BlobLength)
}

func (b *EFIPlatformFirmwareBlob) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, b.BlobBase); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b.BlobLength); err != nil {
		return err
	}

	return nil
}

func decodeEventDataEFIPlatformFirmwareBlob(data []byte) (*EFIPlatformFirmwareBlob, error) {
	r := bytes.NewReader(data)

	d := &EFIPlatformFirmwareBlob{rawEventData: data}

	if err := binary.Read(r, binary.LittleEndian, &d.BlobBase); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.BlobLength); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return d, nil
}

// EFIPlatformFirmwareBlob2 corresponds to UEFI_PLATFORM_FIRMWARE_BLOB2 and is the event data for
// EV_EFI_PLATFORM_FIRMWARE_BLOB2 and some EV_POST_CODE2 events. This is informative.
type EFIPlatformFirmwareBlob2 struct {
	rawEventData
	BlobDescription string
	BlobBase        efi.PhysicalAddress
	BlobLength      uint64
}

func (b *EFIPlatformFirmwareBlob2) String() string {
	return fmt.Sprintf("UEFI_PLATFORM_FIRMWARE_BLOB2{BlobDescription:%q, BlobBase: %#x, BlobLength:%d}", b.BlobDescription, b.BlobBase, b.BlobLength)
}

func (b *EFIPlatformFirmwareBlob2) Write(w io.Writer) error {
	if err := writeLengthPrefixed[uint8](w, []byte(b.BlobDescription)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b.BlobBase); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b.BlobLength); err != nil {
		return err
	}

	return nil
}

func decodeEventDataEFIPlatformFirmwareBlob2(data []byte) (*EFIPlatformFirmwareBlob2, error) {
	r := bytes.NewReader(data)

	d := &EFIPlatformFirmwareBlob2{rawEventData: data}

	desc, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(desc) {
		return nil, fmt.Errorf("BlobDescription contains invalid ASCII")
	}
	d.BlobDescription = string(desc)

	if err := binary.Read(r, binary.LittleEndian, &d.BlobBase); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.BlobLength); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return d, nil
}
