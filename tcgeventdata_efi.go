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

// GUIDEventData corresponds to event data that is a EFI_GUID.
type GUIDEventData efi.GUID

// Bytes implements [EventData.Bytes].
func (d GUIDEventData) Bytes() ([]byte, error) {
	return d[:], nil
}

// String implements [fmt.Stringer].
func (d GUIDEventData) String() string {
	return efi.GUID(d).String()
}

// Write implements [EventData.Write].
func (d GUIDEventData) Write(w io.Writer) error {
	_, err := w.Write(d[:])
	return err
}

// ComputeGUIDEventDataDigest computes the digest for the specified EFI_GUID.
func ComputeGUIDEventDataDigest(alg crypto.Hash, guid efi.GUID) []byte {
	h := alg.New()
	h.Write(guid[:])
	return h.Sum(nil)
}

// SpecIdEvent02 corresponds to the TCG_EfiSpecIdEventStruct type and is the
// event data for a Specification ID Version EV_NO_ACTION event on EFI platforms
// for TPM family 1.2.
type SpecIdEvent02 struct {
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	VendorInfo       []byte
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//
//	(section 7.4 "EV_NO_ACTION Event Types")
func decodeSpecIdEvent02(data []byte, r io.Reader) (out *SpecIdEvent02, err error) {
	d := new(SpecIdEvent02)

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

// String implements [fmt.Stringer].
func (e *SpecIdEvent02) String() string {
	return fmt.Sprintf(`EfiSpecIdEvent {
	platformClass: %d,
	specVersionMinor: %d,
	specVersionMajor: %d,
	specErrata: %d,
	uintnSize: %d,
}`, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata, e.UintnSize)
}

// Bytes implements [EventData.Bytes].
func (e *SpecIdEvent02) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// EFISpecIdEventAlgorithmSize represents a digest algorithm and its length and corresponds to the
// TCG_EfiSpecIdEventAlgorithmSize type.
type EFISpecIdEventAlgorithmSize struct {
	AlgorithmId tpm2.HashAlgorithmId
	DigestSize  uint16
}

// String implements [fmt.Stringer].
func (s EFISpecIdEventAlgorithmSize) String() string {
	return fmt.Sprintf("{ algorithmId: %#04x, digestSize: %d }", uint16(s.AlgorithmId), s.DigestSize)
}

// SpecIdEvent03 corresponds to the TCG_EfiSpecIdEvent type and is the
// event data for a Specification ID Version EV_NO_ACTION event on EFI platforms
// for TPM family 2.0.
type SpecIdEvent03 struct {
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	DigestSizes      []EFISpecIdEventAlgorithmSize // The digest algorithms contained within this log
	VendorInfo       []byte
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(secion 9.4.5.1 "Specification ID Version Event")
func decodeSpecIdEvent03(data []byte, r io.Reader) (out *SpecIdEvent03, err error) {
	d := new(SpecIdEvent03)

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

// String implements [fmt.Stringer].
func (e *SpecIdEvent03) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, `EfiSpecIdEvent {
	platformClass: %d,
	specVersionMinor: %d,
	specVersionMajor: %d,
	specErrata: %d,
	uintnSize: %d,
	digestSizes: [`, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata, e.UintnSize)
	for _, algSize := range e.DigestSizes {
		fmt.Fprintf(&b, "\n\t\t%s,", indent(algSize, 2))
	}
	b.WriteString("\n\t],\n}")
	return b.String()
}

// Bytes implements [EventData.Bytes].
func (e *SpecIdEvent03) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// StartupLocalityEventData is the event data for a StartupLocality EV_NO_ACTION event.
type StartupLocalityEventData struct {
	StartupLocality uint8
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(section 9.4.5.3 "Startup Locality Event")
func decodeStartupLocalityEvent(data []byte, r io.Reader) (*StartupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(r, binary.LittleEndian, &locality); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return &StartupLocalityEventData{StartupLocality: locality}, nil
}

// String implements [fmt.Stringer].
func (e *StartupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent { StartupLocality: %d }", e.StartupLocality)
}

// Bytes implements [EventData.Bytes].
func (e *StartupLocalityEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
func (e *StartupLocalityEventData) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("StartupLocality"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	return binary.Write(w, binary.LittleEndian, e.StartupLocality)
}

type HCRTMMeasurementFormatType uint8

const (
	HCRTMMeasurementFormatDigest  HCRTMMeasurementFormatType = 0
	HCRTMMeasurementFormatRawData HCRTMMeasurementFormatType = 0x80
)

// HCRTMComponentEventData corresponds to TCG_HCRTMComponentEvent
type HCRTMComponentEventData struct {
	ComponentDescription  string
	MeasurementFormatType HCRTMMeasurementFormatType
	ComponentMeasurement  []byte // This will be a TPMT_HA structure if MeasurementFormatType == HCRTMMeasurementFormatDigest
}

func decodeHCRTMComponentEvent(data []byte, r io.Reader) (*HCRTMComponentEventData, error) {
	d := new(HCRTMComponentEventData)

	data, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(data, false) {
		return nil, fmt.Errorf("ComponentDescription does not contain printable ASCII that is not NULL terminated")
	}
	d.ComponentDescription = string(data)

	if err := binary.Read(r, binary.LittleEndian, &d.MeasurementFormatType); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	data, err = readLengthPrefixed[uint16, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.ComponentMeasurement = data

	return d, nil
}

// String implements [fmt.Stringer].
func (d *HCRTMComponentEventData) String() string {
	return fmt.Sprintf("TCG_HCRTMComponentEvent { ComponentDescription: %s, MeasurementFormatType: %x }", d.ComponentDescription, d.MeasurementFormatType)
}

// Bytes implements [EventData.Bytes].
func (e *HCRTMComponentEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
func (d *HCRTMComponentEventData) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("H-CRTM CompMeas"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}

	if err := writeLengthPrefixed[uint8, byte](w, []byte(d.ComponentDescription)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(d.MeasurementFormatType)}); err != nil {
		return err
	}
	return writeLengthPrefixed[uint16, byte](w, d.ComponentMeasurement)
}

func decodeEventDataEFIHCRTMEvent(data []byte) (StringEventData, error) {
	if !bytes.Equal(data, mustSucceed(HCRTM.Bytes())) {
		return "", errors.New("data contains unexpected contents")
	}
	return StringEventData(data), nil
}

// SP800_155_PlatformIdEventData corresponds to the event data for a SP800-155 Event
// EV_NO_ACTION event
type SP800_155_PlatformIdEventData struct {
	VendorId              uint32
	ReferenceManifestGuid efi.GUID
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

	return &SP800_155_PlatformIdEventData{VendorId: d.VendorId, ReferenceManifestGuid: d.Guid}, nil
}

// String implements [fmt.Stringer].
func (e *SP800_155_PlatformIdEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event { VendorId: %d, ReferenceManifestGuid: %s }", e.VendorId, e.ReferenceManifestGuid)
}

// Bytes implements [EventData.Bytes].
func (e *SP800_155_PlatformIdEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// SP800_155_PlatformIdEventData2 corresponds to the event data for a SP800-155 Event2
// EV_NO_ACTION event
type SP800_155_PlatformIdEventData2 struct {
	PlatformManufacturerId uint32
	ReferenceManifestGuid  efi.GUID
	PlatformManufacturer   string
	PlatformModel          string
	PlatformVersion        string
	FirmwareManufacturer   string
	FirmwareManufacturerId uint32
	FirmwareVersion        string
}

func decodeBIMReferenceManifestEvent2(data []byte, r io.Reader) (*SP800_155_PlatformIdEventData2, error) {
	d := new(SP800_155_PlatformIdEventData2)

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
	str, err := decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformManufacturer: %w", err)
	}
	d.PlatformManufacturer = string(str)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformModel: %w", err)
	}
	d.PlatformModel = string(str)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformVersion: %w", err)
	}
	d.PlatformVersion = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode FirmwareManufacturer: %w", err)
	}
	d.FirmwareManufacturer = string(str)

	if err := binary.Read(r, binary.LittleEndian, &d.FirmwareManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode FirmwareVersion: %w", err)
	}
	d.FirmwareVersion = string(str)

	return d, nil
}

// String implements [fmt.Stringer].
func (d *SP800_155_PlatformIdEventData2) String() string {
	return fmt.Sprintf(`SP800_155_PlatformId_Event2 {
	PlatformManufacturerId: %d,
	ReferenceManifestGUID: %v,
	PlatformManufacturer: %s,
	PlatformModel: %s,
	PlatformVersion: %s,
	FirmwareManufacturer: %s,
	FirmwareManufacturerId: %d,
	FirmwareVersion: %s,
}`, d.PlatformManufacturerId, d.ReferenceManifestGuid, d.PlatformManufacturer,
		d.PlatformModel, d.PlatformVersion, d.FirmwareManufacturer,
		d.FirmwareManufacturerId, d.FirmwareVersion)
}

// Bytes implements [EventData.Bytes].
func (e *SP800_155_PlatformIdEventData2) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformManufacturer).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformModel).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformVersion).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.FirmwareManufacturer).Bytes())); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.FirmwareManufacturerId); err != nil {
		return err
	}
	return writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.FirmwareVersion).Bytes()))
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

func decodeBIMReferenceManifestEvent3(data []byte, r io.Reader) (*SP800_155_PlatformIdEventData3, error) {
	d := new(SP800_155_PlatformIdEventData3)

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
	str, err := decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformManufacturer: %w", err)
	}
	d.PlatformManufacturer = string(str)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformModel: %w", err)
	}
	d.PlatformModel = string(str)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PlatformVersion: %w", err)
	}
	d.PlatformVersion = string(data)

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode FirmwareManufacturer: %w", err)
	}
	d.FirmwareManufacturer = string(str)

	if err := binary.Read(r, binary.LittleEndian, &d.FirmwareManufacturerId); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	data, err = readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	str, err = decodeNullTerminatedStringEventData(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode FirmwareVersion: %w", err)
	}
	d.FirmwareVersion = string(str)

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

// String implements [fmt.Stringer].
func (d *SP800_155_PlatformIdEventData3) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, `SP800_155_PlatformId_Event3 {
	PlatformManufacturerId: %d,
	ReferenceManifestGUID: %v,
	PlatformManufacturer: %s,
	PlatformModel: %s,
	PlatformVersion: %s,
	FirmwareManufacturer: %s,
	FirmwareManufacturerId: %d,
	FirmwareVersion: %s,
`, d.PlatformManufacturerId, d.ReferenceManifestGuid, d.PlatformManufacturer,
		d.PlatformModel, d.PlatformVersion, d.FirmwareManufacturer,
		d.FirmwareManufacturerId, d.FirmwareVersion)

	printLocator := func(name string, t LocatorType, data []byte) {
		switch t {
		case LocatorTypeRaw:
			fmt.Fprintf(&b, "%s: <raw>,\n", name)
		case LocatorTypeURI:
			fmt.Fprintf(&b, "%s: uri:%s,\n", name, string(bytes.TrimSuffix(data, []byte{0x00})))
		case LocatorTypeDevicePath:
			path, err := efi.ReadDevicePath(bytes.NewReader(data))
			if err != nil {
				fmt.Fprintf(&b, "%s: devicepath:%v,\n", name, err)
			} else {
				fmt.Fprintf(&b, "%s: devicepath:%s,\n", name, path.ToString(efi.DevicePathDisplayOnly|efi.DevicePathAllowVendorShortcuts|efi.DevicePathDisplayFWGUIDNames))
			}
		case LocatorTypeVariable:
			r := bytes.NewReader(data)
			guid, err := efi.ReadGUID(r)
			if err != nil {
				fmt.Fprintf(&b, "\t%s: variable:%v,\n", name, err)
			}
			name, err := io.ReadAll(r)
			if err != nil {
				fmt.Fprintf(&b, "\t%s: variable:%v,\n", name, err)
			}
			name = bytes.TrimSuffix(name, []byte{0x00})
			fmt.Fprintf(&b, "%s:variable:%v-%s,\n", name, guid, string(name))
		}
	}
	printLocator("\tRIMLocator", d.RIMLocatorType, d.RIMLocator)
	printLocator("\tPlatformCertLocator", d.PlatformCertLocatorType, d.PlatformCertLocator)

	b.WriteString("}")
	return b.String()
}

// Bytes implements [EventData.Bytes].
func (e *SP800_155_PlatformIdEventData3) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformManufacturer).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformModel).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.PlatformVersion).Bytes())); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.FirmwareManufacturer).Bytes())); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.FirmwareManufacturerId); err != nil {
		return err
	}
	if err := writeLengthPrefixed[uint8](w, mustSucceed(NullTerminatedStringEventData(d.FirmwareVersion).Bytes())); err != nil {
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

// EFIVariableData corresponds to the EFI_VARIABLE_DATA type and is the event data associated with the measurement of an
// EFI variable. This is not informative.
type EFIVariableData struct {
	VariableName efi.GUID
	UnicodeName  string
	VariableData []byte
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func decodeEventDataEFIVariable(data []byte) (*EFIVariableData, error) {
	r := bytes.NewReader(data)

	d := new(EFIVariableData)

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

	ucs2Name := make([]uint16, unicodeNameLength)
	if err := binary.Read(r, binary.LittleEndian, &ucs2Name); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.UnicodeName = efi.ConvertUTF16ToUTF8(ucs2Name)

	d.VariableData = make([]byte, variableDataLength)
	if _, err := io.ReadFull(r, d.VariableData); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return d, nil
}

// String implements [fmt.Stringer].
func (e *EFIVariableData) String() string {
	return fmt.Sprintf(`UEFI_VARIABLE_DATA {
	VariableName: %s,
	UnicodeName: %q,
	VariableData:
		%s,
}`, e.VariableName, e.UnicodeName, indent(stringer(hex.Dump(e.VariableData)), 2))
}

// Bytes implements [EventData.Bytes].
func (e *EFIVariableData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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
	if err := binary.Write(w, binary.LittleEndian, efi.ConvertUTF8ToUCS2(e.UnicodeName)); err != nil {
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

type rawEFIImageLoadEventHdr struct {
	LocationInMemory   efi.PhysicalAddress
	LengthInMemory     uint64
	LinkTimeAddress    uint64
	LengthOfDevicePath uint64
}

// EFIImageLoadEvent corresponds to UEFI_IMAGE_LOAD_EVENT and is informative.
type EFIImageLoadEvent struct {
	LocationInMemory efi.PhysicalAddress
	LengthInMemory   uint64
	LinkTimeAddress  uint64
	DevicePath       efi.DevicePath
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
		LocationInMemory: e.LocationInMemory,
		LengthInMemory:   e.LengthInMemory,
		LinkTimeAddress:  e.LinkTimeAddress,
		DevicePath:       path}, nil
}

// String implements [fmt.Stringer].
func (e *EFIImageLoadEvent) String() string {
	return fmt.Sprintf(`UEFI_IMAGE_LOAD_EVENT {
	ImageLocationInMemory: %#016x,
	ImageLengthInMemory: %d,
	ImageLinkTimeAddress: %#016x,
	DevicePath: %s,
}`, e.LocationInMemory, e.LengthInMemory, e.LinkTimeAddress,
		e.DevicePath.ToString(efi.DevicePathDisplayOnly|efi.DevicePathAllowVendorShortcuts|efi.DevicePathDisplayFWGUIDNames))
}

// Bytes implements [EventData.Bytes].
func (e *EFIImageLoadEvent) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// EFIGPTData corresponds to UEFI_GPT_DATA and is the event data for EV_EFI_GPT_EVENT and
// EV_EFI_GPT_EVENT2 events. When used for EV_EFI_GPT_EVENT2 events, the platform firmware
// zeroes out the DiskGUID field in the header and the UniquePartitionGUID field in each
// partition entry.
type EFIGPTData struct {
	Hdr        efi.PartitionTableHeader
	Partitions []*efi.PartitionEntry
}

func decodeEventDataEFIGPT(data []byte) (*EFIGPTData, error) {
	r := bytes.NewReader(data)

	d := new(EFIGPTData)

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

// String implements [fmt.Stringer].
func (e *EFIGPTData) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, `UEFI_GPT_DATA {
	Hdr: %s,
	Partitions: [`, indent(&e.Hdr, 1))
	for _, part := range e.Partitions {
		fmt.Fprintf(&b, "\n\t\t%s,", indent(part, 2))
	}
	b.WriteString("\n\t],\n}")
	return b.String()
}

// Bytes implements [EventData.Bytes].
func (e *EFIGPTData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// ComputeEFIGPTDataDigest computes a UEFI_GPT_DATA digest from the supplied data.
func ComputeEFIGPTDataDigest(alg crypto.Hash, data *EFIGPTData) ([]byte, error) {
	h := alg.New()
	if err := data.Write(h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ComputeEFIGPT2DataDigest computes a UEFI_GPT_DATA digest from the supplied data,
// for the new EV_EFI_GPT_EVENT2 event type, which zeroes out personally identifiable
// information (the disk GUID and each individual partition unique partition GUID).
func ComputeEFIGPT2DataDigest(alg crypto.Hash, data *EFIGPTData) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := data.Write(buf); err != nil {
		return nil, err
	}

	data2, err := decodeEventDataEFIGPT(buf.Bytes())
	if err != nil {
		return nil, err
	}
	data2.Hdr.DiskGUID = efi.GUID{}
	for _, entry := range data2.Partitions {
		entry.UniquePartitionGUID = efi.GUID{}
	}

	h := alg.New()
	if err := data2.Write(h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// EFIConfigurationTable corresponds to UEFI_CONFIGURATION_TABLE
type EFIConfigurationTable struct {
	VendorGuid  efi.GUID
	VendorTable uintptr
}

// String implements [fmt.Stringer].
func (t EFIConfigurationTable) String() string {
	return fmt.Sprintf("UEFI_CONFIGURATION_TABLE { VendorGuid: %v, VendorTable: %#x }", t.VendorGuid, t.VendorTable)
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
	TableEntries []EFIConfigurationTable
}

func decodeEventDataEFIHandoffTablePointers(data []byte) (out *EFIHandoffTablePointers, err error) {
	r := bytes.NewReader(data)

	out = new(EFIHandoffTablePointers)

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

// String implements [fmt.Stringer].
func (e *EFIHandoffTablePointers) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "UEFI_HANDOFF_TABLE_POINTERS {\n\tTableEntries: [")
	for _, entry := range e.TableEntries {
		fmt.Fprintf(&b, "\n\t\t%s,", indent(entry, 2))
	}
	b.WriteString("\n\t],\n}")
	return b.String()
}

// Bytes implements [EventData.Bytes].
func (e *EFIHandoffTablePointers) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// EFIHandoffTablePointers2 corresponds to UEFI_HANDOFF_TABLE_POINTERS2 and is the event data for EV_EFI_HANDOFF_TABLES2 events.
// This is informative.
type EFIHandoffTablePointers2 struct {
	TableDescription string
	TableEntries     []EFIConfigurationTable
}

func decodeEventDataEFIHandoffTablePointers2(data []byte) (out *EFIHandoffTablePointers2, err error) {
	r := bytes.NewReader(data)

	out = new(EFIHandoffTablePointers2)

	desc, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(desc, false) {
		return nil, fmt.Errorf("TableDescription does not contain printable ASCII that is not NULL terminated")
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

// String implements [fmt.Stringer].
func (e *EFIHandoffTablePointers2) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "UEFI_HANDOFF_TABLE_POINTERS2 {\n\tTableDescription: %q,\n\tTableEntries: [", e.TableDescription)
	for _, entry := range e.TableEntries {
		fmt.Fprintf(&b, "\n\t\t%s,", indent(entry, 2))
	}
	b.WriteString("\n\t},\n}")
	return b.String()
}

// Bytes implements [EventData.Bytes].
func (e *EFIHandoffTablePointers2) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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

// EFIPlatformFirmwareBlob corresponds to UEFI_PLATFORM_FIRMWARE_BLOB and is the event data for EV_EFI_PLATFORM_FIRMWARE_BLOB
// and some EV_POST_CODE events. This is informative.
type EFIPlatformFirmwareBlob struct {
	BlobBase   efi.PhysicalAddress
	BlobLength uint64
}

func decodeEventDataEFIPlatformFirmwareBlob(data []byte) (*EFIPlatformFirmwareBlob, error) {
	r := bytes.NewReader(data)

	d := new(EFIPlatformFirmwareBlob)

	if err := binary.Read(r, binary.LittleEndian, &d.BlobBase); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.BlobLength); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	return d, nil
}

// String implements [fmt.Stringer].
func (b *EFIPlatformFirmwareBlob) String() string {
	return fmt.Sprintf("UEFI_PLATFORM_FIRMWARE_BLOB { BlobBase: %#x, BlobLength:%d }", b.BlobBase, b.BlobLength)
}

// Bytes implements [EventData.Bytes].
func (e *EFIPlatformFirmwareBlob) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
func (b *EFIPlatformFirmwareBlob) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, b.BlobBase); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b.BlobLength); err != nil {
		return err
	}

	return nil
}

// EFIPlatformFirmwareBlob2 corresponds to UEFI_PLATFORM_FIRMWARE_BLOB2 and is the event data for
// EV_EFI_PLATFORM_FIRMWARE_BLOB2 and some EV_POST_CODE2 events. This is informative.
type EFIPlatformFirmwareBlob2 struct {
	BlobDescription string
	BlobBase        efi.PhysicalAddress
	BlobLength      uint64
}

func decodeEventDataEFIPlatformFirmwareBlob2(data []byte) (*EFIPlatformFirmwareBlob2, error) {
	r := bytes.NewReader(data)

	d := new(EFIPlatformFirmwareBlob2)

	desc, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	// Make sure we have valid printable ASCII
	if !isPrintableASCII(desc, false) {
		return nil, fmt.Errorf("BlobDescription does not contain printable ASCII that is not NULL terminated")
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

// String implements [fmt.Stringer].
func (b *EFIPlatformFirmwareBlob2) String() string {
	return fmt.Sprintf("UEFI_PLATFORM_FIRMWARE_BLOB2 { BlobDescription:%q, BlobBase: %#x, BlobLength:%d }", b.BlobDescription, b.BlobBase, b.BlobLength)
}

// Bytes implements [EventData.Bytes].
func (e *EFIPlatformFirmwareBlob2) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
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
