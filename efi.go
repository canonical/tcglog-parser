// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/chrisccoulson/go-efilib"

	"golang.org/x/xerrors"
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

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(r io.Reader, eventData *SpecIdEvent) error {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return xerrors.Errorf("cannot read vendor info size: %w", err)
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, eventData.VendorInfo); err != nil {
		return xerrors.Errorf("cannot read vendor info: %w", err)
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(r io.Reader, eventData *SpecIdEvent) error {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(r, binary.LittleEndian, &numberOfAlgorithms); err != nil {
		return xerrors.Errorf("cannot read number of digest algorithms: %w", err)
	}

	if numberOfAlgorithms < 1 {
		return errors.New("numberOfAlgorithms is zero")
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	if err := binary.Read(r, binary.LittleEndian, eventData.DigestSizes); err != nil {
		return xerrors.Errorf("cannot read digest algorithm sizes: %w", err)
	}
	for _, d := range eventData.DigestSizes {
		if d.AlgorithmId.supported() && d.AlgorithmId.Size() != int(d.DigestSize) {
			return fmt.Errorf("digestSize for algorithmId %v does not match expected size", d.AlgorithmId)
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return xerrors.Errorf("cannot read vendor info size: %w", err)
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, eventData.VendorInfo); err != nil {
		return xerrors.Errorf("cannot read vendor info: %w", err)
	}

	return nil
}

// startupLocalityEventData is the event data for a StartupLocality EV_NO_ACTION event.
type startupLocalityEventData struct {
	data      []byte
	signature string
	locality  uint8
}

func (e *startupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent{ StartupLocality: %d }", e.locality)
}

func (e *startupLocalityEventData) Bytes() []byte {
	return e.data
}

func (e *startupLocalityEventData) Type() NoActionEventType {
	return StartupLocality
}

func (e *startupLocalityEventData) Signature() string {
	return e.signature
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.3 "Startup Locality Event")
func decodeStartupLocalityEvent(r io.Reader, signature string, data []byte) (*startupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(r, binary.LittleEndian, &locality); err != nil {
		return nil, err
	}

	return &startupLocalityEventData{data: data, signature: signature, locality: locality}, nil
}

type bimReferenceManifestEventData struct {
	data      []byte
	signature string
	vendorId  uint32
	guid      efi.GUID
}

func (e *bimReferenceManifestEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event{ VendorId: %d, ReferenceManifestGuid: %s }", e.vendorId, &e.guid)
}

func (e *bimReferenceManifestEventData) Bytes() []byte {
	return e.data
}

func (e *bimReferenceManifestEventData) Type() NoActionEventType {
	return BiosIntegrityMeasurement
}

func (e *bimReferenceManifestEventData) Signature() string {
	return e.signature
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.2 "BIOS Integrity Measurement Reference Manifest Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func decodeBIMReferenceManifestEvent(r io.Reader, signature string, data []byte) (*bimReferenceManifestEventData, error) {
	var d struct {
		VendorId uint32
		Guid     efi.GUID
	}
	if err := binary.Read(r, binary.LittleEndian, &d); err != nil {
		return nil, err
	}

	return &bimReferenceManifestEventData{data: data, signature: signature, vendorId: d.VendorId, guid: d.Guid}, nil
}

// EFIVariableData corresponds to the EFI_VARIABLE_DATA type and is the event data associated with the measurement of an
// EFI variable.
type EFIVariableData struct {
	data          []byte
	consumedBytes int
	VariableName  efi.GUID
	UnicodeName   string
	VariableData  []byte
}

func (e *EFIVariableData) String() string {
	return fmt.Sprintf("UEFI_VARIABLE_DATA{ VariableName: %s, UnicodeName: \"%s\" }", e.VariableName, e.UnicodeName)
}

func (e *EFIVariableData) Bytes() []byte {
	return e.data
}

// EncodeMeasuredBytes encodes this data in to the form in which it is hashed and measured by firmware or other bootloaders.
func (e *EFIVariableData) EncodeMeasuredBytes(w io.Writer) error {
	if _, err := w.Write(e.VariableName[:]); err != nil {
		return xerrors.Errorf("cannot write variable name: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(utf8.RuneCount([]byte(e.UnicodeName)))); err != nil {
		return xerrors.Errorf("cannot write unicode name length: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.VariableData))); err != nil {
		return xerrors.Errorf("cannot write variable data length: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, convertStringToUtf16(e.UnicodeName)); err != nil {
		return xerrors.Errorf("cannot write unicode name: %w", err)
	}
	if _, err := w.Write(e.VariableData); err != nil {
		return xerrors.Errorf("cannot write variable data: %w", err)
	}
	return nil
}

// TrailingBytes returns any trailing bytes that were not used during decoding. This indicates a bug in the software responsible
// for the event. See https://github.com/rhboot/shim/commit/7e4d3f1c8c730a5d3f40729cb285b5d8c7b241af and
// https://github.com/rhboot/shim/commit/8a27a4809a6a2b40fb6a4049071bf96d6ad71b50 for the types of bugs that might cause this. Note
// that trailing bytes that are measured must be taken in to account when using EncodeMeasuredBytes.
func (e *EFIVariableData) TrailingBytes() []byte {
	return e.data[e.consumedBytes:]
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func decodeEventDataEFIVariable(data []byte, eventType EventType) (*EFIVariableData, error) {
	r := bytes.NewReader(data)

	d := &EFIVariableData{data: data}

	variableName, err := efi.ReadGUID(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot read variable name: %w", err)
	}
	d.VariableName = variableName

	var unicodeNameLength uint64
	if err := binary.Read(r, binary.LittleEndian, &unicodeNameLength); err != nil {
		return nil, xerrors.Errorf("cannot read unicode name length: %w", err)
	}

	var variableDataLength uint64
	if err := binary.Read(r, binary.LittleEndian, &variableDataLength); err != nil {
		return nil, xerrors.Errorf("cannot read variable data length: %w", err)
	}

	utf16Name, err := extractUTF16Buffer(r, unicodeNameLength)
	if err != nil {
		return nil, xerrors.Errorf("cannot extract unicode name buffer: %w", err)
	}
	d.UnicodeName = convertUtf16ToString(utf16Name)

	d.VariableData = make([]byte, variableDataLength)
	if _, err := io.ReadFull(r, d.VariableData); err != nil {
		return nil, xerrors.Errorf("cannot read variable data: %w", err)
	}

	d.consumedBytes = int(r.Size()) - r.Len()

	return d, nil
}

type EFIImageLoadEvent struct {
	data             []byte
	LocationInMemory efi.PhysicalAddress
	LengthInMemory   uint64
	LinkTimeAddress  uint64
	DevicePath       *efi.DevicePathNode
}

func (e *EFIImageLoadEvent) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.LocationInMemory, e.LengthInMemory, e.LinkTimeAddress, e.DevicePath)
}

func (e *EFIImageLoadEvent) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 4 "Measuring PE/COFF Image Files")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.3 "UEFI_IMAGE_LOAD_EVENT Structure")
func decodeEventDataEFIImageLoad(data []byte) (*EFIImageLoadEvent, error) {
	r := bytes.NewReader(data)

	var e struct {
		LocationInMemory   efi.PhysicalAddress
		LengthInMemory     uint64
		LinkTimeAddress    uint64
		LengthOfDevicePath uint64
	}
	if err := binary.Read(r, binary.LittleEndian, &e); err != nil {
		return nil, err
	}

	lr := io.LimitReader(r, int64(e.LengthOfDevicePath))
	path, err := efi.DecodeDevicePath(lr)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode device path: %w", err)
	}

	return &EFIImageLoadEvent{
		data:             data,
		LocationInMemory: e.LocationInMemory,
		LengthInMemory:   e.LengthInMemory,
		LinkTimeAddress:  e.LinkTimeAddress,
		DevicePath:       path}, nil
}

// EFIGPTData corresponds to UEFI_GPT_DATA and is the event data for EV_EFI_GPT_EVENT events.
type EFIGPTData struct {
	data       []byte
	Hdr        efi.PartitionTableHeader
	Partitions []efi.PartitionEntryRaw
}

func (e *EFIGPTData) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{ DiskGUID: %s, Partitions: [", e.Hdr.DiskGUID)
	for i, part := range e.Partitions {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{ %s }", part)
	}
	fmt.Fprintf(&builder, "] }")
	return builder.String()
}

func (e *EFIGPTData) Bytes() []byte {
	return e.data
}

func decodeEventDataEFIGPT(data []byte) (*EFIGPTData, error) {
	r := bytes.NewReader(data)

	d := &EFIGPTData{data: data}

	// UEFI_GPT_DATA.UEFIPartitionHeader
	hdr, err := efi.ReadPartitionTableHeader(r)
	if err != nil {
		return nil, xerrors.Errorf("cannot read partition table header: %w", err)
	}
	d.Hdr = *hdr

	// UEFI_GPT_DATA.NumberOfPartitions
	var numberOfParts uint64
	if err := binary.Read(r, binary.LittleEndian, &numberOfParts); err != nil {
		return nil, xerrors.Errorf("cannot read number of partitions: %w", err)
	}

	// UEFI_GPT_DATA.Partitions
	for i := uint64(0); i < numberOfParts; i++ {
		entryRaw, err := efi.ReadPartitionEntry(r, hdr.SizeOfPartitionEntry)
		if err != nil {
			return nil, xerrors.Errorf("cannot read partition entry: %w", err)
		}
		d.Partitions = append(d.Partitions, entryRaw)
	}

	return d, nil
}
