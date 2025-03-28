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
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

// separatorErrorDigests are the digests of uint32(1) for various algorithms, used
// to identify EV_SEPARATOR events that signal an error, where the digest is the tagged
// hash of uint32(1) but the event data contains information about the error.
var separatorErrorDigests = map[tpm2.HashAlgorithmId]tpm2.Digest{
	tpm2.HashAlgorithmSHA1: tpm2.Digest{0x3c, 0x58, 0x56, 0x4, 0xe8, 0x7f, 0x85, 0x59, 0x73, 0x73, 0x1f, 0xea, 0x83, 0xe2, 0x1f, 0xab, 0x93, 0x92, 0xd2, 0xfc},
	tpm2.HashAlgorithmSHA256: tpm2.Digest{0x67, 0xab, 0xdd, 0x72, 0x10, 0x24, 0xf0, 0xff, 0x4e, 0xb, 0x3f, 0x4c, 0x2f, 0xc1, 0x3b, 0xc5, 0xba, 0xd4, 0x2d, 0xb,
		0x78, 0x51, 0xd4, 0x56, 0xd8, 0x8d, 0x20, 0x3d, 0x15, 0xaa, 0xa4, 0x50},
	tpm2.HashAlgorithmSHA384: tpm2.Digest{0x72, 0x10, 0xaf, 0x19, 0x14, 0x5e, 0xc2, 0xa8, 0xe2, 0x50, 0xa7, 0xfe, 0x8e, 0x9e, 0xee, 0xac, 0x13, 0x1, 0xe5, 0x24,
		0xda, 0xab, 0x82, 0x36, 0x6c, 0x36, 0xbe, 0x61, 0x4d, 0xc3, 0x54, 0x2, 0xa2, 0x89, 0x10, 0x1e, 0x48, 0xca, 0xd6, 0x1c, 0x45, 0x33, 0x7f, 0x2f, 0x32, 0xc1,
		0x4f, 0xdc},
	tpm2.HashAlgorithmSHA512: tpm2.Digest{0xed, 0xf9, 0x2e, 0x3d, 0x4f, 0x80, 0xfc, 0x47, 0xd9, 0x48, 0xea, 0x2f, 0x17, 0xb9, 0xbf, 0xc7, 0x42, 0xd3, 0x4e, 0x2e,
		0x78, 0x5a, 0x7a, 0x49, 0x27, 0xf3, 0xe2, 0x61, 0xe8, 0xbd, 0x9d, 0x40, 0xb, 0x64, 0x8b, 0xff, 0x21, 0x23, 0xb8, 0x39, 0x6d, 0x24, 0xfb, 0x28, 0xf5, 0x86,
		0x99, 0x79, 0xe0, 0x8d, 0x58, 0xb4, 0xb5, 0xd1, 0x56, 0xe6, 0x40, 0x34, 0x4a, 0x2c, 0xa, 0x54, 0x67, 0x5d},
	tpm2.HashAlgorithmSHA3_256: tpm2.Digest{0x29, 0x5c, 0xd1, 0x69, 0x8c, 0x6a, 0xc5, 0xbd, 0x80, 0x4a, 0x9, 0xe5, 0xf, 0x19, 0xf8, 0x54, 0x94, 0x75, 0xe5, 0x2d,
		0xb1, 0xc6, 0xeb, 0xd4, 0x41, 0xed, 0xc, 0x7b, 0x25, 0x6e, 0x1d, 0xdf},
	tpm2.HashAlgorithmSHA3_384: tpm2.Digest{0xe7, 0xb9, 0x1f, 0x51, 0xfb, 0x66, 0x1b, 0x6e, 0xc8, 0xea, 0x28, 0x55, 0xc8, 0x8b, 0x38, 0x80, 0x71, 0xca, 0xf1,
		0xf6, 0xa3, 0xc, 0x95, 0x24, 0x50, 0x83, 0x8d, 0x61, 0xb3, 0x55, 0x61, 0x63, 0x8b, 0x93, 0xeb, 0xdc, 0x22, 0x1b, 0x86, 0xa6, 0x81, 0x33, 0xe, 0xef, 0xa1,
		0x2e, 0x10, 0xcd},
	tpm2.HashAlgorithmSHA3_512: tpm2.Digest{0xda, 0x5e, 0xa4, 0xad, 0x55, 0x26, 0xac, 0xe3, 0x3e, 0x3, 0x75, 0xf3, 0x68, 0xd4, 0x16, 0xd9, 0x5f, 0xbf, 0x6a, 0x68,
		0x0, 0xb6, 0x60, 0x85, 0x26, 0xdc, 0x7e, 0x39, 0xce, 0x9a, 0x43, 0xf3, 0xb0, 0xa7, 0xbe, 0xd2, 0x20, 0x60, 0xdc, 0xd7, 0x1a, 0x13, 0xc, 0x95, 0x7b, 0xcd, 0x2,
		0xe1, 0x95, 0x7e, 0x6d, 0x76, 0xee, 0x61, 0x79, 0xd7, 0x2, 0x36, 0x94, 0x1, 0x6a, 0x49, 0x25, 0x5b},
}

// StringEventData corresponds to event data that is an non-NULL terminated ASCII string.
// It may or may not be informative.
type StringEventData string

// String implements [fmt.Stringer].
func (d StringEventData) String() string {
	return string(d)
}

// Write implements [EventData.Write].
func (d StringEventData) Write(w io.Writer) error {
	_, err := io.WriteString(w, string(d))
	return err
}

// Bytes implements [EventData.Bytes].
func (d StringEventData) Bytes() ([]byte, error) {
	return []byte(d), nil
}

// ComputeStringEventDigest computes the digest associated with the supplied string, for
// events where the data is not informative. The function assumes that the string is
// ASCII encoded and measured without a terminating NULL byte.
func ComputeStringEventDigest(alg crypto.Hash, str string) []byte {
	h := alg.New()
	io.WriteString(h, str)
	return h.Sum(nil)
}

// NullTerminatedStringEventData corresponds to event data that is a NULL terminated
// ASCII string. As with other strings, the go representation is not NULL terminated.
// It's only use in this package is for EV_S_CRTM_CONTENTS, which is informative.
type NullTerminatedStringEventData string

func decodeNullTerminatedStringEventData(data []byte) (NullTerminatedStringEventData, error) {
	if !isPrintableASCII(data, true) {
		return "", errors.New("data does not contain printable ASCII that is NULL terminated")
	}
	return NullTerminatedStringEventData(data[:len(data)-1]), nil
}

// String implements [fmt.Stringer].
func (d NullTerminatedStringEventData) String() string {
	return string(d)
}

// Write implements [EventData.Write].
func (d NullTerminatedStringEventData) Write(w io.Writer) error {
	if _, err := io.WriteString(w, string(d)); err != nil {
		return err
	}
	_, err := w.Write([]byte{0})
	return err
}

// Bytes implements [EventData.Bytes].
func (d NullTerminatedStringEventData) Bytes() ([]byte, error) {
	return append([]byte(d), 0x00), nil
}

// NullTerminatedUCS2StringEventData corresponds to event data that is a NULL
// terminated UCS2 string. As with other strings, the go representation is not
// NULL terminated and is represented in UTF8. It's only use in this package is
// for EV_S_CRTM_VERSION, which is not informative (the event digest is the tagged
// hash of this event data).
type NullTerminatedUCS2StringEventData string

func decodeNullTerminatedUCS2StringEventData(data []byte) (NullTerminatedUCS2StringEventData, error) {
	if !isPrintableUCS2(data, true) {
		return "", errors.New("data does not contain printable UCS2 that is NULL terminated")
	}

	r := bytes.NewReader(data)
	ucs2Str := make([]uint16, len(data)/2)
	if err := binary.Read(r, binary.LittleEndian, &ucs2Str); err != nil {
		return "", err
	}
	str := efi.ConvertUTF16ToUTF8(ucs2Str[:len(ucs2Str)-1])
	return NullTerminatedUCS2StringEventData(str), nil
}

// String implements [fmt.Stringer].
func (d NullTerminatedUCS2StringEventData) String() string {
	return string(d)
}

// Write implements [EventData.Write].
func (d NullTerminatedUCS2StringEventData) Write(w io.Writer) error {
	ucs2 := efi.ConvertUTF8ToUCS2(string(d))
	if err := binary.Write(w, binary.LittleEndian, ucs2); err != nil {
		return err
	}
	_, err := w.Write([]byte{0x00, 0x00})
	return err
}

// Bytes implements [EventData.Bytes].
func (d NullTerminatedUCS2StringEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	d.Write(w)
	return w.Bytes(), nil

}

// ComputeNullTerminatedUCS2StringEventDigest computes the digest for the supplied string,
// for events where the event data is not informative and is represented by a NULL terminated
// UCS2 string. The supplied string must be UTF8 without a NULL termination.
func ComputeNullTerminatedUCS2StringEventDigest(alg crypto.Hash, str string) []byte {
	ucs2str := efi.ConvertUTF8ToUCS2(str)
	ucs2str = append(ucs2str, 0)
	h := alg.New()
	binary.Write(h, binary.LittleEndian, ucs2str)
	return h.Sum(nil)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//
//	(section 11.3.4 "EV_NO_ACTION Event Types")
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//
//	(section 9.4.5 "EV_NO_ACTION Event Types")
func decodeEventDataNoAction(data []byte) (EventData, error) {
	r := bytes.NewReader(data)

	// Signature field
	var sig [16]byte
	if _, err := io.ReadFull(r, sig[:]); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	signature := strings.TrimRight(string(sig[:]), "\x00")

	switch signature {
	case "Spec ID Event00":
		out, err := decodeSpecIdEvent00(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event00 data: %w", err)
		}
		return out, nil
	case "Spec ID Event02":
		out, err := decodeSpecIdEvent02(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event02 data: %w", err)
		}
		return out, nil
	case "Spec ID Event03":
		out, err := decodeSpecIdEvent03(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event03 data: %w", err)
		}
		return out, nil
	case "SP800-155 Event":
		out, err := decodeBIMReferenceManifestEvent(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode SP800-155 Event data: %w", err)
		}
		return out, nil
	case "SP800-155 Event2":
		out, err := decodeBIMReferenceManifestEvent2(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode SP800-155 Event2 data: %w", err)
		}
		return out, nil
	case "SP800-155 Event3":
		out, err := decodeBIMReferenceManifestEvent3(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode SP800-155 Event3 data: %w", err)
		}
		return out, nil
	case "StartupLocality":
		out, err := decodeStartupLocalityEvent(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode StartupLocality data: %w", err)
		}
		return out, nil
	case "H-CRTM CompMeas":
		out, err := decodeHCRTMComponentEvent(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decocde H-CRTM CompMeas data: %w", err)
		}
		return out, nil
	default:
		return nil, nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func decodeEventDataAction(data []byte) (StringEventData, error) {
	if !isPrintableASCII(data, false) {
		return "", errors.New("data does not contain printable ASCII that is not NULL terminated")
	}
	return StringEventData(data), nil
}

// SeparatorEventData is the event data associated with a EV_SEPARATOR event.
type SeparatorEventData struct {
	Value     uint32 // The separator value measured to the TPM
	ErrorInfo []byte // The error information recorded in the log when Value == SeparatorEventErrorValue
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//
//	(section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
//
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//
//	(section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//	 "Procedure for Pre-OS to OS-Present Transition")
func decodeEventDataSeparator(data []byte, digests DigestMap) (*SeparatorEventData, error) {
	for alg, digest := range digests {
		errorDigest, ok := separatorErrorDigests[alg]
		if !ok {
			continue
		}
		if bytes.Equal(digest, errorDigest) {
			// This separator event indicates an error. The digest is the tagged hash of the
			// error value (uint32(1)) and the event data is information about the error.
			return &SeparatorEventData{Value: SeparatorEventErrorValue, ErrorInfo: data}, nil
		}
	}

	// Not an error separator. The digest is the tagged hash of the event data, which contains one of
	// uint32(0) or uint32(0xffffffff).
	if len(data) != binary.Size(uint32(0)) {
		return nil, errors.New("data is the wrong size")
	}

	value := binary.LittleEndian.Uint32(data)
	switch value {
	case SeparatorEventNormalValue, SeparatorEventAltNormalValue:
	default:
		return nil, fmt.Errorf("invalid separator value: %d", value)
	}

	return &SeparatorEventData{Value: value}, nil
}

// IsError indicates that this event was associated with an error condition.
// The value returned from Bytes() contains an implementation defined indication
// of the actual error.
func (e *SeparatorEventData) IsError() bool {
	return e.Value == SeparatorEventErrorValue
}

// String implements [fmt.Stringer].
func (e *SeparatorEventData) String() string {
	if !e.IsError() {
		return ""
	}
	return fmt.Sprintf("ERROR: 0x%x", e.ErrorInfo)
}

// Bytes implements [EventData.Bytes].
func (e *SeparatorEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
func (e *SeparatorEventData) Write(w io.Writer) error {
	switch e.Value {
	case SeparatorEventNormalValue, SeparatorEventAltNormalValue:
		return binary.Write(w, binary.LittleEndian, e.Value)
	case SeparatorEventErrorValue:
		_, err := w.Write(e.ErrorInfo)
		return err
	default:
		return errors.New("invalid value")
	}
}

// ComputeSeparatorEventDigest computes the digest associated with the separator event. The value
// argument should be one of SeparatorEventNormalValue, SeparatorEventAltNormalValue or
// SeparatorEventErrorValue.
func ComputeSeparatorEventDigest(alg crypto.Hash, value uint32) []byte {
	h := alg.New()
	binary.Write(h, binary.LittleEndian, value)
	return h.Sum(nil)
}

func decodeEventDataCompactHash(data []byte) (StringEventData, error) {
	if !isPrintableASCII(data, false) {
		return "", errors.New("data does not contain printable ASCII that is not NULL terminated")
	}
	return StringEventData(data), nil
}

func decodeEventDataPostCode(data []byte) (EventData, error) {
	if isPrintableASCII(data, false) {
		return StringEventData(data), nil
	}
	return decodeEventDataEFIPlatformFirmwareBlob(data)
}

func decodeEventDataPostCode2(data []byte) (EventData, error) {
	if isPrintableASCII(data, false) {
		return StringEventData(data), nil
	}
	return decodeEventDataEFIPlatformFirmwareBlob2(data)
}

func decodeEventDataOmitBootDeviceEvents(data []byte) (StringEventData, error) {
	if !bytes.Equal(data, mustSucceed(BootAttemptsOmitted.Bytes())) {
		return "", errors.New("data contains unexpected contents")
	}
	return StringEventData(data), nil
}

// TaggedEvent corresponds to TCG_PCClientTaggedEvent. It is not informative - ie, the
// event digest should be the tagged hash of this field.
type TaggedEvent struct {
	EventID uint32
	Data    []byte
}

func decodeEventDataTaggedEvent(data []byte) (*TaggedEvent, error) {
	r := bytes.NewReader(data)

	d := new(TaggedEvent)

	if err := binary.Read(r, binary.LittleEndian, &d.EventID); err != nil {
		return nil, fmt.Errorf("cannot decode taggedEventID: %w", err)
	}

	data, err := readLengthPrefixed[uint32, byte](r)
	if err != nil {
		return nil, fmt.Errorf("cannot read taggedEventData: %w", err)
	}
	d.Data = data

	return d, nil
}

// String implements [fmt.Stringer].
func (e *TaggedEvent) String() string {
	return fmt.Sprintf(`TCG_PCClientTaggedEvent {
	taggedEventID: %d,
	taggedEventData:
		%s,
}`, e.EventID, strings.Replace(hex.Dump(e.Data), "\n", "\n\t\t", -1))
}

// Bytes implements [EventData.Bytes].
func (e *TaggedEvent) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Write implements [EventData.Write].
func (e *TaggedEvent) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, e.EventID); err != nil {
		return fmt.Errorf("cannot write taggedEventID: %w", err)
	}

	if err := writeLengthPrefixed[uint32, byte](w, e.Data); err != nil {
		return fmt.Errorf("cannot write taggedEventData: %w", err)
	}

	return nil
}

// ComputeTaggedEventDigest computes the digest for the specified TaggedEvent.
func ComputeTaggedEventDigest(alg crypto.Hash, ev *TaggedEvent) []byte {
	h := alg.New()
	ev.Write(h)
	return h.Sum(nil)
}

func decodeEventDataSCRTMContents(data []byte) (EventData, error) {
	// If measured by a H-CRTM event, this may be a NULL terminated string
	if isPrintableASCII(data, true) {
		return decodeNullTerminatedStringEventData(data)
	}
	// Try UEFI_PLATFORM_FIRMWARE_BLOB
	if len(data) == 16 { // The size of a UEFI_PLATFORM_FIRMWARE_BLOB
		return decodeEventDataEFIPlatformFirmwareBlob(data)
	}
	// Try UEFI_PLATFORM_FIRMWARE_BLOB2
	return decodeEventDataEFIPlatformFirmwareBlob2(data)
}

func decodeEventDataSCRTMVersion(data []byte) (EventData, error) {
	if isPrintableUCS2(data, true) {
		return decodeNullTerminatedUCS2StringEventData(data)
	}
	if len(data) == 16 {
		guid, err := efi.ReadGUID(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return GUIDEventData(guid), nil
	}
	return nil, errors.New("event data is not a NULL-terminated UCS2 string or a EFI_GUID")
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.1 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.2 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.4.1 "Event Types")
func decodeEventDataTCG(data []byte, eventType EventType, digests DigestMap) (out EventData, err error) {
	switch eventType {
	case EventTypeNoAction:
		return decodeEventDataNoAction(data)
	case EventTypeSeparator:
		return decodeEventDataSeparator(data, digests)
	case EventTypeAction, EventTypeEFIAction:
		return decodeEventDataAction(data)
	case EventTypePostCode:
		return decodeEventDataPostCode(data)
	case EventTypePostCode2:
		return decodeEventDataPostCode2(data)
	case EventTypeEFIPlatformFirmwareBlob:
		return decodeEventDataEFIPlatformFirmwareBlob(data)
	case EventTypeEFIPlatformFirmwareBlob2:
		return decodeEventDataEFIPlatformFirmwareBlob2(data)
	case EventTypeCompactHash:
		return decodeEventDataCompactHash(data)
	case EventTypeEFIVariableDriverConfig, EventTypeEFIVariableBoot, EventTypeEFIVariableAuthority, EventTypeEFIVariableBoot2:
		return decodeEventDataEFIVariable(data)
	case EventTypeEFIBootServicesApplication, EventTypeEFIBootServicesDriver, EventTypeEFIRuntimeServicesDriver:
		return decodeEventDataEFIImageLoad(data)
	case EventTypeEFIGPTEvent, EventTypeEFIGPTEvent2:
		return decodeEventDataEFIGPT(data)
	case EventTypeEFIHCRTMEvent:
		return decodeEventDataEFIHCRTMEvent(data)
	case EventTypeEFIHandoffTables:
		return decodeEventDataEFIHandoffTablePointers(data)
	case EventTypeEFIHandoffTables2:
		return decodeEventDataEFIHandoffTablePointers2(data)
	case EventTypeEventTag:
		return decodeEventDataTaggedEvent(data)
	case EventTypeSCRTMContents:
		return decodeEventDataSCRTMContents(data)
	case EventTypeSCRTMVersion:
		return decodeEventDataSCRTMVersion(data)
	case EventTypeOmitBootDeviceEvents:
		return decodeEventDataOmitBootDeviceEvents(data)
	default:
	}

	if err != nil {
		err = xerrors.Errorf("cannot decode %v event data: %w", eventType, err)
	}
	return
}
