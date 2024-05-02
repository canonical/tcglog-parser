// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

var separatorErrorDigests = make(map[tpm2.HashAlgorithmId]tpm2.Digest)

// StringEventData corresponds to event data that is an non-NULL terminated ASCII string.
// It may or may not be informative.
type StringEventData string

func (d StringEventData) String() string {
	return string(d)
}

func (d StringEventData) Write(w io.Writer) error {
	_, err := io.WriteString(w, string(d))
	return err
}

func (d StringEventData) Bytes() []byte {
	return []byte(d)
}

// ComputeStringEventDigest computes the digest associated with the supplied string, for
// events where the data is not informative. The function assumes that the string is
// ASCII encoded and measured without a terminating NULL byte.
func ComputeStringEventDigest(alg crypto.Hash, str string) []byte {
	h := alg.New()
	io.WriteString(h, str)
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
	case "StartupLocality":
		out, err := decodeStartupLocalityEvent(data, r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode StartupLocality data: %w", err)
		}
		return out, nil
	default:
		return nil, nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func decodeEventDataAction(data []byte) (StringEventData, error) {
	if !isPrintableASCII(data) {
		return "", errors.New("data does not contain printable ASCII")
	}
	return StringEventData(data), nil
}

// SeparatorEventData is the event data associated with a EV_SEPARATOR event.
type SeparatorEventData struct {
	rawEventData
	Value uint32 // The separator value measured to the TPM
}

func NewErrorSeparatorEventData(err []byte) *SeparatorEventData {
	return &SeparatorEventData{rawEventData: err, Value: SeparatorEventErrorValue}
}

// IsError indicates that this event was associated with an error condition.
// The value returned from Bytes() contains an implementation defined indication
// of the actual error.
func (e *SeparatorEventData) IsError() bool {
	return e.Value == SeparatorEventErrorValue
}

func (e *SeparatorEventData) String() string {
	if !e.IsError() {
		return ""
	}
	return fmt.Sprintf("ERROR: 0x%x", e.rawEventData)
}

func (e *SeparatorEventData) Write(w io.Writer) error {
	switch e.Value {
	case SeparatorEventNormalValue, SeparatorEventAltNormalValue:
		return binary.Write(w, binary.LittleEndian, e.Value)
	case SeparatorEventErrorValue:
		_, err := w.Write(e.rawEventData)
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

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//
//	(section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
//
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//
//	(section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//	 "Procedure for Pre-OS to OS-Present Transition")
func decodeEventDataSeparator(data []byte, digests DigestMap) (*SeparatorEventData, error) {
	var alg tpm2.HashAlgorithmId
	for a, _ := range digests {
		if !alg.IsValid() || a.Size() > alg.Size() {
			alg = a
		}
	}

	errorDigest, ok := separatorErrorDigests[alg]
	if !ok {
		h := alg.NewHash()
		binary.Write(h, binary.LittleEndian, SeparatorEventErrorValue)
		separatorErrorDigests[alg] = h.Sum(nil)
		errorDigest = separatorErrorDigests[alg]
	}

	if bytes.Equal(digests[alg], errorDigest) {
		return &SeparatorEventData{rawEventData: data, Value: SeparatorEventErrorValue}, nil
	}

	if len(data) != binary.Size(uint32(0)) {
		return nil, errors.New("data is the wrong size")
	}

	value := binary.LittleEndian.Uint32(data)
	switch value {
	case SeparatorEventNormalValue, SeparatorEventErrorValue, SeparatorEventAltNormalValue:
	default:
		return nil, fmt.Errorf("invalid separator value: %d", value)
	}

	return &SeparatorEventData{rawEventData: data, Value: value}, nil
}

func decodeEventDataCompactHash(data []byte) (StringEventData, error) {
	if !isPrintableASCII(data) {
		return "", errors.New("data does not contain printable ASCII")
	}
	return StringEventData(data), nil
}

func decodeEventDataPostCode(data []byte) (EventData, error) {
	if isPrintableASCII(data) {
		return StringEventData(data), nil
	}
	return decodeEventDataEFIPlatformFirmwareBlob(data)
}

func decodeEventDataPostCode2(data []byte) (EventData, error) {
	if isPrintableASCII(data) {
		return StringEventData(data), nil
	}
	return decodeEventDataEFIPlatformFirmwareBlob2(data)
}

// TaggedEvent corresponds to TCG_PCClientTaggedEvent
type TaggedEvent struct {
	rawEventData
	EventID uint32
	Data    []byte
}

func (e *TaggedEvent) String() string {
	return fmt.Sprintf("TCG_PCClientTaggedEvent{taggedEventID: %d, taggedEventData: %x}", e.EventID, e.Data)
}

func (e *TaggedEvent) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, e.EventID); err != nil {
		return fmt.Errorf("cannot write taggedEventID: %w", err)
	}

	if err := writeLengthPrefixed[uint32, byte](w, e.Data); err != nil {
		return fmt.Errorf("cannot write taggedEventData: %w", err)
	}

	return nil
}

func decodeEventDataTaggedEvent(data []byte) (*TaggedEvent, error) {
	r := bytes.NewReader(data)

	d := &TaggedEvent{rawEventData: data}

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
	case EventTypeEFIHandoffTables:
		return decodeEventDataEFIHandoffTablePointers(data)
	case EventTypeEFIHandoffTables2:
		return decodeEventDataEFIHandoffTablePointers2(data)
	case EventTypeEventTag:
		return decodeEventDataTaggedEvent(data)
	default:
	}

	if err != nil {
		err = xerrors.Errorf("cannot decode %v event data: %w", eventType, err)
	}
	return
}
