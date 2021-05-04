// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"golang.org/x/xerrors"
)

type invalidSpecIdEventError struct {
	err error
}

func (e invalidSpecIdEventError) Error() string {
	return e.err.Error()
}

func (e invalidSpecIdEventError) Unwrap() error {
	return e.err
}

// EFISpecIdEventAlgorithmSize represents a digest algorithm and its length and corresponds to the
// TCG_EfiSpecIdEventAlgorithmSize type.
type EFISpecIdEventAlgorithmSize struct {
	AlgorithmId AlgorithmId
	DigestSize  uint16
}

// NoActionEventType corresponds to the type of a EV_NO_ACTION event.
type NoActionEventType int

const (
	UnknownNoActionEvent     NoActionEventType = iota // Unknown EV_NO_ACTION event type
	SpecId                                            // "Spec ID Event00", "Spec ID Event02" or "Spec ID Event03" event type
	StartupLocality                                   // "StartupLocality" event type
	BiosIntegrityMeasurement                          // "SP800-155 Event" event type
)

// NoActionEventData provides a mechanism to determine the type of a EV_NO_ACTION event from the decoded EventData.
type NoActionEventData interface {
	Type() NoActionEventType
	Spec() string
}

// SpecIdEvent corresponds to the TCG_PCClientSpecIdEventStruct, TCG_EfiSpecIdEventStruct, and TCG_EfiSpecIdEvent types and is the
// event data for a Specification ID Version EV_NO_ACTION event.
type SpecIdEvent struct {
	data             []byte
	signature        string
	Spec             Spec
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	DigestSizes      []EFISpecIdEventAlgorithmSize // The digest algorithms contained within this log
	VendorInfo       []byte
}

func (e *SpecIdEvent) String() string {
	var builder bytes.Buffer
	switch e.Spec {
	case SpecPCClient:
		builder.WriteString("PCClientSpecIdEvent")
	case SpecEFI_1_2, SpecEFI_2:
		builder.WriteString("EfiSpecIDEvent")
	}

	fmt.Fprintf(&builder, "{ spec=%d, platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, "+
		"specErrata=%d", e.Spec, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
	if e.Spec == SpecEFI_2 {
		builder.WriteString(", digestSizes=[")
		for i, algSize := range e.DigestSizes {
			if i > 0 {
				builder.WriteString(", ")
			}
			fmt.Fprintf(&builder, "{ algorithmId=0x%04x, digestSize=%d }",
				uint16(algSize.AlgorithmId), algSize.DigestSize)
		}
		builder.WriteString("]")
	}
	builder.WriteString(" }")
	return builder.String()
}

func (e *SpecIdEvent) Bytes() []byte {
	return e.data
}

func (e *SpecIdEvent) Type() NoActionEventType {
	return SpecId
}

func (e *SpecIdEvent) Signature() string {
	return e.signature
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func parsePCClientSpecIdEvent(r io.Reader, eventData *SpecIdEvent) error {
	eventData.Spec = SpecPCClient

	// TCG_PCClientSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return xerrors.Errorf("cannot read vendor info size: %w", err)
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, eventData.VendorInfo); err != nil {
		return xerrors.Errorf("cannot read vendor info: %w", err)
	}

	return nil
}

type specIdEventCommon struct {
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func decodeSpecIdEvent(r io.Reader, signature string, data []byte, helper func(io.Reader, *SpecIdEvent) error) (*SpecIdEvent, error) {
	var common struct {
		PlatformClass    uint32
		SpecVersionMinor uint8
		SpecVersionMajor uint8
		SpecErrata       uint8
		UintnSize        uint8
	}
	if err := binary.Read(r, binary.LittleEndian, &common); err != nil {
		return nil, invalidSpecIdEventError{xerrors.Errorf("cannot read common fields: %w", err)}
	}

	eventData := &SpecIdEvent{
		data:             data,
		signature:        signature,
		PlatformClass:    common.PlatformClass,
		SpecVersionMinor: common.SpecVersionMinor,
		SpecVersionMajor: common.SpecVersionMajor,
		SpecErrata:       common.SpecErrata,
		UintnSize:        common.UintnSize}

	if err := helper(r, eventData); err != nil {
		return nil, invalidSpecIdEventError{err}
	}

	return eventData, nil
}

var (
	validNormalSeparatorValues = [...]uint32{0, math.MaxUint32}
)

// asciiStringEventData corresponds to event data that is an ASCII string. The event data may be informational (it provides a hint
// as to what was measured as opposed to representing what was measured).
type asciiStringEventData string

func (d asciiStringEventData) String() string {
	return string(d)
}

func (d asciiStringEventData) Bytes() []byte {
	return []byte(d)
}

// unknownNoActionEventData is the event data for a EV_NO_ACTION event with an unrecognized type.
type unknownNoActionEventData struct {
	data      []byte
	signature string
}

func (e *unknownNoActionEventData) String() string {
	return ""
}

func (e *unknownNoActionEventData) Bytes() []byte {
	return e.data
}

func (e *unknownNoActionEventData) Type() NoActionEventType {
	return UnknownNoActionEvent
}

func (e *unknownNoActionEventData) Signature() string {
	return e.signature
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5 "EV_NO_ACTION Event Types")
func decodeEventDataNoAction(data []byte) (EventData, error) {
	r := bytes.NewReader(data)

	// Signature field
	var sig [16]byte
	if _, err := io.ReadFull(r, sig[:]); err != nil {
		return nil, xerrors.Errorf("cannot read signature: %w", err)
	}
	signature := strings.TrimRight(string(sig[:]), "\x00")

	switch signature {
	case "Spec ID Event00":
		out, err := decodeSpecIdEvent(r, signature, data, parsePCClientSpecIdEvent)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event00 data: %w", err)
		}
		return out, nil
	case "Spec ID Event02":
		out, err := decodeSpecIdEvent(r, signature, data, parseEFI_1_2_SpecIdEvent)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event02 data: %w", err)
		}
		return out, nil
	case "Spec ID Event03":
		out, err := decodeSpecIdEvent(r, signature, data, parseEFI_2_SpecIdEvent)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode Spec ID Event03 data: %w", err)
		}
		return out, nil
	case "SP800-155 Event":
		out, err := decodeBIMReferenceManifestEvent(r, signature, data)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode SP800-155 Event data: %w", err)
		}
		return out, nil
	case "StartupLocality":
		out, err := decodeStartupLocalityEvent(r, signature, data)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode StartupLocality data: %w", err)
		}
		return out, nil
	default:
		return &unknownNoActionEventData{data: data, signature: signature}, nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func decodeEventDataAction(data []byte) asciiStringEventData {
	return asciiStringEventData(data)
}

func decodeEventDataHostPlatformSpecificCompactHash(data []byte) asciiStringEventData {
	return asciiStringEventData(data)
}

// SeparatorEventData is the event data associated with a EV_SEPARATOR event.
type SeparatorEventData struct {
	data    []byte
	IsError bool // The event indicates an error condition
}

func (e *SeparatorEventData) String() string {
	if !e.IsError {
		return ""
	}
	return "*ERROR*"
}

func (e *SeparatorEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
func decodeEventDataSeparator(digests DigestMap, data []byte) *SeparatorEventData {
	errorValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(errorValue, SeparatorEventErrorValue)

	var isError bool
	for alg, digest := range digests {
		isError = bytes.Equal(digest, alg.hash(errorValue))
		break
	}

	return &SeparatorEventData{data: data, IsError: isError}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.1 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.2 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.4.1 "Event Types")
func decodeEventDataTCG(pcrIndex PCRIndex, eventType EventType, digests DigestMap, data []byte) (out EventData, err error) {
	switch eventType {
	case EventTypeNoAction:
		out, err = decodeEventDataNoAction(data)
	case EventTypeSeparator:
		return decodeEventDataSeparator(digests, data), nil
	case EventTypeAction, EventTypeEFIAction:
		return decodeEventDataAction(data), nil
	case EventTypeCompactHash:
		if pcrIndex == 6 {
			return decodeEventDataHostPlatformSpecificCompactHash(data), nil
		}
	case EventTypeEFIVariableDriverConfig, EventTypeEFIVariableBoot, EventTypeEFIVariableAuthority:
		out, err = decodeEventDataEFIVariable(data, eventType)
	case EventTypeEFIBootServicesApplication, EventTypeEFIBootServicesDriver, EventTypeEFIRuntimeServicesDriver:
		out, err = decodeEventDataEFIImageLoad(data)
	case EventTypeEFIGPTEvent:
		out, err = decodeEventDataEFIGPT(data)
	default:
	}

	if err != nil {
		err = xerrors.Errorf("cannot decode %v event data: %w", eventType, err)
	}
	return
}
