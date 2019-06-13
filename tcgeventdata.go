package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

type SeparatorEventType uint

type EFISpecIdEventAlgorithmSize struct {
	AlgorithmId AlgorithmId
	DigestSize  uint16
}

type SpecIdEventData struct {
	data             []byte
	Spec             Spec
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	uintnSize        uint8
	DigestSizes      []EFISpecIdEventAlgorithmSize
	VendorInfo       []byte
}

func (e *SpecIdEventData) String() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "SpecIdEvent{ spec=%d, platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, "+
		"specErrata=%d", e.Spec, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
	if e.Spec == SpecEFI_2 {
		fmt.Fprintf(&builder, ", digestSizes=[")
		for i, algSize := range e.DigestSizes {
			if i > 0 {
				fmt.Fprintf(&builder, ", ")
			}
			fmt.Fprintf(&builder, "{ algorithmId=0x%04x, digestSize=%d }",
				uint16(algSize.AlgorithmId), algSize.DigestSize)
		}
		fmt.Fprintf(&builder, "]")
	}
	fmt.Fprintf(&builder, " }")
	return builder.String()
}

func (e *SpecIdEventData) RawBytes() []byte {
	return e.data
}

func (e *SpecIdEventData) MeasuredBytes() []byte {
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func parsePCClientSpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) error {
	eventData.Spec = SpecPCClient

	// TCG_PCClientSpecIdEventStruct.reserved
	var reserved uint8
	if err := binary.Read(stream, order, &reserved); err != nil {
		return err
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return err
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return err
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return err
	}

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return err
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return err
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return err
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, order, &numberOfAlgorithms); err != nil {
		return err
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		if err := binary.Read(stream, order, &eventData.DigestSizes[i].AlgorithmId); err != nil {
			return err
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		if err := binary.Read(stream, order, &eventData.DigestSizes[i].DigestSize); err != nil {
			return err
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return err
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return err
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func makeSpecIdEvent(stream io.Reader, order binary.ByteOrder, data []byte,
	helper func(io.Reader, binary.ByteOrder, *SpecIdEventData) error) (*SpecIdEventData, error) {
	// platformClass field
	var platformClass uint32
	if err := binary.Read(stream, order, &platformClass); err != nil {
		return nil, err
	}

	// specVersionMinor field
	var specVersionMinor uint8
	if err := binary.Read(stream, order, &specVersionMinor); err != nil {
		return nil, err
	}

	// specVersionMajor field
	var specVersionMajor uint8
	if err := binary.Read(stream, order, &specVersionMajor); err != nil {
		return nil, err
	}

	// specErrata field
	var specErrata uint8
	if err := binary.Read(stream, order, &specErrata); err != nil {
		return nil, err
	}

	eventData := &SpecIdEventData{
		data:             data,
		PlatformClass:    platformClass,
		SpecVersionMinor: specVersionMinor,
		SpecVersionMajor: specVersionMajor,
		SpecErrata:       specErrata}

	if err := helper(stream, order, eventData); err != nil {
		return nil, err
	}

	return eventData, nil
}

var (
	validNormalSeparatorValues = [...]uint32{0, math.MaxUint32}
)

type SeparatorEventData struct {
	data []byte
	Type SeparatorEventType
}

func (e *SeparatorEventData) String() string {
	if e.Type == SeparatorEventTypeError {
		return "Error"
	}
	return ""
}

func (e *SeparatorEventData) RawBytes() []byte {
	return e.data
}

func (e *SeparatorEventData) MeasuredBytes() []byte {
	if e.Type == SeparatorEventTypeNormal {
		return e.data
	}
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
func makeEventDataSeparator(data []byte, order binary.ByteOrder) (*SeparatorEventData, error) {
	if len(data) != 4 {
		return nil, io.EOF
	}

	v := order.Uint32(data)

	t := SeparatorEventTypeError
	for _, w := range validNormalSeparatorValues {
		if v == w {
			t = SeparatorEventTypeNormal
			break
		}
	}

	return &SeparatorEventData{data, t}, nil
}

type AsciiStringEventData struct {
	data          []byte
	informational bool
}

func (e *AsciiStringEventData) String() string {
	var builder strings.Builder
	builder.Write(e.data)
	return builder.String()
}

func (e *AsciiStringEventData) RawBytes() []byte {
	return e.data
}

func (e *AsciiStringEventData) MeasuredBytes() []byte {
	if !e.informational {
		return e.data
	}
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5 "EV_NO_ACTION Event Types")
func makeEventDataNoAction(data []byte, order binary.ByteOrder) (EventData, error) {
	stream := bytes.NewReader(data)

	// Signature field
	sigRaw := make([]byte, 16)
	if _, err := io.ReadFull(stream, sigRaw); err != nil {
		return nil, err
	}

	var signature strings.Builder
	if _, err := signature.Write(sigRaw); err != nil {
		return nil, err
	}

	switch signature.String() {
	case "Spec ID Event00\x00":
		return makeSpecIdEvent(stream, order, data, parsePCClientSpecIdEvent)
	case "Spec ID Event02\x00":
		return makeSpecIdEvent(stream, order, data, parseEFI_1_2_SpecIdEvent)
	case "Spec ID Event03\x00":
		return makeSpecIdEvent(stream, order, data, parseEFI_2_SpecIdEvent)
	default:
		return nil, nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func makeEventDataAction(data []byte) *AsciiStringEventData {
	return &AsciiStringEventData{data: data, informational: false}
}

func makeEventDataTCG(eventType EventType, data []byte, order binary.ByteOrder) (EventData, error) {
	switch eventType {
	case EventTypeNoAction:
		return makeEventDataNoAction(data, order)
	case EventTypeSeparator:
		d, err := makeEventDataSeparator(data, order)
		if err != nil {
			return nil, err
		}
		return d, nil
	case EventTypeAction, EventTypeEFIAction:
		return makeEventDataAction(data), nil
	case EventTypeEFIVariableDriverConfig, EventTypeEFIVariableBoot, EventTypeEFIVariableAuthority:
		d, err := makeEventDataEFIVariable(data, order)
		if err != nil {
			return nil, err
		}
		return d, nil
	case EventTypeEFIBootServicesApplication, EventTypeEFIBootServicesDriver,
		EventTypeEFIRuntimeServicesDriver:
		d, err := makeEventDataImageLoad(data, order)
		if err != nil {
			return nil, err
		}
		return d, nil
	default:
	}
	return nil, nil
}
