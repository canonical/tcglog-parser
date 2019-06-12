package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"unsafe"
)

type EventData interface {
	String() string
	Bytes() []byte
}

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
	fmt.Fprintf(&builder, "SpecIdEvent{spec=%d, platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, "+
		"specErrata=%d", e.Spec, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
	if e.Spec == SpecEFI_2 {
		fmt.Fprintf(&builder, ", digestSizes=[")
		for i, algSize := range e.DigestSizes {
			if i > 0 {
				fmt.Fprintf(&builder, ", ")
			}
			fmt.Fprintf(&builder, "{algorithmId=%04x, digestSize=%d}",
				algSize.AlgorithmId, algSize.DigestSize)
		}
		fmt.Fprintf(&builder, "]")
	}
	fmt.Fprintf(&builder, "}")
	return builder.String()
}

func (e *SpecIdEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func parsePCClientSpecIdEvent(stream io.Reader, eventData *SpecIdEventData) EventData {
	eventData.Spec = SpecPCClient

	// TCG_PCClientSpecIdEventStruct.reserved
	var reserved uint8
	if err := binary.Read(stream, nativeEndian, &reserved); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, nativeEndian, &vendorInfoSize); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return nil
	}

	return eventData
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData) EventData {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.uintnSize
	if err := binary.Read(stream, nativeEndian, &eventData.uintnSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, nativeEndian, &vendorInfoSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return nil
	}

	return eventData
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData) EventData {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.uintnSize
	if err := binary.Read(stream, nativeEndian, &eventData.uintnSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, nativeEndian, &numberOfAlgorithms); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		if err := binary.Read(stream, nativeEndian, &eventData.DigestSizes[i].AlgorithmId); err != nil {
			return nil
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		if err := binary.Read(stream, nativeEndian, &eventData.DigestSizes[i].DigestSize); err != nil {
			return nil
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, nativeEndian, &vendorInfoSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return nil
	}

	return eventData
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseSpecIdEvent(data []byte) EventData {
	stream := bytes.NewReader(data)

	// Signature field
	sigRaw := make([]byte, 16)
	if _, err := io.ReadFull(stream, sigRaw); err != nil {
		return nil
	}

	var signature strings.Builder
	if _, err := signature.Write(sigRaw); err != nil {
		return nil
	}

	// platformClass field
	var platformClass uint32
	if err := binary.Read(stream, nativeEndian, &platformClass); err != nil {
		return nil
	}

	// specVersionMinor field
	var specVersionMinor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMinor); err != nil {
		return nil
	}

	// specVersionMajor field
	var specVersionMajor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMajor); err != nil {
		return nil
	}

	// specErrata field
	var specErrata uint8
	if err := binary.Read(stream, nativeEndian, &specErrata); err != nil {
		return nil
	}

	eventData := &SpecIdEventData{
		data:             data,
		PlatformClass:    platformClass,
		SpecVersionMinor: specVersionMinor,
		SpecVersionMajor: specVersionMajor,
		SpecErrata:       specErrata}

	switch signature.String() {
	case "Spec ID Event00\x00":
		return parsePCClientSpecIdEvent(stream, eventData)
	case "Spec ID Event02\x00":
		return parseEFI_1_2_SpecIdEvent(stream, eventData)
	case "Spec ID Event03\x00":
		return parseEFI_2_SpecIdEvent(stream, eventData)
	default:
		return nil
	}
}

var (
	validNormalSeparatorValues = [...]uint32{0, math.MaxUint32}
)

type SeparatorEventType uint32

type SeparatorEventData struct {
	data []byte
	Type SeparatorEventType
}

type AsciiStringEventData struct {
	data []byte
}

func (e *SeparatorEventData) String() string {
	if e.Type == SeparatorEventTypeError {
		return "Error"
	} else {
		return ""
	}
}

func (e *SeparatorEventData) Bytes() []byte {
	return e.data
}

func (e *AsciiStringEventData) String() string {
	var builder strings.Builder
	builder.Write(e.data)
	return builder.String()
}

func (e *AsciiStringEventData) Bytes() []byte {
	return e.data
}

type opaqueEventData struct {
	data []byte
}

func (e *opaqueEventData) String() string {
	return ""
}

func (e *opaqueEventData) Bytes() []byte {
	return e.data
}

func makeEventDataNoAction(pcrIndex PCRIndex, data []byte) EventData {
	switch pcrIndex {
	case 0:
		return parseSpecIdEvent(data)
	default:
		return nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
func makeEventDataSeparator(data []byte) EventData {
	if len(data) != 4 {
		return nil
	}

	v := *(*uint32)(unsafe.Pointer(&data[0]))

	t := SeparatorEventTypeError
	for _, w := range validNormalSeparatorValues {
		if v == w {
			t = SeparatorEventTypeNormal
			break
		}
	}

	return &SeparatorEventData{data, t}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func makeEventDataAction(data []byte) EventData {
	return &AsciiStringEventData{data}
}

func makeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte) EventData {
	switch eventType {
	case EventTypeNoAction:
		return makeEventDataNoAction(pcrIndex, data)
	case EventTypeSeparator:
		return makeEventDataSeparator(data)
	case EventTypeAction:
		return makeEventDataAction(data)
	default:
		return nil
	}
}

func makeEventData(pcrIndex PCRIndex, eventType EventType, data []byte) EventData {
	var e EventData
	if e = makeEventDataImpl(pcrIndex, eventType, data); e == nil {
		e = &opaqueEventData{data}
	}
	return e
}
