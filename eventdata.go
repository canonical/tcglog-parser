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

type EFISpecIdEventData struct {
	data             []byte
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	uintnSize        uint8
	DigestSizes      []EFISpecIdEventAlgorithmSize
	VendorInfo       []byte
}

type PCClientSpecIdEventData struct {
	data             []byte
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	VendorInfo       []byte
}

var (
	validNormalSeparatorValues = [...]uint32{0, math.MaxUint32}
)

type SeparatorEventType uint32

type SeparatorEventData struct {
	data []byte
	Type SeparatorEventType
}

func (e *EFISpecIdEventData) String() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "TCG_EfiSpecIdEvent{platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, "+
		"specErrata=%d, digestSizes=[", e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor,
		e.SpecErrata)
	for i, algSize := range e.DigestSizes {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{algorithmId=%04x, digestSize=%d}",
			algSize.AlgorithmId, algSize.DigestSize)
	}
	fmt.Fprintf(&builder, "]}")
	return builder.String()
}

func (e *EFISpecIdEventData) Bytes() []byte {
	return e.data
}

func (e *PCClientSpecIdEventData) String() string {
	return fmt.Sprintf("TCG_PCClientSpecIdEventStruct{platformClass=%d, specVersionMinor=%d, "+
		"specVersionMajor=%d, specErrata=%d}", e.PlatformClass, e.SpecVersionMinor,
		e.SpecVersionMajor, e.SpecErrata)
}

func (e *PCClientSpecIdEventData) Bytes() []byte {
	return e.data
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

type eventDataUnclassified struct {
	data []byte
}

func (e *eventDataUnclassified) String() string {
	return ""
}

func (e *eventDataUnclassified) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFISpecIdEvent(data []byte) EventData {
	stream := bytes.NewReader(data)

	// TCG_EfiSpecIdEvent.Signature
	sigRaw := make([]byte, 16)
	if _, err := io.ReadFull(stream, sigRaw); err != nil {
		return nil
	}

	var signature strings.Builder
	if _, err := signature.Write(sigRaw); err != nil {
		return nil
	}

	if signature.String() != "Spec ID Event03\x00" {
		return nil
	}

	// TCG_EfiSpecIdEvent.platformClass
	var platformClass uint32
	if err := binary.Read(stream, nativeEndian, &platformClass); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.specVersionMinor
	var specVersionMinor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMinor); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.specVersionMajor
	var specVersionMajor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMajor); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.specErrata
	var specErrata uint8
	if err := binary.Read(stream, nativeEndian, &specErrata); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.uintnSize
	var uintnSize uint8
	if err := binary.Read(stream, nativeEndian, &uintnSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, nativeEndian, &numberOfAlgorithms); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.digestSizes
	digestSizes := make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		var algorithmId AlgorithmId
		if err := binary.Read(stream, nativeEndian, &algorithmId); err != nil {
			return nil
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		var digestSize uint16
		if err := binary.Read(stream, nativeEndian, &digestSize); err != nil {
			return nil
		}

		digestSizes[i] = EFISpecIdEventAlgorithmSize{algorithmId, digestSize}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, nativeEndian, &vendorInfoSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	vendorInfo := make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, vendorInfo); err != nil {
		return nil
	}

	return &EFISpecIdEventData{
		data:             data,
		PlatformClass:    platformClass,
		SpecVersionMinor: specVersionMinor,
		SpecVersionMajor: specVersionMajor,
		SpecErrata:       specErrata,
		uintnSize:        uintnSize,
		DigestSizes:      digestSizes,
		VendorInfo:       vendorInfo}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func parsePCClientSpecIdEvent(data []byte) EventData {
	stream := bytes.NewReader(data)

	// TCG_PCClientSpecIdEventStruct.Signature
	sigRaw := make([]byte, 16)
	if _, err := io.ReadFull(stream, sigRaw); err != nil {
		return nil
	}

	var signature strings.Builder
	if _, err := signature.Write(sigRaw); err != nil {
		return nil
	}

	if signature.String() != "Spec ID Event00\x00" {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.platformClass
	var platformClass uint32
	if err := binary.Read(stream, nativeEndian, &platformClass); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.specVersionMinor
	var specVersionMinor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMinor); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.specVersionMajor
	var specVersionMajor uint8
	if err := binary.Read(stream, nativeEndian, &specVersionMajor); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.specErrata
	var specErrata uint8
	if err := binary.Read(stream, nativeEndian, &specErrata); err != nil {
		return nil
	}

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
	vendorInfo := make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, vendorInfo); err != nil {
		return nil
	}

	return &PCClientSpecIdEventData{
		data:             data,
		PlatformClass:    platformClass,
		SpecVersionMinor: specVersionMinor,
		SpecVersionMajor: specVersionMajor,
		SpecErrata:       specErrata,
		VendorInfo:       vendorInfo}
}

func makeEventDataNoAction(pcrIndex PCRIndex, data []byte) EventData {
	var d EventData

	switch pcrIndex {
	case 0:
		d = parseEFISpecIdEvent(data)
		if d != nil {
			return d
		}
		return parsePCClientSpecIdEvent(data)
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

func makeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte) EventData {
	switch eventType {
	case EventTypeNoAction:
		return makeEventDataNoAction(pcrIndex, data)
	case EventTypeSeparator:
		return makeEventDataSeparator(data)
	default:
		return nil
	}
}

func makeEventData(pcrIndex PCRIndex, eventType EventType, data []byte) EventData {
	var e EventData
	if e = makeEventDataImpl(pcrIndex, eventType, data); e == nil {
		e = &eventDataUnclassified{data}
	}
	return e
}
