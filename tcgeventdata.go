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

func wrapSpecIdEventReadError(origErr error) error {
	if origErr == io.EOF {
		return &InvalidSpecIdEventError{"not enough data"}
	}

	return &InvalidSpecIdEventError{origErr.Error()}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func parsePCClientSpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) (bool, error) {
	eventData.Spec = SpecPCClient

	// TCG_PCClientSpecIdEventStruct.reserved
	var reserved uint8
	if err := binary.Read(stream, order, &reserved); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	var nonFatalErr error

	switch {
	case eventData.SpecVersionMinor != 0x02:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMinor value (0x%02x)",
			eventData.SpecVersionMinor)
	case eventData.SpecVersionMajor != 0x01:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMajor value (0x%02x)",
			eventData.SpecVersionMajor)
	case eventData.SpecErrata != 0x01:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specErrata value (0x%02x)",
			eventData.SpecErrata)
	}

	return true, nonFatalErr
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) (bool, error) {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	var nonFatalErr error

	switch {
	case eventData.SpecVersionMinor != 0x02:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMinor value (0x%02x)",
			eventData.SpecVersionMinor)
	case eventData.SpecVersionMajor != 0x01:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMajor value (0x%02x)",
			eventData.SpecVersionMajor)
	case eventData.SpecErrata > 0x02:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specErrata value (0x%02x)",
			eventData.SpecErrata)
	}

	return true, nonFatalErr
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(stream io.Reader, order binary.ByteOrder, eventData *SpecIdEventData) (bool, error) {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, order, &numberOfAlgorithms); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	if numberOfAlgorithms < 1 {
		return false, &InvalidSpecIdEventError{"numberOfAlgorithms is zero"}
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		var algorithmId AlgorithmId
		if err := binary.Read(stream, order, &algorithmId); err != nil {
			return false, wrapSpecIdEventReadError(err)
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		var digestSize uint16
		if err := binary.Read(stream, order, &digestSize); err != nil {
			return false, wrapSpecIdEventReadError(err)
		}

		knownSize, known := knownAlgorithms[algorithmId]
		if known && knownSize != digestSize {
			return false, &InvalidSpecIdEventError{
				fmt.Sprintf("digestSize for algorithmId 0x%04x doesn't match expected size "+
					"(got: %d, expected: %d)", algorithmId, digestSize, knownSize)}
		}
		eventData.DigestSizes[i] = EFISpecIdEventAlgorithmSize{algorithmId, digestSize}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return false, wrapSpecIdEventReadError(err)
	}

	var nonFatalErr error

	switch {
	case eventData.SpecVersionMinor != 0x00:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMinor value (0x%02x)",
			eventData.SpecVersionMinor)
	case eventData.SpecVersionMajor != 0x02:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specVersionMajor value (0x%02x)",
			eventData.SpecVersionMajor)
	case eventData.SpecErrata != 0x00:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.specErrata value (0x%02x)",
			eventData.SpecErrata)
	}

	return true, nonFatalErr
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func makeSpecIdEvent(stream io.Reader, order binary.ByteOrder, data []byte,
	helper func(io.Reader, binary.ByteOrder, *SpecIdEventData) (bool, error)) (*SpecIdEventData, error) {
	// platformClass field
	var platformClass uint32
	if err := binary.Read(stream, order, &platformClass); err != nil {
		return nil, err
	}

	var nonFatalErr error

	switch platformClass {
	case 0x00000000:
	case 0x00000001:
	default:
		nonFatalErr = fmt.Errorf("unexpected SpecIdEvent.platformClass value (0x%08x)", platformClass)
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

	if ok, err := helper(stream, order, eventData); !ok {
		return nil, err
	} else if err != nil {
		nonFatalErr = err
	}

	return eventData, nonFatalErr
}

var (
	validNormalSeparatorValues = [...]uint32{0, math.MaxUint32}
)

type AsciiStringEventData struct {
	data          []byte
	informational bool
}

func (e *AsciiStringEventData) String() string {
	return *(*string)(unsafe.Pointer(&e.data))
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
func makeEventDataNoAction(data []byte, order binary.ByteOrder) (out EventData, n int, err error) {
	stream := bytes.NewReader(data)

	// Signature field
	signature := make([]byte, 16)
	if _, err := io.ReadFull(stream, signature); err != nil {
		return nil, 0, err
	}

	switch *(*string)(unsafe.Pointer(&signature)) {
	case "Spec ID Event00\x00":
		d, e := makeSpecIdEvent(stream, order, data, parsePCClientSpecIdEvent)
		if d != nil {
			out = d
		}
		err = e
	case "Spec ID Event02\x00":
		d, e := makeSpecIdEvent(stream, order, data, parseEFI_1_2_SpecIdEvent)
		if d != nil {
			out = d
		}
		err = e
	case "Spec ID Event03\x00":
		d, e := makeSpecIdEvent(stream, order, data, parseEFI_2_SpecIdEvent)
		if d != nil {
			out = d
		}
		err = e
	default:
		return nil, 0, nil
	}

	n = bytesRead(stream)
	return
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func makeEventDataAction(data []byte) (*AsciiStringEventData, int, error) {
	return &AsciiStringEventData{data: data, informational: false}, len(data), nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.1 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.2 "Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.4.1 "Event Types")
func makeEventDataTCG(eventType EventType, data []byte, order binary.ByteOrder) (out EventData, n int, err error) {
	switch eventType {
	case EventTypeNoAction:
		return makeEventDataNoAction(data, order)
	case EventTypeAction, EventTypeEFIAction:
		return makeEventDataAction(data)
	case EventTypeEFIVariableDriverConfig, EventTypeEFIVariableBoot, EventTypeEFIVariableAuthority:
		return makeEventDataEFIVariable(data, order)
	case EventTypeEFIBootServicesApplication, EventTypeEFIBootServicesDriver,
		EventTypeEFIRuntimeServicesDriver:
		return makeEventDataImageLoad(data, order)
	default:
	}
	return nil, 0, nil
}
