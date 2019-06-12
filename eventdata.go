package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

type SeparatorEventType uint32

type EventData interface {
	String() string
	RawBytes() []byte
	MeasuredBytes() []byte
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
	fmt.Fprintf(&builder, "SpecIdEvent{ spec=%d, platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, "+
		"specErrata=%d", e.Spec, e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
	if e.Spec == SpecEFI_2 {
		fmt.Fprintf(&builder, ", digestSizes=[")
		for i, algSize := range e.DigestSizes {
			if i > 0 {
				fmt.Fprintf(&builder, ", ")
			}
			fmt.Fprintf(&builder, "{ algorithmId=%04x, digestSize=%d }",
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
func parsePCClientSpecIdEvent(stream io.Reader, eventData *SpecIdEventData, order binary.ByteOrder) EventData {
	eventData.Spec = SpecPCClient

	// TCG_PCClientSpecIdEventStruct.reserved
	var reserved uint8
	if err := binary.Read(stream, order, &reserved); err != nil {
		return nil
	}

	// TCG_PCClientSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
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
func parseEFI_1_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData, order binary.ByteOrder) EventData {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
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
func parseEFI_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData, order binary.ByteOrder) EventData {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.uintnSize
	if err := binary.Read(stream, order, &eventData.uintnSize); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, order, &numberOfAlgorithms); err != nil {
		return nil
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		if err := binary.Read(stream, order, &eventData.DigestSizes[i].AlgorithmId); err != nil {
			return nil
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		if err := binary.Read(stream, order, &eventData.DigestSizes[i].DigestSize); err != nil {
			return nil
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, order, &vendorInfoSize); err != nil {
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
func parseSpecIdEvent(data []byte, order binary.ByteOrder) EventData {
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
	if err := binary.Read(stream, order, &platformClass); err != nil {
		return nil
	}

	// specVersionMinor field
	var specVersionMinor uint8
	if err := binary.Read(stream, order, &specVersionMinor); err != nil {
		return nil
	}

	// specVersionMajor field
	var specVersionMajor uint8
	if err := binary.Read(stream, order, &specVersionMajor); err != nil {
		return nil
	}

	// specErrata field
	var specErrata uint8
	if err := binary.Read(stream, order, &specErrata); err != nil {
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
		return parsePCClientSpecIdEvent(stream, eventData, order)
	case "Spec ID Event02\x00":
		return parseEFI_1_2_SpecIdEvent(stream, eventData, order)
	case "Spec ID Event03\x00":
		return parseEFI_2_SpecIdEvent(stream, eventData, order)
	default:
		return nil
	}
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
func makeEventDataSeparator(data []byte, order binary.ByteOrder) EventData {
	if len(data) != 4 {
		return nil
	}

	v := order.Uint32(data)

	t := SeparatorEventTypeError
	for _, w := range validNormalSeparatorValues {
		if v == w {
			t = SeparatorEventTypeNormal
			break
		}
	}

	return &SeparatorEventData{data, t}
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

type opaqueEventData struct {
	data          []byte
	informational bool
}

func (e *opaqueEventData) String() string {
	return ""
}

func (e *opaqueEventData) RawBytes() []byte {
	return e.data
}

func (e *opaqueEventData) MeasuredBytes() []byte {
	if !e.informational {
		return e.data
	}
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4 "EV_NO_ACTION Event Types")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5 "EV_NO_ACTION Event Types")
func makeEventDataNoAction(pcrIndex PCRIndex, data []byte, order binary.ByteOrder) EventData {
	switch pcrIndex {
	case 0:
		return parseSpecIdEvent(data, order)
	default:
		return nil
	}
}

var (
	kernelCmdlinePrefix = "kernel_cmdline: "
	grubCmdPrefix       = "grub_cmd: "
)

type KernelCmdlineEventData struct {
	data    []byte
	Cmdline string
}

func (e *KernelCmdlineEventData) String() string {
	return fmt.Sprintf("kernel_cmdline{ %s }", e.Cmdline)
}

func (e *KernelCmdlineEventData) RawBytes() []byte {
	return e.data
}

func (e *KernelCmdlineEventData) MeasuredBytes() []byte {
	r := strings.NewReader(e.Cmdline)
	b := make([]byte, r.Len())
	r.Read(b)
	return b
}

type GrubCmdEventData struct {
	data []byte
	Cmd  string
}

func (e *GrubCmdEventData) String() string {
	return fmt.Sprintf("grub_cmd{ %s }", e.Cmd)
}

func (e *GrubCmdEventData) RawBytes() []byte {
	return e.data
}

func (e *GrubCmdEventData) MeasuredBytes() []byte {
	r := strings.NewReader(e.Cmd)
	b := make([]byte, r.Len())
	r.Read(b)
	return b
}

func makeEventDataIPL(pcrIndex PCRIndex, data []byte) EventData {
	switch pcrIndex {
	case 8:
		var builder strings.Builder
		builder.Write(data)
		str := builder.String()

		switch {
		case strings.Index(str, kernelCmdlinePrefix) == 0:
			str = strings.TrimPrefix(str, kernelCmdlinePrefix)
			str = strings.TrimSuffix(str, "\x00")
			return &KernelCmdlineEventData{data, str}
		case strings.Index(str, grubCmdPrefix) == 0:
			str = strings.TrimPrefix(str, grubCmdPrefix)
			str = strings.TrimSuffix(str, "\x00")
			return &GrubCmdEventData{data, str}
		default:
			return nil
		}
	case 9:
		return &AsciiStringEventData{data: data, informational: true}
	default:
		return nil
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.3 "EV_ACTION event types")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.4.3 "EV_ACTION Event Types")
func makeEventDataAction(data []byte) EventData {
	return &AsciiStringEventData{data: data, informational: false}
}

type EFIGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func (g *EFIGUID) String() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}", g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:8])
}

func readEFIGUID(stream io.Reader, guid *EFIGUID, order binary.ByteOrder) error {
	if err := binary.Read(stream, order, &guid.Data1); err != nil {
		return err
	}
	if err := binary.Read(stream, order, &guid.Data2); err != nil {
		return err
	}
	if err := binary.Read(stream, order, &guid.Data3); err != nil {
		return err
	}
	if _, err := io.ReadFull(stream, guid.Data4[:]); err != nil {
		return err
	}
	return nil
}

type EFIVariableEventData struct {
	data         []byte
	VariableName EFIGUID
	UnicodeName  string
	VariableData []byte
}

func (e *EFIVariableEventData) String() string {
	return fmt.Sprintf("UEFI_VARIABLE_DATA{ VariableName: %s, UnicodeName: \"%s\" }",
		e.VariableName.String(), e.UnicodeName)
}

func (e *EFIVariableEventData) RawBytes() []byte {
	return e.data
}

func (e *EFIVariableEventData) MeasuredBytes() []byte {
	return e.data
}

func makeEFIVariableEventData(data []byte, order binary.ByteOrder) EventData {
	stream := bytes.NewReader(data)

	var guid EFIGUID
	if err := readEFIGUID(stream, &guid, order); err != nil {
		return nil
	}

	var unicodeNameLength uint64
	if err := binary.Read(stream, order, &unicodeNameLength); err != nil {
		return nil
	}

	var variableDataLength uint64
	if err := binary.Read(stream, order, &variableDataLength); err != nil {
		return nil
	}

	unicodeName, err := decodeUTF16ToString(stream, unicodeNameLength, order)
	if err != nil {
		return nil
	}

	variableData := make([]byte, variableDataLength)
	if _, err := io.ReadFull(stream, variableData); err != nil {
		return nil
	}

	return &EFIVariableEventData{data: data,
		VariableName: guid,
		UnicodeName:  unicodeName,
		VariableData: variableData}
}

func makeEventDataEFIVariableDriverConfig(data []byte, order binary.ByteOrder) EventData {
	return makeEFIVariableEventData(data, order)
}

func makeEventDataEFIVariableBoot(data []byte, order binary.ByteOrder) EventData {
	return makeEFIVariableEventData(data, order)
}

func makeEventDataEFIVariableAuthority(data []byte, order binary.ByteOrder) EventData {
	return makeEFIVariableEventData(data, order)
}

func makeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte, order binary.ByteOrder) EventData {
	switch eventType {
	case EventTypeNoAction:
		return makeEventDataNoAction(pcrIndex, data, order)
	case EventTypeSeparator:
		return makeEventDataSeparator(data, order)
	case EventTypeAction:
		return makeEventDataAction(data)
	case EventTypeIPL:
		return makeEventDataIPL(pcrIndex, data)
	case EventTypeEFIVariableDriverConfig:
		return makeEventDataEFIVariableDriverConfig(data, order)
	case EventTypeEFIVariableBoot:
		return makeEventDataEFIVariableBoot(data, order)
	case EventTypeEFIAction:
		return makeEventDataAction(data)
	case EventTypeEFIVariableAuthority:
		return makeEventDataEFIVariableAuthority(data, order)
	default:
		return nil
	}
}

func makeOpaqueEventData(eventType EventType, data []byte) EventData {
	switch eventType {
	case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags, EventTypeTableOfDevices,
		EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents, EventTypeEFIGPTEvent:
		return &opaqueEventData{data: data, informational: false}
	default:
		return &opaqueEventData{data: data, informational: true}
	}
}

func makeEventData(pcrIndex PCRIndex, eventType EventType, data []byte, order binary.ByteOrder) EventData {
	if event := makeEventDataImpl(pcrIndex, eventType, data, order); event != nil {
		return event
	}
	return makeOpaqueEventData(eventType, data)
}
