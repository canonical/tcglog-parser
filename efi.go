package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
)

// UEFI_VARIABLE_DATA specifies the number of *characters* for a UTF-16 sequence rather than the size of
// the buffer. Extract a UTF-16 sequence of the correct length, given a buffer and the number of characters.
// The returned buffer can be passed to utf16.Decode.
func extractUTF16Buffer(stream io.ReadSeeker, nchars uint64) ([]uint16, error) {
	var out []uint16

	for i := nchars; i > 0; i-- {
		var c uint16
		if err := binary.Read(stream, binary.LittleEndian, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
		if c >= surr1 && c < surr2 {
			if err := binary.Read(stream, binary.LittleEndian, &c); err != nil {
				return nil, err
			}
			if c < surr2 || c >= surr3 {
				// Invalid surrogate sequence. utf16.Decode doesn't consume this
				// byte when inserting the replacement char
				if _, err := stream.Seek(-1, io.SeekCurrent); err != nil {
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

// EFIGUID corresponds to the EFI_GUID type
type EFIGUID struct {
	A uint32
	B uint16
	C uint16
	D uint16
	E [6]uint8
}

func (g *EFIGUID) String() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}", g.A, g.B, g.C, g.D, g.E)
}

// Encode marshals g to buf in little endian format.
func (g *EFIGUID) Encode(buf io.Writer) error {
	if err := binary.Write(buf, binary.LittleEndian, g.A); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, g.B); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, g.C); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, g.D); err != nil {
		return err
	}
	if _, err := buf.Write(g.E[:]); err != nil {
		return err
	}
	return nil
}

func decodeEFIGUID(stream io.Reader) (*EFIGUID, error) {
	var out EFIGUID
	if err := binary.Read(stream, binary.LittleEndian, &out.A); err != nil {
		return nil, err
	}
	if err := binary.Read(stream, binary.LittleEndian, &out.B); err != nil {
		return nil, err
	}
	if err := binary.Read(stream, binary.LittleEndian, &out.C); err != nil {
		return nil, err
	}
	if err := binary.Read(stream, binary.BigEndian, &out.D); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(stream, out.E[:]); err != nil {
		return nil, err
	}
	return &out, nil
}

func decodeEFIGUIDFromArray(data [16]byte) (*EFIGUID, error) {
	stream := bytes.NewReader(data[:])
	return decodeEFIGUID(stream)
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, binary.LittleEndian, &vendorInfoSize); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, binary.LittleEndian, &numberOfAlgorithms); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	if numberOfAlgorithms < 1 {
		return invalidSpecIdEventError{"numberOfAlgorithms is zero"}
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	if err := binary.Read(stream, binary.LittleEndian, &eventData.DigestSizes); err != nil {
		return wrapSpecIdEventReadError(err)
	}
	for _, d := range eventData.DigestSizes {
		if d.AlgorithmId.supported() && d.AlgorithmId.size() != int(d.DigestSize) {
			return invalidSpecIdEventError{
				fmt.Sprintf("digestSize for algorithmId 0x%04x doesn't match expected size "+
					"(got: %d, expected: %d)", d.AlgorithmId, d.DigestSize, d.AlgorithmId.size())}
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(stream, binary.LittleEndian, &vendorInfoSize); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(stream, eventData.VendorInfo); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	return nil
}

type startupLocalityEventData struct {
	data     []byte
	Locality uint8
}

func (e *startupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent{ StartupLocality: %d }", e.Locality)
}

func (e *startupLocalityEventData) Bytes() []byte {
	return e.data
}

func (e *startupLocalityEventData) Type() NoActionEventType {
	return StartupLocality
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.3 "Startup Locality Event")
func decodeStartupLocalityEvent(stream io.Reader, data []byte) (*startupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(stream, binary.LittleEndian, &locality); err != nil {
		return nil, err
	}

	return &startupLocalityEventData{data: data, Locality: locality}, nil
}

type bimReferenceManifestEventData struct {
	data     []byte
	VendorId uint32
	Guid     EFIGUID
}

func (e *bimReferenceManifestEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event{ VendorId: %d, ReferenceManifestGuid: %s }",
		e.VendorId, &e.Guid)
}

func (e *bimReferenceManifestEventData) Bytes() []byte {
	return e.data
}

func (e *bimReferenceManifestEventData) Type() NoActionEventType {
	return BiosIntegrityMeasurement
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.2 "BIOS Integrity Measurement Reference Manifest Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func decodeBIMReferenceManifestEvent(stream io.Reader, data []byte) (*bimReferenceManifestEventData, error) {
	var vendorId uint32
	if err := binary.Read(stream, binary.LittleEndian, &vendorId); err != nil {
		return nil, err
	}

	guid, err := decodeEFIGUID(stream)
	if err != nil {
		return nil, err
	}

	return &bimReferenceManifestEventData{data: data, VendorId: vendorId, Guid: *guid}, nil
}

// EFIVariableEventData corresponds to the EFI_VARIABLE_DATA type.
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

func (e *EFIVariableEventData) Bytes() []byte {
	return e.data
}

func (e *EFIVariableEventData) EncodeMeasuredBytes(buf io.Writer) error {
	if err := e.VariableName.Encode(buf); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint64(utf8.RuneCount([]byte(e.UnicodeName)))); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint64(len(e.VariableData))); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, convertStringToUtf16(e.UnicodeName)); err != nil {
		return err
	}
	if _, err := buf.Write(e.VariableData); err != nil {
		return err
	}
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func decodeEventDataEFIVariableImpl(data []byte, eventType EventType) (*EFIVariableEventData, int, error) {
	stream := bytes.NewReader(data)

	guid, err := decodeEFIGUID(stream)
	if err != nil {
		return nil, 0, err
	}

	var unicodeNameLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &unicodeNameLength); err != nil {
		return nil, 0, err
	}

	var variableDataLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &variableDataLength); err != nil {
		return nil, 0, err
	}

	utf16Name, err := extractUTF16Buffer(stream, unicodeNameLength)
	if err != nil {
		return nil, 0, err
	}

	variableData := make([]byte, variableDataLength)
	if _, err := io.ReadFull(stream, variableData); err != nil {
		return nil, 0, err
	}

	return &EFIVariableEventData{data: data,
		VariableName: *guid,
		UnicodeName:  convertUtf16ToString(utf16Name),
		VariableData: variableData}, stream.Len(), nil
}

func decodeEventDataEFIVariable(data []byte, eventType EventType) (out EventData, trailingBytes int, err error) {
	d, trailingBytes, err := decodeEventDataEFIVariableImpl(data, eventType)
	if d != nil {
		out = d
	}
	return
}

type efiDevicePathNodeType uint8

func (t efiDevicePathNodeType) String() string {
	switch t {
	case efiDevicePathNodeHardware:
		return "HardwarePath"
	case efiDevicePathNodeACPI:
		return "AcpiPath"
	case efiDevicePathNodeMsg:
		return "Msg"
	case efiDevicePathNodeMedia:
		return "MediaPath"
	case efiDevicePathNodeBBS:
		return "BbsPath"
	default:
		return fmt.Sprintf("Path[%02x]", uint8(t))
	}
}

const (
	efiDevicePathNodeHardware efiDevicePathNodeType = 0x01
	efiDevicePathNodeACPI                           = 0x02
	efiDevicePathNodeMsg                            = 0x03
	efiDevicePathNodeMedia                          = 0x04
	efiDevicePathNodeBBS                            = 0x05
	efiDevicePathNodeEoH                            = 0x7f
)

const (
	efiHardwareDevicePathNodePCI = 0x01

	efiACPIDevicePathNodeNormal = 0x01

	efiMsgDevicePathNodeLU   = 0x11
	efiMsgDevicePathNodeSATA = 0x12

	efiMediaDevicePathNodeHardDrive      = 0x01
	efiMediaDevicePathNodeFilePath       = 0x04
	efiMediaDevicePathNodeFvFile         = 0x06
	efiMediaDevicePathNodeFv             = 0x07
	efiMediaDevicePathNodeRelOffsetRange = 0x08
)

func firmwareDevicePathNodeToString(subType uint8, data []byte) (string, error) {
	stream := bytes.NewReader(data)

	name, err := decodeEFIGUID(stream)
	if err != nil {
		return "", err
	}

	var builder bytes.Buffer
	switch subType {
	case efiMediaDevicePathNodeFvFile:
		builder.WriteString("\\FvFile")
	case efiMediaDevicePathNodeFv:
		builder.WriteString("\\Fv")
	default:
		return "", fmt.Errorf("invalid sub type for firmware device path node: %d", subType)
	}

	fmt.Fprintf(&builder, "(%s)", name)
	return builder.String(), nil
}

func acpiDevicePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	var hid uint32
	if err := binary.Read(stream, binary.LittleEndian, &hid); err != nil {
		return "", err
	}

	var uid uint32
	if err := binary.Read(stream, binary.LittleEndian, &uid); err != nil {
		return "", err
	}

	if hid&0xffff == 0x41d0 {
		switch hid >> 16 {
		case 0x0a03:
			return fmt.Sprintf("\\PciRoot(0x%x)", uid), nil
		case 0x0a08:
			return fmt.Sprintf("\\PcieRoot(0x%x)", uid), nil
		case 0x0604:
			return fmt.Sprintf("\\Floppy(0x%x)", uid), nil
		default:
			return fmt.Sprintf("\\Acpi(PNP%04x,0x%x)", hid>>16, uid), nil
		}
	} else {
		return fmt.Sprintf("\\Acpi(0x%08x,0x%x)", hid, uid), nil
	}
}

func pciDevicePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	var function uint8
	if err := binary.Read(stream, binary.LittleEndian, &function); err != nil {
		return "", err
	}

	var device uint8
	if err := binary.Read(stream, binary.LittleEndian, &device); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Pci(0x%x,0x%x)", device, function), nil
}

func luDevicePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	var lun uint8
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Unit(0x%x)", lun), nil
}

func hardDriveDevicePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	var partNumber uint32
	if err := binary.Read(stream, binary.LittleEndian, &partNumber); err != nil {
		return "", err
	}

	var partStart uint64
	if err := binary.Read(stream, binary.LittleEndian, &partStart); err != nil {
		return "", err
	}

	var partSize uint64
	if err := binary.Read(stream, binary.LittleEndian, &partSize); err != nil {
		return "", err
	}

	var sig [16]byte
	if _, err := io.ReadFull(stream, sig[:]); err != nil {
		return "", err
	}

	var partFormat uint8
	if err := binary.Read(stream, binary.LittleEndian, &partFormat); err != nil {
		return "", err
	}

	var sigType uint8
	if err := binary.Read(stream, binary.LittleEndian, &sigType); err != nil {
		return "", err
	}

	var builder bytes.Buffer

	switch sigType {
	case 0x01:
		fmt.Fprintf(&builder, "\\HD(%d,MBR,0x%08x,", partNumber, binary.LittleEndian.Uint32(sig[:]))
	case 0x02:
		guid, err := decodeEFIGUIDFromArray(sig)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&builder, "\\HD(%d,GPT,%s,", partNumber, guid)
	default:
		fmt.Fprintf(&builder, "\\HD(%d,%d,0,", partNumber, sigType)
	}

	fmt.Fprintf(&builder, "0x%016x, 0x%016x)", partStart, partSize)
	return builder.String(), nil
}

func sataDevicePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	var hbaPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &hbaPortNumber); err != nil {
		return "", err
	}

	var portMultiplierPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &portMultiplierPortNumber); err != nil {
		return "", err
	}

	var lun uint16
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Sata(0x%x,0x%x,0x%x)", hbaPortNumber, portMultiplierPortNumber, lun), nil
}

func filePathDevicePathNodeToString(data []byte) string {
	u16 := make([]uint16, len(data)/2)
	stream := bytes.NewReader(data)
	binary.Read(stream, binary.LittleEndian, &u16)

	var buf bytes.Buffer
	for _, r := range utf16.Decode(u16) {
		buf.WriteRune(r)
	}
	return buf.String()
}

func relOffsetRangePathNodeToString(data []byte) (string, error) {
	stream := bytes.NewReader(data)

	if _, err := stream.Seek(4, io.SeekCurrent); err != nil {
		return "", err
	}

	var start uint64
	if err := binary.Read(stream, binary.LittleEndian, &start); err != nil {
		return "", err
	}

	var end uint64
	if err := binary.Read(stream, binary.LittleEndian, &end); err != nil {
		return "", err
	}

	return fmt.Sprintf("\\Offset(0x%x,0x%x)", start, end), nil
}

func decodeDevicePathNode(stream io.Reader) (string, error) {
	var t efiDevicePathNodeType
	if err := binary.Read(stream, binary.LittleEndian, &t); err != nil {
		return "", err
	}

	if t == efiDevicePathNodeEoH {
		return "", nil
	}

	var subType uint8
	if err := binary.Read(stream, binary.LittleEndian, &subType); err != nil {
		return "", err
	}

	var length uint16
	if err := binary.Read(stream, binary.LittleEndian, &length); err != nil {
		return "", err
	}

	if length < 4 {
		return "", fmt.Errorf("unexpected device path node length (got %d, expected >= 4)", length)
	}

	data := make([]byte, length-4)
	if _, err := io.ReadFull(stream, data); err != nil {
		return "", err
	}

	switch t {
	case efiDevicePathNodeMedia:
		switch subType {
		case efiMediaDevicePathNodeFvFile:
			fallthrough
		case efiMediaDevicePathNodeFv:
			return firmwareDevicePathNodeToString(subType, data)
		case efiMediaDevicePathNodeHardDrive:
			return hardDriveDevicePathNodeToString(data)
		case efiMediaDevicePathNodeFilePath:
			return filePathDevicePathNodeToString(data), nil
		case efiMediaDevicePathNodeRelOffsetRange:
			return relOffsetRangePathNodeToString(data)
		}
	case efiDevicePathNodeACPI:
		switch subType {
		case efiACPIDevicePathNodeNormal:
			return acpiDevicePathNodeToString(data)
		}
	case efiDevicePathNodeHardware:
		switch subType {
		case efiHardwareDevicePathNodePCI:
			return pciDevicePathNodeToString(data)
		}
	case efiDevicePathNodeMsg:
		switch subType {
		case efiMsgDevicePathNodeLU:
			return luDevicePathNodeToString(data)
		case efiMsgDevicePathNodeSATA:
			return sataDevicePathNodeToString(data)
		}

	}

	var builder bytes.Buffer
	fmt.Fprintf(&builder, "\\%s(%d", t, subType)
	if len(data) > 0 {
		fmt.Fprintf(&builder, ", 0x")
		for _, b := range data {
			fmt.Fprintf(&builder, "%02x", b)
		}
	}
	fmt.Fprintf(&builder, ")")
	return builder.String(), nil
}

func decodeDevicePath(data []byte) (string, error) {
	stream := bytes.NewReader(data)
	var builder bytes.Buffer

	for {
		node, err := decodeDevicePathNode(stream)
		if err != nil {
			return "", err
		}
		if node == "" {
			return builder.String(), nil
		}
		fmt.Fprintf(&builder, "%s", node)
	}
}

type efiImageLoadEventData struct {
	data             []byte
	locationInMemory uint64
	lengthInMemory   uint64
	linkTimeAddress  uint64
	path             string
}

func (e *efiImageLoadEventData) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.locationInMemory, e.lengthInMemory,
		e.linkTimeAddress, e.path)
}

func (e *efiImageLoadEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 4 "Measuring PE/COFF Image Files")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.3 "UEFI_IMAGE_LOAD_EVENT Structure")
func decodeEventDataEFIImageLoadImpl(data []byte) (*efiImageLoadEventData, error) {
	stream := bytes.NewReader(data)

	var locationInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &locationInMemory); err != nil {
		return nil, err
	}

	var lengthInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &lengthInMemory); err != nil {
		return nil, err
	}

	var linkTimeAddress uint64
	if err := binary.Read(stream, binary.LittleEndian, &linkTimeAddress); err != nil {
		return nil, err
	}

	var devicePathLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &devicePathLength); err != nil {
		return nil, err
	}

	devicePathBuf := make([]byte, devicePathLength)

	if _, err := io.ReadFull(stream, devicePathBuf); err != nil {
		return nil, err
	}

	path, err := decodeDevicePath(devicePathBuf)
	if err != nil {
		return nil, err
	}

	return &efiImageLoadEventData{data: data,
		locationInMemory: locationInMemory,
		lengthInMemory:   lengthInMemory,
		linkTimeAddress:  linkTimeAddress,
		path:             path}, nil
}

func decodeEventDataEFIImageLoad(data []byte) (out EventData, trailingBytes int, err error) {
	d, err := decodeEventDataEFIImageLoadImpl(data)
	if d != nil {
		out = d
	}
	return
}

type efiGPTPartitionEntry struct {
	typeGUID   EFIGUID
	uniqueGUID EFIGUID
	name       string
}

func (p *efiGPTPartitionEntry) String() string {
	return fmt.Sprintf("PartitionTypeGUID: %s, UniquePartitionGUID: %s, Name: \"%s\"",
		&p.typeGUID, &p.uniqueGUID, p.name)
}

type efiGPTEventData struct {
	data       []byte
	diskGUID   EFIGUID
	partitions []efiGPTPartitionEntry
}

func (e *efiGPTEventData) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{ DiskGUID: %s, Partitions: [", &e.diskGUID)
	for i, part := range e.partitions {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{ %s }", &part)
	}
	fmt.Fprintf(&builder, "] }")
	return builder.String()
}

func (e *efiGPTEventData) Bytes() []byte {
	return e.data
}

func decodeEventDataEFIGPTImpl(data []byte) (*efiGPTEventData, int, error) {
	stream := bytes.NewReader(data)

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.{Header, MyLBA, AlternateLBA, FirstUsableLBA, LastUsableLBA}
	if _, err := stream.Seek(56, io.SeekCurrent); err != nil {
		return nil, 0, err
	}

	// UEFI_GPT_DATA.UEFIPartitionHeader.DiskGUID
	diskGUID, err := decodeEFIGUID(stream)
	if err != nil {
		return nil, 0, err
	}

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.{PartitionEntryLBA, NumberOfPartitionEntries}
	if _, err := stream.Seek(12, io.SeekCurrent); err != nil {
		return nil, 0, err
	}

	// UEFI_GPT_DATA.UEFIPartitionHeader.SizeOfPartitionEntry
	var partEntrySize uint32
	if err := binary.Read(stream, binary.LittleEndian, &partEntrySize); err != nil {
		return nil, 0, err
	}

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.PartitionEntryArrayCRC32
	if _, err := stream.Seek(4, io.SeekCurrent); err != nil {
		return nil, 0, err
	}

	// UEFI_GPT_DATA.NumberOfPartitions
	var numberOfParts uint64
	if err := binary.Read(stream, binary.LittleEndian, &numberOfParts); err != nil {
		return nil, 0, err
	}

	eventData := &efiGPTEventData{diskGUID: *diskGUID, partitions: make([]efiGPTPartitionEntry, numberOfParts)}

	for i := uint64(0); i < numberOfParts; i++ {
		entryData := make([]byte, partEntrySize)
		if _, err := io.ReadFull(stream, entryData); err != nil {
			return nil, 0, err
		}

		entryStream := bytes.NewReader(entryData)

		typeGUID, err := decodeEFIGUID(entryStream)
		if err != nil {
			return nil, 0, err
		}

		uniqueGUID, err := decodeEFIGUID(entryStream)
		if err != nil {
			return nil, 0, err
		}

		// Skip UEFI_GPT_DATA.Partitions[i].{StartingLBA, EndingLBA, Attributes}
		if _, err := entryStream.Seek(24, io.SeekCurrent); err != nil {
			return nil, 0, err
		}

		nameUtf16 := make([]uint16, entryStream.Len()/2)
		if err := binary.Read(entryStream, binary.LittleEndian, &nameUtf16); err != nil {
			return nil, 0, err
		}

		var name bytes.Buffer
		for _, r := range utf16.Decode(nameUtf16) {
			if r == rune(0) {
				break
			}
			name.WriteRune(r)
		}

		eventData.partitions[i] =
			efiGPTPartitionEntry{typeGUID: *typeGUID, uniqueGUID: *uniqueGUID, name: name.String()}
	}

	return eventData, stream.Len(), nil
}

func decodeEventDataEFIGPT(data []byte) (out EventData, trailingBytes int, err error) {
	d, trailingBytes, err := decodeEventDataEFIGPTImpl(data)
	if d != nil {
		out = d
	}
	return
}
