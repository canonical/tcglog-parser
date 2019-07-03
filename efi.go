package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
	surr4 rune   = 0x10000
)

// UEFI_VARIABLE_DATA specifies the number of *characters* for a UTF-16 rather than the size of
// the buffer, which makes it difficult for us to use go's utf16 module (which will decode the whole
// buffer. We need to know the size of the buffer so we can calculate the slice to pass it, but we
// need to decode it first)
// This will decode the specified number of characters or until a null character is found
func decodeUTF16ToString(stream io.Reader, count uint64) (string, error) {
	var builder strings.Builder

	for i := uint64(0); i < count; i++ {
		var c1 uint16
		if err := binary.Read(stream, binary.LittleEndian, &c1); err != nil {
			return "", err
		}
		if c1 == 0x0000 {
			break
		}
		if c1 < surr1 || c1 >= surr3 {
			builder.WriteRune(rune(c1))
			continue
		}
		if c1 >= surr1 && c1 < surr2 {
			var c2 uint16
			if err := binary.Read(stream, binary.LittleEndian, &c2); err != nil {
				return "", err
			}
			if c2 >= surr2 && c2 < surr3 {
				builder.WriteRune(rune((c1-surr1)<<10|(c2-surr2)) + surr4)
				i++
				continue
			}
		}
		builder.WriteRune(rune(0xfffd))
	}

	return builder.String(), nil
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

func readEFIGUID(stream io.Reader, out *EFIGUID) error {
	if err := binary.Read(stream, binary.LittleEndian, &out.Data1); err != nil {
		return err
	}
	if err := binary.Read(stream, binary.LittleEndian, &out.Data2); err != nil {
		return err
	}
	if err := binary.Read(stream, binary.LittleEndian, &out.Data3); err != nil {
		return err
	}
	if _, err := io.ReadFull(stream, out.Data4[:]); err != nil {
		return err
	}
	return nil
}

func makeEFIGUID(data [16]byte) *EFIGUID {
	stream := bytes.NewReader(data[:])

	var out EFIGUID
	if err := readEFIGUID(stream, &out); err != nil {
		return nil
	}

	return &out
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(stream io.Reader, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.uintnSize
	if err := binary.Read(stream, binary.LittleEndian, &eventData.uintnSize); err != nil {
		return wrapSpecIdEventReadError(err)
	}

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

	// TCG_EfiSpecIdEvent.uintnSize
	if err := binary.Read(stream, binary.LittleEndian, &eventData.uintnSize); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(stream, binary.LittleEndian, &numberOfAlgorithms); err != nil {
		return wrapSpecIdEventReadError(err)
	}

	if numberOfAlgorithms < 1 {
		return &InvalidSpecIdEventError{"numberOfAlgorithms is zero"}
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	for i := uint32(0); i < numberOfAlgorithms; i++ {
		// TCG_EfiSpecIdEvent.digestSizes[i].algorithmId
		var algorithmId AlgorithmId
		if err := binary.Read(stream, binary.LittleEndian, &algorithmId); err != nil {
			return wrapSpecIdEventReadError(err)
		}

		// TCG_EfiSpecIdEvent.digestSizes[i].digestSize
		var digestSize uint16
		if err := binary.Read(stream, binary.LittleEndian, &digestSize); err != nil {
			return wrapSpecIdEventReadError(err)
		}

		knownSize, known := knownAlgorithms[algorithmId]
		if known && knownSize != digestSize {
			return &InvalidSpecIdEventError{
				fmt.Sprintf("digestSize for algorithmId 0x%04x doesn't match expected size "+
					"(got: %d, expected: %d)", algorithmId, digestSize, knownSize)}
		}
		eventData.DigestSizes[i] = EFISpecIdEventAlgorithmSize{algorithmId, digestSize}
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

type StartupLocalityEventData struct {
	data     []byte
	Locality uint8
}

func (e *StartupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent{ StartupLocality: %d }", e.Locality)
}

func (e *StartupLocalityEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.3 "Startup Locality Event")
func makeStartupLocalityEvent(stream io.Reader, data []byte) (*StartupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(stream, binary.LittleEndian, &locality); err != nil {
		return nil, err
	}

	return &StartupLocalityEventData{data: data, Locality: locality}, nil
}

type BIMReferenceManifestEventData struct {
	data     []byte
	VendorId uint32
	Guid     EFIGUID
}

func (e *BIMReferenceManifestEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event{ VendorId: %d, ReferenceManifestGuid: %s }",
		e.VendorId, &e.Guid)
}

func (e *BIMReferenceManifestEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.2 "BIOS Integrity Measurement Reference Manifest Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func makeBIMReferenceManifestEvent(stream io.Reader, data []byte) (*BIMReferenceManifestEventData, error) {
	var vendorId uint32
	if err := binary.Read(stream, binary.LittleEndian, &vendorId); err != nil {
		return nil, err
	}

	var guid EFIGUID
	if err := readEFIGUID(stream, &guid); err != nil {
		return nil, err
	}

	return &BIMReferenceManifestEventData{data: data, VendorId: vendorId, Guid: guid}, nil
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

func (e *EFIVariableEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func makeEventDataEFIVariableImpl(data []byte, eventType EventType) (*EFIVariableEventData, int, error) {
	stream := bytes.NewReader(data)

	var guid EFIGUID
	if err := readEFIGUID(stream, &guid); err != nil {
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

	unicodeName, err := decodeUTF16ToString(stream, unicodeNameLength)
	if err != nil {
		return nil, 0, err
	}

	variableData := make([]byte, variableDataLength)
	if _, err := io.ReadFull(stream, variableData); err != nil {
		return nil, 0, err
	}

	return &EFIVariableEventData{data: data,
		VariableName: guid,
		UnicodeName:  unicodeName,
		VariableData: variableData}, bytesRead(stream), nil
}

func makeEventDataEFIVariable(data []byte, eventType EventType) (out EventData, n int, err error) {
	d, n, err := makeEventDataEFIVariableImpl(data, eventType)
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

type efiDevicePathNode struct {
	t       efiDevicePathNodeType
	subType uint8
	data    []byte
	next    *efiDevicePathNode
}

func firmwareDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var name EFIGUID
	if err := readEFIGUID(stream, &name); err != nil {
		return ""
	}

	var builder strings.Builder
	switch n.subType {
	case efiMediaDevicePathNodeFvFile:
		builder.WriteString("FvFile")
	case efiMediaDevicePathNodeFv:
		builder.WriteString("Fv")
	default:
		return ""
	}

	fmt.Fprintf(&builder, "(%s)", &name)
	return builder.String()
}

func acpiDevicePathNodeToString(n *efiDevicePathNode) string {
	if n.subType != efiACPIDevicePathNodeNormal {
		// No support for the extended path node
		return ""
	}

	stream := bytes.NewReader(n.data)

	var hid uint32
	if err := binary.Read(stream, binary.LittleEndian, &hid); err != nil {
		return ""
	}

	var uid uint32
	if err := binary.Read(stream, binary.LittleEndian, &uid); err != nil {
		return ""
	}

	if hid&0xffff == 0x41d0 {
		switch hid >> 16 {
		case 0x0a03:
			return fmt.Sprintf("PciRoot(0x%x)", uid)
		case 0x0a08:
			return fmt.Sprintf("PcieRoot(0x%x)", uid)
		case 0x0604:
			return fmt.Sprintf("Floppy(0x%x)", uid)
		default:
			return fmt.Sprintf("Acpi(PNP%04x,0x%x)", hid>>16, uid)
		}
	} else {
		return fmt.Sprintf("Acpi(0x%08x,0x%x)", hid, uid)
	}
}

func pciDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var function uint8
	if err := binary.Read(stream, binary.LittleEndian, &function); err != nil {
		return ""
	}

	var device uint8
	if err := binary.Read(stream, binary.LittleEndian, &device); err != nil {
		return ""
	}

	return fmt.Sprintf("Pci(0x%x,0x%x)", device, function)
}

func luDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var lun uint8
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return ""
	}

	return fmt.Sprintf("Unit(0x%x)", lun)
}

func hardDriveDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var partNumber uint32
	if err := binary.Read(stream, binary.LittleEndian, &partNumber); err != nil {
		return ""
	}

	var partStart uint64
	if err := binary.Read(stream, binary.LittleEndian, &partStart); err != nil {
		return ""
	}

	var partSize uint64
	if err := binary.Read(stream, binary.LittleEndian, &partSize); err != nil {
		return ""
	}

	var sig [16]byte
	if _, err := io.ReadFull(stream, sig[:]); err != nil {
		return ""
	}

	var partFormat uint8
	if err := binary.Read(stream, binary.LittleEndian, &partFormat); err != nil {
		return ""
	}

	var sigType uint8
	if err := binary.Read(stream, binary.LittleEndian, &sigType); err != nil {
		return ""
	}

	var builder strings.Builder

	switch sigType {
	case 0x01:
		fmt.Fprintf(&builder, "HD(%d,MBR,0x%08x,", partNumber, binary.LittleEndian.Uint32(sig[:]))
	case 0x02:
		fmt.Fprintf(&builder, "HD(%d,GPT,%s,", partNumber, makeEFIGUID(sig))
	default:
		fmt.Fprintf(&builder, "HD(%d,%d,0,", partNumber, sigType)
	}

	fmt.Fprintf(&builder, "0x%016x, 0x%016x)", partStart, partSize)
	return builder.String()
}

func sataDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var hbaPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &hbaPortNumber); err != nil {
		return ""
	}

	var portMultiplierPortNumber uint16
	if err := binary.Read(stream, binary.LittleEndian, &portMultiplierPortNumber); err != nil {
		return ""
	}

	var lun uint16
	if err := binary.Read(stream, binary.LittleEndian, &lun); err != nil {
		return ""
	}

	return fmt.Sprintf("Sata(0x%x,0x%x,0x%x)", hbaPortNumber, portMultiplierPortNumber, lun)
}

func filePathDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	s, err := decodeUTF16ToString(stream, uint64(len(n.data)))
	if err != nil {
		return ""
	}
	return s
}

func relOffsetRangePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	if _, err := stream.Seek(4, io.SeekCurrent); err != nil {
		return ""
	}

	var start uint64
	if err := binary.Read(stream, binary.LittleEndian, &start); err != nil {
		return ""
	}

	var end uint64
	if err := binary.Read(stream, binary.LittleEndian, &end); err != nil {
		return ""
	}

	return fmt.Sprintf("Offset(0x%x,0x%x)", start, end)
}

func (n *efiDevicePathNode) toString() string {
	switch {
	case n.t == efiDevicePathNodeMedia &&
		(n.subType == efiMediaDevicePathNodeFvFile || n.subType == efiMediaDevicePathNodeFv):
		return firmwareDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeMedia && n.subType == efiMediaDevicePathNodeHardDrive:
		return hardDriveDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeMedia && n.subType == efiMediaDevicePathNodeFilePath:
		return filePathDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeACPI:
		return acpiDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeHardware && n.subType == efiHardwareDevicePathNodePCI:
		return pciDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeMsg && n.subType == efiMsgDevicePathNodeLU:
		return luDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeMsg && n.subType == efiMsgDevicePathNodeSATA:
		return sataDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeMedia && n.subType == efiMediaDevicePathNodeRelOffsetRange:
		return relOffsetRangePathNodeToString(n)
	default:
		return ""
	}
}

func (n *efiDevicePathNode) String() string {
	if s := n.toString(); s != "" {
		return s
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s(%d", n.t, n.subType)
	if len(n.data) > 0 {
		fmt.Fprintf(&builder, ", 0x")
		for _, b := range n.data {
			fmt.Fprintf(&builder, "%02x", b)
		}
	}
	fmt.Fprintf(&builder, ")")
	return builder.String()
}

func readDevicePathNode(stream io.Reader) *efiDevicePathNode {
	var t efiDevicePathNodeType
	if err := binary.Read(stream, binary.LittleEndian, &t); err != nil {
		return nil
	}

	var subType uint8
	if err := binary.Read(stream, binary.LittleEndian, &subType); err != nil {
		return nil
	}

	var length uint16
	if err := binary.Read(stream, binary.LittleEndian, &length); err != nil {
		return nil
	}

	if length < 4 {
		return nil
	}

	data := make([]byte, length-4)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil
	}

	return &efiDevicePathNode{t: t, subType: subType, data: data}
}

type EFIDevicePath struct {
	root *efiDevicePathNode
}

func (p *EFIDevicePath) String() string {
	var builder strings.Builder
	for node := p.root; node != nil; node = node.next {
		if node != p.root {
			builder.WriteString("/")
		}
		fmt.Fprintf(&builder, "%s", node)
	}
	return builder.String()
}

func readDevicePath(data []byte) *EFIDevicePath {
	stream := bytes.NewReader(data)

	var rootNode, lastNode *efiDevicePathNode
	for {
		node := readDevicePathNode(stream)
		if node == nil {
			return &EFIDevicePath{}
		}

		if node.t == efiDevicePathNodeEoH {
			break
		}

		if lastNode != nil {
			lastNode.next = node
		} else {
			rootNode = node
		}
		lastNode = node
	}

	return &EFIDevicePath{root: rootNode}
}

type EFIImageLoadEventData struct {
	data             []byte
	LocationInMemory uint64
	LengthInMemory   uint64
	LinkTimeAddress  uint64
	Path             *EFIDevicePath
}

func (e *EFIImageLoadEventData) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.LocationInMemory, e.LengthInMemory,
		e.LinkTimeAddress, e.Path)
}

func (e *EFIImageLoadEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 4 "Measuring PE/COFF Image Files")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.3 "UEFI_IMAGE_LOAD_EVENT Structure")
func makeEventDataEFIImageLoadImpl(data []byte) (*EFIImageLoadEventData, int, error) {
	stream := bytes.NewReader(data)

	var locationInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &locationInMemory); err != nil {
		return nil, 0, err
	}

	var lengthInMemory uint64
	if err := binary.Read(stream, binary.LittleEndian, &lengthInMemory); err != nil {
		return nil, 0, err
	}

	var linkTimeAddress uint64
	if err := binary.Read(stream, binary.LittleEndian, &linkTimeAddress); err != nil {
		return nil, 0, err
	}

	var devicePathLength uint64
	if err := binary.Read(stream, binary.LittleEndian, &devicePathLength); err != nil {
		return nil, 0, err
	}

	devicePathBuf := make([]byte, devicePathLength)

	if _, err := io.ReadFull(stream, devicePathBuf); err != nil {
		return nil, 0, err
	}

	path := readDevicePath(devicePathBuf)

	return &EFIImageLoadEventData{data: data,
		LocationInMemory: locationInMemory,
		LengthInMemory:   lengthInMemory,
		LinkTimeAddress:  linkTimeAddress,
		Path:             path}, bytesRead(stream), nil
}

func makeEventDataEFIImageLoad(data []byte) (out EventData, n int, err error) {
	d, n, err := makeEventDataEFIImageLoadImpl(data)
	if d != nil {
		out = d
	}
	return
}

type EFIGPTPartitionEntry struct {
	TypeGUID   EFIGUID
	UniqueGUID EFIGUID
	Attrs      uint64
	Name       string
}

func (p *EFIGPTPartitionEntry) String() string {
	return fmt.Sprintf("PartitionTypeGUID: %s, UniquePartitionGUID: %s, Name: \"%s\"",
		&p.TypeGUID, &p.UniqueGUID, p.Name)
}

type EFIGPTEventData struct {
	data       []byte
	DiskGUID   EFIGUID
	Partitions []EFIGPTPartitionEntry
}

func (e *EFIGPTEventData) String() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{ DiskGUID: %s, Partitions: [", &e.DiskGUID)
	for i, part := range e.Partitions {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{ %s }", &part)
	}
	fmt.Fprintf(&builder, "] }")
	return builder.String()
}

func (e *EFIGPTEventData) Bytes() []byte {
	return e.data
}

func makeEventDataEFIGPTImpl(data []byte) (*EFIGPTEventData, int, error) {
	stream := bytes.NewReader(data)

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.{Header, MyLBA, AlternateLBA, FirstUsableLBA, LastUsableLBA}
	if _, err := stream.Seek(56, io.SeekCurrent); err != nil {
		return nil, 0, err
	}

	// UEFI_GPT_DATA.UEFIPartitionHeader.DiskGUID
	var diskGUID EFIGUID
	if err := readEFIGUID(stream, &diskGUID); err != nil {
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

	eventData := &EFIGPTEventData{DiskGUID: diskGUID, Partitions: make([]EFIGPTPartitionEntry, numberOfParts)}

	for i := uint64(0); i < numberOfParts; i++ {
		entryData := make([]byte, partEntrySize)
		if _, err := io.ReadFull(stream, entryData); err != nil {
			return nil, 0, err
		}

		entryStream := bytes.NewReader(entryData)

		var typeGUID EFIGUID
		if err := readEFIGUID(entryStream, &typeGUID); err != nil {
			return nil, 0, err
		}

		var uniqueGUID EFIGUID
		if err := readEFIGUID(entryStream, &uniqueGUID); err != nil {
			return nil, 0, err
		}

		// Skip UEFI_GPT_DATA.Partitions[i].{StartingLBA, EndingLBA}
		if _, err := entryStream.Seek(16, io.SeekCurrent); err != nil {
			return nil, 0, err
		}

		var attrs uint64
		if err := binary.Read(entryStream, binary.LittleEndian, &attrs); err != nil {
			return nil, 0, err
		}

		name, err := decodeUTF16ToString(entryStream, uint64(entryStream.Len()))
		if err != nil {
			return nil, 0, err
		}

		eventData.Partitions[i] =
			EFIGPTPartitionEntry{TypeGUID: typeGUID, UniqueGUID: uniqueGUID, Attrs: attrs, Name: name}
	}

	return eventData, bytesRead(stream), nil
}

func makeEventDataEFIGPT(data []byte) (out EventData, n int, err error) {
	d, n, err := makeEventDataEFIGPTImpl(data)
	if d != nil {
		out = d
	}
	return
}
