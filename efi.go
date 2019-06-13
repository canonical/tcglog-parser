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
func decodeUTF16ToString(stream io.Reader, count uint64, order binary.ByteOrder) (string, error) {
	var builder strings.Builder

	for i := uint64(0); i < count; i++ {
		var c1 uint16
		if err := binary.Read(stream, order, &c1); err != nil {
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
			if err := binary.Read(stream, order, &c2); err != nil {
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

func readEFIGUID(stream io.Reader, order binary.ByteOrder, out *EFIGUID) error {
	if err := binary.Read(stream, order, &out.Data1); err != nil {
		return err
	}
	if err := binary.Read(stream, order, &out.Data2); err != nil {
		return err
	}
	if err := binary.Read(stream, order, &out.Data3); err != nil {
		return err
	}
	if _, err := io.ReadFull(stream, out.Data4[:]); err != nil {
		return err
	}
	return nil
}

func makeEFIGUID(data [16]byte, order binary.ByteOrder) *EFIGUID {
	stream := bytes.NewReader(data[:])

	var out EFIGUID
	if err := readEFIGUID(stream, order, &out); err != nil {
		return nil
	}

	return &out
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

func makeEventDataEFIVariable(data []byte, order binary.ByteOrder) (*EFIVariableEventData, error) {
	stream := bytes.NewReader(data)

	var guid EFIGUID
	if err := readEFIGUID(stream, order, &guid); err != nil {
		return nil, err
	}

	var unicodeNameLength uint64
	if err := binary.Read(stream, order, &unicodeNameLength); err != nil {
		return nil, err
	}

	var variableDataLength uint64
	if err := binary.Read(stream, order, &variableDataLength); err != nil {
		return nil, err
	}

	unicodeName, err := decodeUTF16ToString(stream, unicodeNameLength, order)
	if err != nil {
		return nil, err
	}

	variableData := make([]byte, variableDataLength)
	if _, err := io.ReadFull(stream, variableData); err != nil {
		return nil, err
	}

	return &EFIVariableEventData{data: data,
		VariableName: guid,
		UnicodeName:  unicodeName,
		VariableData: variableData}, nil
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

	efiMediaDevicePathNodeHardDrive = 0x01
	efiMediaDevicePathNodeFilePath  = 0x04
	efiMediaDevicePathNodeFvFile    = 0x06
	efiMediaDevicePathNodeFv        = 0x07
)

type efiDevicePathNode struct {
	t       efiDevicePathNodeType
	subType uint8
	data    []byte
	order   binary.ByteOrder
	next    *efiDevicePathNode
}

func firmwareDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var name EFIGUID
	if err := readEFIGUID(stream, n.order, &name); err != nil {
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
	if err := binary.Read(stream, n.order, &hid); err != nil {
		return ""
	}

	var uid uint32
	if err := binary.Read(stream, n.order, &uid); err != nil {
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
	if err := binary.Read(stream, n.order, &function); err != nil {
		return ""
	}

	var device uint8
	if err := binary.Read(stream, n.order, &device); err != nil {
		return ""
	}

	return fmt.Sprintf("Pci(0x%x,0x%x)", device, function)
}

func luDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var lun uint8
	if err := binary.Read(stream, n.order, &lun); err != nil {
		return ""
	}

	return fmt.Sprintf("Unit(0x%x)", lun)
}

func hardDriveDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var partNumber uint32
	if err := binary.Read(stream, n.order, &partNumber); err != nil {
		return ""
	}

	var partStart uint64
	if err := binary.Read(stream, n.order, &partStart); err != nil {
		return ""
	}

	var partSize uint64
	if err := binary.Read(stream, n.order, &partSize); err != nil {
		return ""
	}

	var sig [16]byte
	if _, err := io.ReadFull(stream, sig[:]); err != nil {
		return ""
	}

	var partFormat uint8
	if err := binary.Read(stream, n.order, &partFormat); err != nil {
		return ""
	}

	var sigType uint8
	if err := binary.Read(stream, n.order, &sigType); err != nil {
		return ""
	}

	var builder strings.Builder

	switch sigType {
	case 0x01:
		fmt.Fprintf(&builder, "HD(%d,MBR,0x%08x,", partNumber, n.order.Uint32(sig[:]))
	case 0x02:
		fmt.Fprintf(&builder, "HD(%d,GPT,%s,", partNumber, makeEFIGUID(sig, n.order))
	default:
		fmt.Fprintf(&builder, "HD(%d,%d,0,", partNumber, sigType)
	}

	fmt.Fprintf(&builder, "0x%016x, 0x%016x)", partStart, partSize)
	return builder.String()
}

func sataDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	var hbaPortNumber uint16
	if err := binary.Read(stream, n.order, &hbaPortNumber); err != nil {
		return ""
	}

	var portMultiplierPortNumber uint16
	if err := binary.Read(stream, n.order, &portMultiplierPortNumber); err != nil {
		return ""
	}

	var lun uint16
	if err := binary.Read(stream, n.order, &lun); err != nil {
		return ""
	}

	return fmt.Sprintf("Sata(0x%x,0x%x,0x%x)", hbaPortNumber, portMultiplierPortNumber, lun)
}

func filePathDevicePathNodeToString(n *efiDevicePathNode) string {
	stream := bytes.NewReader(n.data)

	s, err := decodeUTF16ToString(stream, uint64(len(n.data)), n.order)
	if err != nil {
		return ""
	}
	return s
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

func readDevicePathNode(stream io.Reader, order binary.ByteOrder) *efiDevicePathNode {
	var t efiDevicePathNodeType
	if err := binary.Read(stream, order, &t); err != nil {
		return nil
	}

	var subType uint8
	if err := binary.Read(stream, order, &subType); err != nil {
		return nil
	}

	var length uint16
	if err := binary.Read(stream, order, &length); err != nil {
		return nil
	}

	if length < 4 {
		return nil
	}

	data := make([]byte, length-4)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil
	}

	return &efiDevicePathNode{t: t, subType: subType, data: data, order: order}
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

func readDevicePath(data []byte, order binary.ByteOrder) *EFIDevicePath {
	stream := bytes.NewReader(data)

	var rootNode, lastNode *efiDevicePathNode
	for {
		node := readDevicePathNode(stream, order)
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

func (e *EFIImageLoadEventData) RawBytes() []byte {
	return e.data
}

func (e *EFIImageLoadEventData) MeasuredBytes() []byte {
	return nil
}

func makeEventDataImageLoad(data []byte, order binary.ByteOrder) (*EFIImageLoadEventData, error) {
	stream := bytes.NewReader(data)

	var locationInMemory uint64
	if err := binary.Read(stream, order, &locationInMemory); err != nil {
		return nil, err
	}

	var lengthInMemory uint64
	if err := binary.Read(stream, order, &lengthInMemory); err != nil {
		return nil, err
	}

	var linkTimeAddress uint64
	if err := binary.Read(stream, order, &linkTimeAddress); err != nil {
		return nil, err
	}

	var devicePathLength uint64
	if err := binary.Read(stream, order, &devicePathLength); err != nil {
		return nil, err
	}

	devicePathBuf := make([]byte, devicePathLength)

	if _, err := io.ReadFull(stream, devicePathBuf); err != nil {
		return nil, err
	}

	path := readDevicePath(devicePathBuf, order)

	return &EFIImageLoadEventData{data: data,
		LocationInMemory: locationInMemory,
		LengthInMemory:   lengthInMemory,
		LinkTimeAddress:  linkTimeAddress,
		Path:             path}, nil
}
