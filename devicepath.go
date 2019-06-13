package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

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
	efiFirmwareDevicePathNodeFile   = 0x06
	efiFirmwareDevicePathNodeVolume = 0x07
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
	case efiFirmwareDevicePathNodeFile:
		builder.WriteString("FvFile")
	case efiFirmwareDevicePathNodeVolume:
		builder.WriteString("Fv")
	default:
		return ""
	}

	fmt.Fprintf(&builder, "(%s)", &name)
	return builder.String()
}

func acpiDevicePathNodeToString(n *efiDevicePathNode) string {
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
			return fmt.Sprintf("Acpi(PNP%04x, 0x%x)", hid>>16, uid)
		}
	} else {
		return fmt.Sprintf("Acpi(0x%08x, 0x%x)", hid, uid)
	}
}

func (n *efiDevicePathNode) toString() string {
	switch {
	case n.t == efiDevicePathNodeMedia && (n.subType == efiFirmwareDevicePathNodeFile || n.subType == efiFirmwareDevicePathNodeVolume):
		return firmwareDevicePathNodeToString(n)
	case n.t == efiDevicePathNodeACPI && n.subType == 0x01:
		return acpiDevicePathNodeToString(n)
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
