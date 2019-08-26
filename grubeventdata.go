package tcglog

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

var (
	kernelCmdlinePrefix = "kernel_cmdline: "
	grubCmdPrefix       = "grub_cmd: "
)

type KernelCmdlineEventData struct {
	data    []byte
	cmdline []byte
}

func (e *KernelCmdlineEventData) String() string {
	return fmt.Sprintf("kernel_cmdline{ %s }", e.Cmdline())
}

func (e *KernelCmdlineEventData) Bytes() []byte {
	return e.data
}

func (e *KernelCmdlineEventData) Cmdline() string {
	return *(*string)(unsafe.Pointer(&e.cmdline))
}

type GrubCmdEventData struct {
	data []byte
	cmd  []byte
}

func (e *GrubCmdEventData) String() string {
	return fmt.Sprintf("grub_cmd{ %s }", e.Cmd())
}

func (e *GrubCmdEventData) Bytes() []byte {
	return e.data
}

func (e *GrubCmdEventData) Cmd() string {
	return *(*string)(unsafe.Pointer(&e.cmd))
}

func decodeEventDataGRUB(pcrIndex PCRIndex, eventType EventType, data []byte) (EventData, int, error) {
	if eventType != EventTypeIPL {
		return nil, 0, nil
	}

	switch pcrIndex {
	case 8:
		str := *(*string)(unsafe.Pointer(&data))

		switch {
		case strings.Index(str, kernelCmdlinePrefix) == 0:
			return &KernelCmdlineEventData{data,
					data[len(kernelCmdlinePrefix) : len(str)-1]},
				len(data), nil
		case strings.Index(str, grubCmdPrefix) == 0:
			return &GrubCmdEventData{data, data[len(grubCmdPrefix) : len(str)-1]}, len(data), nil
		default:
			return nil, 0, errors.New("unexpected prefix for GRUB string")
		}
	case 9:
		return &AsciiStringEventData{data: data}, len(data), nil
	default:
		panic("unhandled PCR index")
	}
}
