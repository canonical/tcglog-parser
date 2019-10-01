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

type GrubStringEventType int

const (
	GrubCmd GrubStringEventType = iota
	KernelCmdline
)

func grubEventTypeString(t GrubStringEventType) string {
	switch t {
	case GrubCmd:
		return "grub_cmd"
	case KernelCmdline:
		return "kernel_cmdline"
	}
	panic("invalid value")
}

type GrubStringEventData struct {
	data         []byte
	measuredData []byte
	Type         GrubStringEventType
}

func (e *GrubStringEventData) String() string {
	return fmt.Sprintf("%s{ %s }", grubEventTypeString(e.Type), e.MeasuredString())
}

func (e *GrubStringEventData) Bytes() []byte {
	return e.data
}

func (e *GrubStringEventData) MeasuredString() string {
	return *(*string)(unsafe.Pointer(&e.measuredData))
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
			return &GrubStringEventData{data, data[len(kernelCmdlinePrefix) : len(str)-1],
				KernelCmdline}, 0, nil
		case strings.Index(str, grubCmdPrefix) == 0:
			return &GrubStringEventData{data, data[len(grubCmdPrefix) : len(str)-1], GrubCmd}, 0, nil
		default:
			return nil, 0, errors.New("unexpected prefix for GRUB string")
		}
	case 9:
		return &asciiStringEventData{data: data}, 0, nil
	default:
		panic("unhandled PCR index")
	}
}
