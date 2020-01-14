package tcglog

import (
	"fmt"
	"io"
	"strings"
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
	data []byte
	Type GrubStringEventType
	Str  string
}

func (e *GrubStringEventData) String() string {
	return fmt.Sprintf("%s{ %s }", grubEventTypeString(e.Type), e.Str)
}

func (e *GrubStringEventData) Bytes() []byte {
	return e.data
}

func (e *GrubStringEventData) Encode(buf io.Writer) error {
	if _, err := io.WriteString(buf, e.Str); err != nil {
		return err
	}
	return nil
}

func decodeEventDataGRUB(pcrIndex PCRIndex, eventType EventType, data []byte) (EventData, int) {
	if eventType != EventTypeIPL {
		return nil, 0
	}

	switch pcrIndex {
	case 8:
		str := string(data)
		switch {
		case strings.HasPrefix(str, kernelCmdlinePrefix):
			return &GrubStringEventData{data, KernelCmdline, strings.TrimSuffix(strings.TrimPrefix(str, kernelCmdlinePrefix), "\x00")}, 0
		case strings.HasPrefix(str, grubCmdPrefix):
			return &GrubStringEventData{data, GrubCmd, strings.TrimSuffix(strings.TrimPrefix(str, grubCmdPrefix), "\x00")}, 0
		default:
			return nil, 0
		}
	case 9:
		return &asciiStringEventData{data: data}, 0
	default:
		panic("unhandled PCR index")
	}
}
