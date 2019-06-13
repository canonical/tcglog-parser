package tcglog

import (
	"fmt"
	"strings"
)

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

func makeEventDataGRUB(pcrIndex PCRIndex, data []byte) EventData {
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
