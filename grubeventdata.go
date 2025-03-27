// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/canonical/go-tpm2"
)

var (
	kernelCmdlinePrefix = "kernel_cmdline: "
	grubCmdPrefix       = "grub_cmd: "
)

// GrubStringEventType indicates the type of data measured by GRUB in to a log by GRUB.
type GrubStringEventType string

const (
	// GrubCmd indicates that the data measured by GRUB is associated with a GRUB command.
	GrubCmd GrubStringEventType = "grub_cmd"

	// KernelCmdline indicates that the data measured by GRUB is associated with a kernel commandline.
	KernelCmdline = "kernel_cmdline"
)

// GrubStringEventData represents the data associated with an event measured by GRUB.
type GrubStringEventData struct {
	Type GrubStringEventType
	Str  string
}

func (e *GrubStringEventData) String() string {
	return fmt.Sprintf("%s{ %s }", string(e.Type), e.Str)
}

func (e *GrubStringEventData) Bytes() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes(), nil
}

func (e *GrubStringEventData) Write(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("%s: %s\x00", string(e.Type), e.Str))
	return err
}

func decodeEventDataGRUB(data []byte, pcrIndex tpm2.Handle, eventType EventType) EventData {
	if eventType != EventTypeIPL {
		return nil
	}

	switch pcrIndex {
	case 0x00000008:
		str := string(data)
		switch {
		case strings.HasPrefix(str, kernelCmdlinePrefix):
			return &GrubStringEventData{Type: KernelCmdline, Str: strings.TrimSuffix(strings.TrimPrefix(str, kernelCmdlinePrefix), "\x00")}
		case strings.HasPrefix(str, grubCmdPrefix):
			return &GrubStringEventData{Type: GrubCmd, Str: strings.TrimSuffix(strings.TrimPrefix(str, grubCmdPrefix), "\x00")}
		default:
			return nil
		}
	case 0x00000009:
		return StringEventData(data)
	default:
		panic("unhandled PCR index")
	}
}
