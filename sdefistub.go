// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"crypto"
	"encoding/binary"
)

// SystemdEFIStubCommandline represents the data associated with a kernel commandline measured by the systemd EFI stub linux loader.
type SystemdEFIStubCommandline struct {
	data []byte
	Str  string
}

func (e *SystemdEFIStubCommandline) String() string {
	return e.Str
}

func (e *SystemdEFIStubCommandline) Bytes() []byte {
	return e.data
}

// ComputeSystemdEFIStubCommandlineDigest computes the digest measured by the systemd EFI stub linux loader for the specified
// kernel commandline. Note that it assumes that the calling bootloader includes a UTF-16 NULL terminator at the end of
// LoadOptions and sets LoadOptionsSize to StrLen(LoadOptions)+1.
func ComputeSystemdEFIStubCommandlineDigest(alg crypto.Hash, commandline string) []byte {
	h := alg.New()

	// Both GRUB's chainloader and systemd's EFI bootloader include a UTF-16 NULL terminator at the end of LoadOptions and
	// set LoadOptionsSize to StrLen(LoadOptions)+1. The EFI stub loader measures LoadOptionsSize number of bytes, meaning that
	// the 2 NULL bytes are measured. Include those here.
	binary.Write(h, binary.LittleEndian, append(convertStringToUtf16(commandline), 0))
	return h.Sum(nil)
}

func decodeEventDataSystemdEFIStub(data []byte, eventType EventType) EventData {
	if eventType != EventTypeIPL {
		return nil
	}

	// data is a UTF-16 string in little-endian form terminated with a single zero byte.
	// Omit the zero byte added by the EFI stub and then convert to native byte order.
	reader := bytes.NewReader(data[:len(data)-1])

	utf16Str := make([]uint16, len(data)/2)
	binary.Read(reader, binary.LittleEndian, &utf16Str)

	return &SystemdEFIStubCommandline{data: data, Str: convertUtf16ToString(utf16Str)}
}
