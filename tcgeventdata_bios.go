// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

// SpecIdEvent00 corresponds to the TCG_PCClientSpecIdEventStruct type and is the
// event data for a Specification ID Version EV_NO_ACTION event for BIOS platforms.
type SpecIdEvent00 struct {
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	VendorInfo       []byte
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//
//	(section 11.3.4.1 "Specification Event")
func decodeSpecIdEvent00(data []byte, r io.Reader) (out *SpecIdEvent00, err error) {
	d := new(SpecIdEvent00)

	if err := binary.Read(r, binary.LittleEndian, &d.PlatformClass); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMinor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecVersionMajor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &d.SpecErrata); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	var reserved uint8
	if err := binary.Read(r, binary.LittleEndian, &reserved); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	vendorInfo, err := readLengthPrefixed[uint8, byte](r)
	if err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	d.VendorInfo = vendorInfo

	return d, nil
}

func (e *SpecIdEvent00) String() string {
	return fmt.Sprintf("PCClientSpecIdEvent{ platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, specErrata=%d }",
		e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
}

func (e *SpecIdEvent00) Bytes() []byte {
	w := new(bytes.Buffer)
	if err := e.Write(w); err != nil {
		panic(err)
	}
	return w.Bytes()
}

func (e *SpecIdEvent00) Write(w io.Writer) error {
	var signature [16]byte
	copy(signature[:], []byte("Spec ID Event00"))
	if _, err := w.Write(signature[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.PlatformClass); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMinor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecVersionMajor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, e.SpecErrata); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	return writeLengthPrefixed[uint8](w, e.VendorInfo)
}
