// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
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

func (e *SpecIdEvent00) String() string {
	return fmt.Sprintf("PCClientSpecIdEvent{ platformClass=%d, specVersionMinor=%d, specVersionMajor=%d, specErrata=%d }",
		e.PlatformClass, e.SpecVersionMinor, e.SpecVersionMajor, e.SpecErrata)
}

func (e *SpecIdEvent00) Type() NoActionEventType {
	return SpecId
}

func (e *SpecIdEvent00) Signature() string {
	return "Spec ID Event00"
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.3.4.1 "Specification Event")
func decodeSpecIdEvent00(r io.Reader) (out *SpecIdEvent00, err error) {
	out = &SpecIdEvent00{}
	if err := binary.Read(r, binary.LittleEndian, &out.PlatformClass); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SpecVersionMinor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SpecVersionMajor); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}
	if err := binary.Read(r, binary.LittleEndian, &out.SpecErrata); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	var reserved uint8
	if err := binary.Read(r, binary.LittleEndian, &reserved); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, ioerr.EOFIsUnexpected(err)
	}

	out.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, out.VendorInfo); err != nil {
		return nil, err
	}

	return out, nil
}
