// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"io"
)

// LogOptions allows the behaviour of Log to be controlled.
type LogOptions struct {
	EnableGrub           bool     // Enable support for interpreting events recorded by GRUB
	EnableSystemdEFIStub bool     // Enable support for interpreting events recorded by systemd's EFI linux loader stub
	SystemdEFIStubPCR    PCRIndex // Specify the PCR that systemd's EFI linux loader stub measures to
}

// ReadLog reads an event log read from r using the supplied options. The log must
// be in the format defined in one of the PC Client Platform Firmware Profile
// specifications. If an error occurs during parsing, this may return an incomplete
// list of events with the error.
func ReadLog(r io.Reader, options *LogOptions) (*Log, error) {
	event, err := ReadEvent(r, options)
	switch {
	case err == io.EOF:
		return new(Log), nil
	case err != nil:
		return nil, err
	}

	log, digestSizes := NewLog(event)

	for {
		var event *Event
		var err error
		if log.Spec.IsEFI_2() {
			event, err = ReadEventCryptoAgile(r, digestSizes, options)
		} else {
			event, err = ReadEvent(r, options)
		}

		switch {
		case err == io.EOF:
			return log, nil
		case err != nil:
			return log, err
		default:
			log.Events = append(log.Events, event)
		}
	}
}
