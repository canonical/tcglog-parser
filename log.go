// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser/internal/ioerr"
)

// LogOptions allows the behaviour of Log to be controlled.
type LogOptions struct {
	EnableGrub           bool     // Enable support for interpreting events recorded by GRUB
	EnableSystemdEFIStub bool     // Enable support for interpreting events recorded by systemd's EFI linux loader stub
	SystemdEFIStubPCR    PCRIndex // Specify the PCR that systemd's EFI linux loader stub measures to
}

type parser interface {
	readNextEvent() (*Event, error)
}

func isPCRIndexInRange(index PCRIndex) bool {
	const maxPCRIndex PCRIndex = 31
	return index <= maxPCRIndex
}

type eventHeader_1_2 struct {
	PCRIndex  PCRIndex
	EventType EventType
}

type parser_1_2 struct {
	r       io.Reader
	options *LogOptions
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.1.1 "TCG_PCClientPCREventStruct Structure")
func (p *parser_1_2) readNextEvent() (*Event, error) {
	var header eventHeader_1_2
	if err := binary.Read(p.r, binary.LittleEndian, &header); err != nil {
		return nil, ioerr.PassRawEOF("cannot read event header: %w", err)
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, fmt.Errorf("log entry has an out-of-range PCR index (%d)", header.PCRIndex)
	}

	digest := make(Digest, tpm2.HashAlgorithmSHA1.Size())
	if _, err := io.ReadFull(p.r, digest); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read SHA-1 digest: %w", err)
	}
	digests := make(DigestMap)
	digests[tpm2.HashAlgorithmSHA1] = digest

	var eventSize uint32
	if err := binary.Read(p.r, binary.LittleEndian, &eventSize); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read event size: %w", err)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(p.r, event); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read event data: %w", err)
	}

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      decodeEventData(event, header.PCRIndex, header.EventType, digests, p.options),
	}, nil
}

type eventHeader_2 struct {
	PCRIndex  PCRIndex
	EventType EventType
	Count     uint32
}

type parser_2 struct {
	r        io.Reader
	options  *LogOptions
	algSizes []EFISpecIdEventAlgorithmSize
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.2.2 "TCG_PCR_EVENT2 Structure")
func (p *parser_2) readNextEvent() (*Event, error) {
	var header eventHeader_2
	if err := binary.Read(p.r, binary.LittleEndian, &header); err != nil {
		return nil, ioerr.PassRawEOF("cannot read event header: %w", err)
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, fmt.Errorf("log entry has an out-of-range PCR index (%d)", header.PCRIndex)
	}

	digests := make(DigestMap)

	for i := uint32(0); i < header.Count; i++ {
		var algorithmId tpm2.HashAlgorithmId
		if err := binary.Read(p.r, binary.LittleEndian, &algorithmId); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read algorithm ID: %w", err)
		}

		var digestSize uint16
		var j int
		for j = 0; j < len(p.algSizes); j++ {
			if p.algSizes[j].AlgorithmId == algorithmId {
				digestSize = p.algSizes[j].DigestSize
				break
			}
		}

		if j == len(p.algSizes) {
			return nil, fmt.Errorf("event contains a digest for an unrecognized algorithm (%v)", algorithmId)
		}

		digest := make(Digest, digestSize)
		if _, err := io.ReadFull(p.r, digest); err != nil {
			return nil, ioerr.EOFIsUnexpected("cannot read digest for algorithm %v: %w", algorithmId, err)
		}

		if _, exists := digests[algorithmId]; exists {
			return nil, fmt.Errorf("event contains more than one digest value for algorithm %v", algorithmId)
		}
		digests[algorithmId] = digest
	}

	for _, s := range p.algSizes {
		if _, exists := digests[s.AlgorithmId]; !exists {
			return nil, fmt.Errorf("event is missing a digest value for algorithm %v", s.AlgorithmId)
		}
	}

	for alg, _ := range digests {
		if alg.Supported() {
			continue
		}
		delete(digests, alg)
	}

	var eventSize uint32
	if err := binary.Read(p.r, binary.LittleEndian, &eventSize); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read event size: %w", err)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(p.r, event); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read event data: %w", err)
	}

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      decodeEventData(event, header.PCRIndex, header.EventType, digests, p.options),
	}, nil
}

func fixupSpecIdEvent(event *Event, algorithms AlgorithmIdList) {
	for _, alg := range algorithms {
		if alg == tpm2.HashAlgorithmSHA1 {
			continue
		}

		if _, ok := event.Digests[alg]; ok {
			continue
		}

		event.Digests[alg] = make(Digest, alg.Size())
	}
}

type PlatformType int

const (
	PlatformTypeUnknown PlatformType = iota
	PlatformTypeBIOS
	PlatformTypeEFI
)

// Spec corresponds to the TCG specification that an event log conforms to.
type Spec struct {
	PlatformType PlatformType
	Major        uint8
	Minor        uint8
	Errata       uint8
}

// IsBIOS indicates that a log conforms to "TCG PC Client Specific Implementation Specification
// for Conventional BIOS".
// See https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
func (s Spec) IsBIOS() bool { return s.PlatformType == PlatformTypeBIOS }

// IsEFI_1_2 indicates that a log conforms to "TCG EFI Platform Specification For TPM Family 1.1 or
// 1.2".
// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
func (s Spec) IsEFI_1_2() bool {
	return s.PlatformType == PlatformTypeEFI && s.Major == 1 && s.Minor == 2
}

// IsEFI_2 indicates that a log conforms to "TCG PC Client Platform Firmware Profile Specification"
// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
func (s Spec) IsEFI_2() bool {
	return s.PlatformType == PlatformTypeEFI && s.Major == 2
}

// Log corresponds to a parsed event log.
type Log struct {
	Spec       Spec            // The specification to which this log conforms
	Algorithms AlgorithmIdList // The digest algorithms that appear in the log
	Events     []*Event        // The list of events in the log
}

// ParseLog parses an event log read from r, using the supplied options. If an error occurs during parsing, this may return an
// incomplete list of events with the error.
func ParseLog(r io.Reader, options *LogOptions) (*Log, error) {
	var parser parser = &parser_1_2{r: r, options: options}
	event, err := parser.readNextEvent()
	if err != nil {
		return nil, err
	}

	var spec Spec
	var digestSizes []EFISpecIdEventAlgorithmSize

	switch d := event.Data.(type) {
	case *SpecIdEvent00:
		spec = Spec{
			PlatformType: PlatformTypeBIOS,
			Major:        d.SpecVersionMajor,
			Minor:        d.SpecVersionMinor,
			Errata:       d.SpecErrata}
	case *SpecIdEvent02:
		spec = Spec{
			PlatformType: PlatformTypeEFI,
			Major:        d.SpecVersionMajor,
			Minor:        d.SpecVersionMinor,
			Errata:       d.SpecErrata}
	case *SpecIdEvent03:
		spec = Spec{
			PlatformType: PlatformTypeEFI,
			Major:        d.SpecVersionMajor,
			Minor:        d.SpecVersionMinor,
			Errata:       d.SpecErrata}
		digestSizes = d.DigestSizes
	}

	var algorithms AlgorithmIdList

	if spec.IsEFI_2() {
		for _, s := range digestSizes {
			if s.AlgorithmId.Supported() {
				algorithms = append(algorithms, s.AlgorithmId)
			}
		}
		parser = &parser_2{r: r,
			options:  options,
			algSizes: digestSizes}
	} else {
		algorithms = AlgorithmIdList{tpm2.HashAlgorithmSHA1}
	}

	if spec.IsEFI_2() {
		fixupSpecIdEvent(event, algorithms)
	}

	log := &Log{Spec: spec, Algorithms: algorithms, Events: []*Event{event}}

	for {
		event, err := parser.readNextEvent()
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
