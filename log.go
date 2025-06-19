// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"github.com/canonical/go-tpm2"
)

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

func NewLog(event0 *Event) (*Log, []EFISpecIdEventAlgorithmSize) {
	var spec Spec
	var digestSizes []EFISpecIdEventAlgorithmSize

	switch d := event0.Data.(type) {
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
			if s.AlgorithmId.IsValid() {
				algorithms = append(algorithms, s.AlgorithmId)
			}
		}
	} else {
		algorithms = AlgorithmIdList{tpm2.HashAlgorithmSHA1}
	}

	return &Log{Spec: spec, Algorithms: algorithms, Events: []*Event{event0}}, digestSizes
}

// NewLogForTesting creates a new log instance from the supplied list of
// events.
func NewLogForTesting(events []*Event) *Log {
	if len(events) == 0 {
		return new(Log)
	}

	log, _ := NewLog(events[0])
	log.Events = append(log.Events, events[1:]...)
	return log
}
