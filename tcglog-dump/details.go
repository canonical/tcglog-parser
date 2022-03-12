// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/canonical/go-efilib"

	"github.com/canonical/tcglog-parser"
)

type bootOrderStringer []byte

func (s bootOrderStringer) String() string {
	data := []byte(s)

	if len(data)%2 != 0 {
		return fmt.Sprint("Invalid BootOrder payload length (", len(data), " bytes)")
	}

	var order []string
	for len(data) > 0 {
		order = append(order, fmt.Sprintf("%04x", binary.LittleEndian.Uint16(data)))
		data = data[2:]
	}

	return "BootOrder: " + strings.Join(order, ",")
}

type bootOptionStringer struct {
	verbose bool
	name    string
	data    []byte
}

func (s *bootOptionStringer) String() string {
	opt, err := efi.ReadLoadOption(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid load option for %s: %v", s.name, err)
	}

	if s.verbose {
		return fmt.Sprintf("%s: %v", s.name, opt)
	}
	return fmt.Sprintf("%s: %s", s.name, opt.Description)
}

type variableDriverConfigBoolStringer struct {
	name string
	data []byte
}

func (s *variableDriverConfigBoolStringer) String() string {
	switch {
	case bytes.Equal(s.data, []byte{0}):
		return s.name + ": 0"
	case bytes.Equal(s.data, []byte{1}):
		return s.name + ": 1"
	default:
		return "Invalid " + s.name + " payload"
	}
}

type variableDriverConfigDbStringer struct {
	verbose bool
	name    string
	data    []byte
}

func (s *variableDriverConfigDbStringer) String() string {
	db, err := efi.ReadSignatureDatabase(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid signature database for %s: %v", s.name, err)
	}

	str := fmt.Sprintf("%-4s", s.name+":")

	counts := make(map[efi.GUID]int)
	for _, l := range db {
		if _, exists := counts[l.Type]; !exists {
			counts[l.Type] = 0
		}
		counts[l.Type] += len(l.Signatures)
	}

	if n := counts[efi.CertX509Guid]; n > 0 {
		str += fmt.Sprint(" entries(x509)=", n)
	}
	if n := counts[efi.CertSHA256Guid]; n > 0 {
		str += fmt.Sprint(" entries(sha256)=", n)
	}

	if s.verbose {
		return str + strings.Replace(db.String(), "\n", "\n\t", -1)
	}
	return str
}

type variableAuthorityStringer struct {
	verbose      bool
	variableName efi.GUID
	unicodeName  string
	data         []byte
}

func (s *variableAuthorityStringer) String() string {
	var authority string

	if s.verbose {
		data := s.data

		var guid efi.GUID
		data = data[copy(guid[:], s.data):]

		cert, err := x509.ParseCertificate(data)
		if err != nil {
			guid = efi.GUID{}
			cert, err = x509.ParseCertificate(s.data)
		}

		if err == nil {
			authority = fmt.Sprint("authority: \"", cert.Subject, "\", ")
		}
	}

	if s.variableName == efi.ImageSecurityDatabaseGuid {
		return authority + "source: \"" + s.unicodeName + "\""
	}
	return fmt.Sprintf("%ssource: guid=%v, name=\"%s\"", authority, s.variableName, s.unicodeName)
}

type sbatLevelStringer struct{}

func (sbatLevelStringer) String() string { return "SbatLevel" }

type simpleGptEventStringer struct {
	data *tcglog.EFIGPTData
}

func (s *simpleGptEventStringer) String() string {
	return fmt.Sprint("GUID: ", s.data.Hdr.DiskGUID)
}

func customEventDetailsStringer(event *tcglog.Event, verbose bool) fmt.Stringer {
	switch {
	//case event.EventType == tcglog.EventTypeNoAction && !verbose:
	case event.EventType == tcglog.EventTypeEFIVariableBoot, event.EventType == tcglog.EventTypeEFIVariableBoot2:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return event.Data
		}
		if varData.VariableName != efi.GlobalVariable {
			// Unexpected GUID
			return nil
		}

		if varData.UnicodeName == "BootOrder" {
			return bootOrderStringer(varData.VariableData)
		}

		return &bootOptionStringer{verbose, varData.UnicodeName, varData.VariableData}
	case event.EventType == tcglog.EventTypeEFIVariableDriverConfig:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return event.Data
		}
		if varData.VariableName == efi.ImageSecurityDatabaseGuid {
			return &variableDriverConfigDbStringer{verbose, varData.UnicodeName, varData.VariableData}
		}
		if varData.VariableName != efi.GlobalVariable {
			// Unexpected GUID
			return nil
		}
		switch varData.UnicodeName {
		case "SecureBoot", "DeployedMode", "AuditMode":
			return &variableDriverConfigBoolStringer{varData.UnicodeName, varData.VariableData}
		default:
			return &variableDriverConfigDbStringer{verbose, varData.UnicodeName, varData.VariableData}
		}
	case event.EventType == tcglog.EventTypeEFIVariableAuthority:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return event.Data
		}
		if varData.VariableName == efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}) &&
			varData.UnicodeName == "SbatLevel" {
			return sbatLevelStringer{}
		}

		return &variableAuthorityStringer{verbose, varData.VariableName, varData.UnicodeName, varData.VariableData}
	case event.EventType == tcglog.EventTypeEFIGPTEvent && !verbose:
		data, ok := event.Data.(*tcglog.EFIGPTData)
		if !ok {
			return event.Data
		}

		return &simpleGptEventStringer{data}
	case event.EventType == tcglog.EventTypeEFIBootServicesApplication, event.EventType == tcglog.EventTypeEFIBootServicesDriver,
		event.EventType == tcglog.EventTypeEFIRuntimeServicesDriver:
		if !verbose {
			data, ok := event.Data.(*tcglog.EFIImageLoadEvent)
			if !ok {
				return event.Data
			}
			return data.DevicePath
		}
	}

	return nil
}

type nullStringer struct{}

func (s nullStringer) String() string { return "" }

func eventDetailsStringer(event *tcglog.Event, verbose bool) fmt.Stringer {
	if out := customEventDetailsStringer(event, verbose); out != nil {
		return out
	}
	switch d := event.Data.(type) {
	case *tcglog.GrubStringEventData:
		return d
	case tcglog.OpaqueEventData:
		return d
	case tcglog.StringEventData:
		return d
	case *tcglog.SystemdEFIStubCommandline:
		return d
	default:
		if verbose {
			return event.Data
		}
		return nullStringer{}
	}
}
