// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	efi "github.com/canonical/go-efilib"

	"github.com/canonical/tcglog-parser"
)

var shimLockGuid = efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23})

type varDescriptor efi.VariableDescriptor

func (d varDescriptor) String() string {
	switch d.GUID {
	case efi.GlobalVariable, efi.ImageSecurityDatabaseGuid, shimLockGuid:
		return d.Name
	default:
		return fmt.Sprintf("%s-%s", d.Name, d.GUID)
	}
}

type bootOrderVariableStringer []byte

func (s bootOrderVariableStringer) String() string {
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

type bootOptionVariableStringer struct {
	verbose bool
	name    string
	data    []byte
}

func (s *bootOptionVariableStringer) String() string {
	opt, err := efi.ReadLoadOption(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid load option for %s: %v", s.name, err)
	}

	if s.verbose {
		return fmt.Sprintf("%s: %v", s.name, opt)
	}
	return fmt.Sprintf("%s: %s", s.name, opt.Description)
}

type boolVariableStringer struct {
	desc varDescriptor
	data []byte
}

func (s *boolVariableStringer) String() string {
	switch {
	case bytes.Equal(s.data, []byte{0}):
		return fmt.Sprintf("%s: 0", s.desc)
	case bytes.Equal(s.data, []byte{1}):
		return fmt.Sprintf("%s: 1", s.desc)
	default:
		return fmt.Sprintf("Invalid %s boolean payload", s.desc)
	}
}

type dbVariableStringer struct {
	desc    varDescriptor
	data    []byte
	verbose bool
}

func (s *dbVariableStringer) String() string {
	db, err := efi.ReadSignatureDatabase(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid signature database for %s: %v", s.desc, err)
	}

	str := fmt.Sprintf("%s:", s.desc)

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
	desc    varDescriptor
	data    []byte
	verbose bool
}

func (s *variableAuthorityStringer) String() string {
	var owner efi.GUID
	data := s.data[copy(owner[:], s.data):]

	switch len(s.data) {
	case 36, 44, 48, 64, 80:
		return fmt.Sprintf("hash: %x, owner: %s, source: %s", data, owner, s.desc)
	default:
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			// Shim doesn't log a EFI_SIGNATURE_DATA when doing verification
			// with its vendor cert.
			cert, err = x509.ParseCertificate(s.data)
			if err != nil {
				return fmt.Sprintf("Invalid authority event for %s - not a hash or X509 certificate: %v", s.desc, err)
			}
			if !s.verbose {
				return fmt.Sprintf("subject: \"%s\", source: %s", cert.Subject, s.desc)
			}
			return fmt.Sprintf("subject: \"%s\", fingerprint: %x, source: %s", cert.Subject, sha1.Sum(cert.Raw), s.desc)
		}
		if !s.verbose {
			return fmt.Sprintf("subject: \"%s\", owner: %s, source: %s", cert.Subject, owner, s.desc)
		}
		return fmt.Sprintf("subject: \"%s\", fingerprint: %x, owner: %s, source: %s", cert.Subject, sha1.Sum(cert.Raw), owner, s.desc)
	}
}

type stringVariableStringer struct {
	desc varDescriptor
	data []byte
}

func (s stringVariableStringer) String() string {
	return fmt.Sprintf("%s: %s", s.desc, string(s.data))
}

type simpleGptEventStringer struct {
	data *tcglog.EFIGPTData
}

func (s *simpleGptEventStringer) String() string {
	return fmt.Sprint("DiskGUID: ", s.data.Hdr.DiskGUID)
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
			return bootOrderVariableStringer(varData.VariableData)
		}

		return &bootOptionVariableStringer{verbose, varData.UnicodeName, varData.VariableData}
	case event.EventType == tcglog.EventTypeEFIVariableDriverConfig:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return event.Data
		}
		if varData.VariableName == efi.GlobalVariable {
			switch varData.UnicodeName {
			case "SecureBoot", "DeployedMode", "AuditMode":
				return &boolVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData}
			}
		}
		return &dbVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData, verbose}
	case event.EventType == tcglog.EventTypeEFIVariableAuthority:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return event.Data
		}
		if varData.VariableName == shimLockGuid {
			// XXX: Ideally these events would have a type of EV_EFI_VARIABLE_DRIVER_CONFIG
			switch varData.UnicodeName {
			case "MokSBState":
				return &boolVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData}
			case "SbatLevel":
				return stringVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData}
			}
		}

		return &variableAuthorityStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData, verbose}
	case (event.EventType == tcglog.EventTypeEFIGPTEvent || event.EventType == tcglog.EventTypeEFIGPTEvent2) && !verbose:
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
	if _, isErr := event.Data.(error); isErr && !verbose {
		return nullStringer{}
	}
	return event.Data
}
