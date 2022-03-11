// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"crypto"
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
	name string
	data []byte
}

func (s *bootOptionStringer) String() string {
	opt, err := efi.ReadLoadOption(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid load option for %s: %v", s.name, err)
	}

	return fmt.Sprintf("%s: %v", s.name, opt)
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
	name string
	data []byte
}

func (s *variableDriverConfigDbStringer) String() string {
	db, err := efi.ReadSignatureDatabase(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid signature database for %s: %v", s.name, err)
	}
	if len(db) == 1 && len(db[0].Signatures) == 1 && db[0].Type == efi.CertX509Guid {
		cert, err := x509.ParseCertificate(db[0].Signatures[0].Data)
		if err != nil {
			return fmt.Sprintf("Invalid X509 certificate in signature database %s: %v", s.name, err)
		}
		h := crypto.SHA256.New()
		h.Write(cert.RawTBSCertificate)
		return fmt.Sprintf("%-4s subject=\"%v\" fingerprint=%x", s.name+":", cert.Subject, h.Sum(nil))
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

	return str
}

func eventDetailsStringer(event *tcglog.Event) fmt.Stringer {
	switch {
	case event.EventType == tcglog.EventTypeEFIVariableBoot, event.EventType == tcglog.EventTypeEFIVariableBoot2:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			// Return the invalid event data
			return event.Data
		}
		if varData.VariableName != efi.GlobalVariable {
			// Unexpected GUID - just use the standard variable printer
			return event.Data
		}

		if varData.UnicodeName == "BootOrder" {
			return bootOrderStringer(varData.VariableData)
		}

		return &bootOptionStringer{varData.UnicodeName, varData.VariableData}
	case event.EventType == tcglog.EventTypeEFIVariableDriverConfig:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			// Return the invalid event data
			return event.Data
		}
		if varData.VariableName == efi.ImageSecurityDatabaseGuid {
			return &variableDriverConfigDbStringer{varData.UnicodeName, varData.VariableData}
		}
		if varData.VariableName != efi.GlobalVariable {
			// Unexpected GUID - just use the standard variable printer
			return event.Data
		}
		switch varData.UnicodeName {
		case "SecureBoot", "DeployedMode", "AuditMode":
			return &variableDriverConfigBoolStringer{varData.UnicodeName, varData.VariableData}
		default:
			return &variableDriverConfigDbStringer{varData.UnicodeName, varData.VariableData}
		}
	default:
		return event.Data
	}
}
