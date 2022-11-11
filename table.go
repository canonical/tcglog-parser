// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/canonical/go-tpm2"
	"golang.org/x/sys/unix"

	"github.com/canonical/tcglog-parser"
)

type terminalWriter struct {
	colSz int
	w     io.Writer

	savedCursor int
}

func (w *terminalWriter) Write(data []byte) (int, error) {
	var lines [][]byte

	for i, line := range bytes.Split(data, []byte("\n")) {
		var cursor int
		if i == 0 {
			cursor = w.savedCursor
		}

		var ellipsized []byte

		if len(line)+cursor > w.colSz {
			for w.colSz-cursor < 4 {
				ellipsized = append(ellipsized, '\b')
				cursor--
			}
			ellipsized = append(ellipsized, line[0:w.colSz-cursor-4]...)
			ellipsized = append(ellipsized, []byte(" ...")...)

			w.savedCursor = w.colSz
			lines = append(lines, ellipsized)
		} else {
			w.savedCursor = cursor + len(line)
			lines = append(lines, line)
		}
	}

	if _, err := w.w.Write(bytes.Join(lines, []byte("\n"))); err != nil {
		return 0, err
	}

	return len(data), nil
}

type tableStringer struct {
	fmt.Stringer
}

func (s *tableStringer) String() string {
	str := s.Stringer.String()
	n := strings.IndexAny(str, "\n\t")
	if n == -1 {
		return str
	}
	return str[0:n] + " ..."
}

type tableFormatter struct {
	dst *tabwriter.Writer

	alg     tpm2.HashAlgorithmId
	verbose bool
}

func (f *tableFormatter) printHeader() {
	fmt.Fprint(f.dst, "PCR\tDIGEST\tTYPE")
	if f.verbose {
		fmt.Fprint(f.dst, "\tDETAILS")
	}
	fmt.Fprint(f.dst, "\n")
}

func (f *tableFormatter) printEvent(event *tcglog.Event) {
	fmt.Fprintf(f.dst, "%d\t%x\t%s", event.PCRIndex, event.Digests[f.alg], event.EventType)
	if f.verbose {
		fmt.Fprintf(f.dst, "\t%s", &tableStringer{eventDetailsStringer(event, false)})
	}
	fmt.Fprint(f.dst, "\n")
}

func (f *tableFormatter) flush() {
	f.dst.Flush()
}

func newTableFormatter(f *os.File, alg tpm2.HashAlgorithmId, verbose bool) (formatter, error) {
	var w io.Writer = f

	sz, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	switch {
	case err == syscall.ENOTTY:
		// Ignore
	case err != nil:
		return nil, err
	default:
		w = &terminalWriter{colSz: int(sz.Col), w: w}
	}

	return &tableFormatter{
		dst:     tabwriter.NewWriter(w, 0, 0, 2, ' ', 0),
		alg:     alg,
		verbose: verbose}, nil
}
