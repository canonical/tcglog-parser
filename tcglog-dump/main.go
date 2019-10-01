package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chrisccoulson/tcglog-parser"
)

var (
	alg      string
	verbose  bool
	withGrub bool
	pcrs     tcglog.PCRArgList
)

func init() {
	flag.StringVar(&alg, "alg", "sha1", "Name of the hash algorithm to display")
	flag.BoolVar(&verbose, "verbose", false, "Display details of event data")
	flag.BoolVar(&withGrub, "with-grub", false, "Interpret measurements made by GRUB to PCR's 8 and 9")
	flag.Var(&pcrs, "pcr", "Display events associated with the specified PCR. Can be specified multiple times")
}

func shouldDisplayEvent(event *tcglog.Event) bool {
	if len(pcrs) == 0 {
		return true
	}

	for _, pcr := range pcrs {
		if pcr == event.PCRIndex {
			return true
		}
	}

	return false
}

func main() {
	flag.Parse()

	algorithmId, err := tcglog.ParseAlgorithm(alg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "Too many arguments\n")
		os.Exit(1)
	}

	var path string
	if len(args) == 1 {
		path = args[0]
	} else {
		path = "/sys/kernel/security/tpm0/binary_bios_measurements"
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	log, err := tcglog.NewLog(file, tcglog.LogOptions{EnableGrub: withGrub})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse log file: %v\n", err)
		os.Exit(1)
	}

	if !log.Algorithms.Contains(algorithmId) {
		fmt.Fprintf(os.Stderr,
			"The log doesn't contain entries for the %s digest algorithm\n", algorithmId)
		os.Exit(1)
	}

	for {
		event, err := log.NextEvent()
		if err != nil {
			if err == io.EOF {
				break
			}

			fmt.Fprintf(os.Stderr, "Encountered an error when reading the next log event: %v\n", err)
			os.Exit(1)
		}

		if !shouldDisplayEvent(event) {
			continue
		}

		var builder bytes.Buffer
		fmt.Fprintf(&builder, "%2d %x %s", event.PCRIndex, event.Digests[algorithmId], event.EventType)
		if verbose {
			data := event.Data.String()
			if data != "" {
				fmt.Fprintf(&builder, " [ %s ]", data)
			}

		}
		if err != nil {
			fmt.Fprintf(&builder, " (WARNING: %s)", err)
		}
		fmt.Println(builder.String())
	}
}
