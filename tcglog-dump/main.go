package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chrisccoulson/tcglog-parser"
)

var (
	alg      string
	verbose  bool
	withGrub bool
)

func init() {
	flag.StringVar(&alg, "alg", "sha1", "Name of the hash algorithm to display")
	flag.BoolVar(&verbose, "verbose", false, "Display details of event data")
	flag.BoolVar(&withGrub, "with-grub", false, "Interpret measurements made by GRUB to PCR's 8 and 9")
}

func main() {
	flag.Parse()

	var algorithmId tcglog.AlgorithmId
	switch alg {
	case "sha1":
		algorithmId = tcglog.AlgorithmSha1
	case "sha256":
		algorithmId = tcglog.AlgorithmSha256
	case "sha384":
		algorithmId = tcglog.AlgorithmSha384
	case "sha512":
		algorithmId = tcglog.AlgorithmSha512
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized algorithm\n")
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

	log, err := tcglog.NewLogFromFile(file, tcglog.Options{EnableGrub: withGrub})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse log file: %v\n", err)
		os.Exit(1)
	}

	if !log.HasAlgorithm(algorithmId) {
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

		var builder strings.Builder
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
