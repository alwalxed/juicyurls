package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"juicyurls/config"
	"juicyurls/internal/checker"
	"juicyurls/internal/processor"
)

func printUsage() {
	fmt.Println("JuicyURLs - Fast and Safe URL Security Scanner")
	// … same as before …
}

func main() {
	cfg := &config.Config{}
	var timeoutStr string
	var showHelp bool

	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.StringVar(&cfg.FilePath, "l", "", "Path to URL list file")
	flag.StringVar(&cfg.Categories, "m", "", "Categories to check")
	flag.StringVar(&cfg.OutputPath, "o", "", "Output file path")
	flag.StringVar(&cfg.Excludes, "e", "", "Exclude patterns")
	flag.IntVar(&cfg.Workers, "w", 0, "Number of worker goroutines (default: CPU cores)")
	flag.StringVar(&timeoutStr, "t", "300s", "Processing timeout (default: 5m, zero = no timeout)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&cfg.ValidateURLs, "validate", false, "Validate URL format")
	flag.Parse()

	if showHelp || cfg.FilePath == "" {
		printUsage()
		os.Exit(0)
	}

	// Parse timeout
	var err error
	cfg.Timeout, err = time.ParseDuration(timeoutStr)
	if err != nil {
		log.Fatalf("Invalid timeout format: %v", err)
	}

	// Init URLChecker
	cfg.URLChecker = checker.NewURLChecker(cfg.Categories, cfg.Excludes)

	// Build context: use no timeout if cfg.Timeout==0
	var ctx context.Context
	var cancel context.CancelFunc
	if cfg.Timeout == 0 {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
	}
	defer cancel()

	// Run
	if err := processor.ProcessFile(ctx, cfg); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			if cfg.Verbose {
				log.Printf("⏱ Timeout reached, partial results in %s\n", cfg.OutputPath)
			}
			os.Exit(0)
		}
		log.Fatalf("Error: %v", err)
	}
}
