package config

import (
	"time"

	"juicyurls/internal/checker"
)

const (
	MaxURLLength     = 2048
	MaxFileSize      = 500 * 1024 * 1024 // 500MB limit (increased)
	BufferSize       = 1024 * 1024       // 1MB buffer (increased)
	DefaultTimeout   = 300 * time.Second // 5 minutes default (increased)
	MaxWorkers       = 500               // Increased max workers
	ProgressInterval = 10000             // Report progress every 10k URLs
)

// Config holds application configuration
type Config struct {
	FilePath     string
	OutputPath   string
	Categories   string
	Excludes     string
	Workers      int
	Timeout      time.Duration
	Verbose      bool
	ValidateURLs bool
	URLChecker   *checker.URLChecker // Use pointer for URLChecker
}
