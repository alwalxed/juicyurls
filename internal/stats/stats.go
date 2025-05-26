package stats

import (
	"fmt"
	"sync"
	"time"
)

// Stats holds scanning statistics
type Stats struct {
	TotalURLs      int
	SuspiciousURLs int
	InvalidURLs    int
	ProcessedURLs  int
	SkippedURLs    int
	Duration       time.Duration
	ProcessingRate float64
	mutex          sync.RWMutex
}

// UpdateStats safely updates statistics
func (s *Stats) UpdateStats(suspicious, invalid, processed, skipped int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.SuspiciousURLs += suspicious
	s.InvalidURLs += invalid
	s.ProcessedURLs += processed
	s.SkippedURLs += skipped
}

// GetStats safely reads statistics
func (s *Stats) GetStats() (int, int, int, int) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.SuspiciousURLs, s.InvalidURLs, s.ProcessedURLs, s.SkippedURLs
}

// PrintStats displays scanning statistics
func PrintStats(s *Stats) {
	fmt.Printf("\n=== Scan Statistics ===\n")
	fmt.Printf("Total URLs: %d\n", s.TotalURLs)
	fmt.Printf("Processed URLs: %d\n", s.ProcessedURLs)
	fmt.Printf("Suspicious URLs: %d\n", s.SuspiciousURLs)
	fmt.Printf("Invalid URLs: %d\n", s.InvalidURLs)
	fmt.Printf("Skipped URLs: %d\n", s.SkippedURLs)
	fmt.Printf("Duration: %v\n", s.Duration)
	if s.ProcessingRate > 0 {
		fmt.Printf("Processing Rate: %.0f URLs/sec\n", s.ProcessingRate)
	}
	fmt.Printf("Success Rate: %.2f%%\n", float64(s.SuspiciousURLs)*100/float64(max(s.ProcessedURLs, 1)))
	fmt.Printf("========================\n")
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
