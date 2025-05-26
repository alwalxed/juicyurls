package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alwalxed/juicyurls/suspicious"
)

const (
	maxURLLength     = 2048
	maxFileSize      = 500 * 1024 * 1024 // 500MB limit (increased)
	bufferSize       = 1024 * 1024       // 1MB buffer (increased)
	defaultTimeout   = 300 * time.Second // 5 minutes default (increased)
	maxWorkers       = 500               // Increased max workers
	progressInterval = 10000             // Report progress every 10k URLs
)

// URLChecker handles URL validation and suspicious pattern detection
type URLChecker struct {
	checkKeywords    bool
	checkExtensions  bool
	checkPaths       bool
	checkHidden      bool
	excludePatterns  []string
	excludeRegexes   []*regexp.Regexp
	keywordRegexes   []*regexp.Regexp
	extensionRegexes []*regexp.Regexp
	pathRegexes      []*regexp.Regexp
	hiddenRegexes    []*regexp.Regexp
	compiledOnce     sync.Once
}

// Config holds application configuration
type Config struct {
	filePath     string
	outputPath   string
	categories   string
	excludes     string
	workers      int
	timeout      time.Duration
	verbose      bool
	validateURLs bool
	urlChecker   URLChecker
}

// Result represents a scan result
type Result struct {
	URL      string
	Category string
	Reason   string
}

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

// isValidURL performs basic URL validation
func isValidURL(rawURL string) bool {
	if len(rawURL) == 0 || len(rawURL) > maxURLLength {
		return false
	}

	// Basic URL parsing validation
	if _, err := url.Parse(rawURL); err != nil {
		return false
	}

	// Check for common URL patterns
	return strings.HasPrefix(rawURL, "http://") ||
		strings.HasPrefix(rawURL, "https://") ||
		strings.HasPrefix(rawURL, "ftp://") ||
		strings.Contains(rawURL, ".")
}

// compileRegexes compiles all regex patterns once for better performance
func (c *URLChecker) compileRegexes() {
	c.compiledOnce.Do(func() {
		// Compile exclude patterns
		for _, pattern := range c.excludePatterns {
			if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pattern)); err == nil {
				c.excludeRegexes = append(c.excludeRegexes, regex)
			}
		}

		// Compile suspicious patterns
		if c.checkKeywords {
			for _, keyword := range suspicious.Keywords {
				if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(keyword)); err == nil {
					c.keywordRegexes = append(c.keywordRegexes, regex)
				}
			}
		}

		if c.checkExtensions {
			for _, ext := range suspicious.Extensions {
				pattern := regexp.QuoteMeta(ext) + "$"
				if regex, err := regexp.Compile("(?i)" + pattern); err == nil {
					c.extensionRegexes = append(c.extensionRegexes, regex)
				}
			}
		}

		if c.checkPaths {
			for _, path := range suspicious.Paths {
				if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(path)); err == nil {
					c.pathRegexes = append(c.pathRegexes, regex)
				}
			}
		}

		if c.checkHidden {
			for _, hidden := range suspicious.Hidden {
				if regex, err := regexp.Compile("(?i)" + regexp.QuoteMeta(hidden)); err == nil {
					c.hiddenRegexes = append(c.hiddenRegexes, regex)
				}
			}
		}
	})
}

// isSuspicious checks if a URL matches suspicious patterns
func (c *URLChecker) isSuspicious(rawURL string) (bool, string, string) {
	if rawURL == "" || len(rawURL) > maxURLLength {
		return false, "", ""
	}

	c.compileRegexes()

	// Check exclude patterns first
	for _, regex := range c.excludeRegexes {
		if regex.MatchString(rawURL) {
			return false, "", ""
		}
	}

	// Check suspicious patterns
	for _, regex := range c.keywordRegexes {
		if regex.MatchString(rawURL) {
			return true, "keywords", "Contains suspicious keyword"
		}
	}

	for _, regex := range c.extensionRegexes {
		if regex.MatchString(rawURL) {
			return true, "extensions", "Suspicious file extension"
		}
	}

	for _, regex := range c.pathRegexes {
		if regex.MatchString(rawURL) {
			return true, "paths", "Suspicious path pattern"
		}
	}

	for _, regex := range c.hiddenRegexes {
		if regex.MatchString(rawURL) {
			return true, "hidden", "Hidden file or directory"
		}
	}

	return false, "", ""
}

// worker processes URLs from the input channel with improved error handling
func worker(ctx context.Context, id int, urls <-chan string, results chan<- Result,
	checker *URLChecker, config *Config, stats *Stats, wg *sync.WaitGroup) {
	defer wg.Done()

	localStats := struct {
		suspicious, invalid, processed, skipped int
	}{}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			stats.UpdateStats(localStats.suspicious, localStats.invalid, localStats.processed, localStats.skipped)
			return
		case <-ticker.C:
			// Periodically update global stats
			stats.UpdateStats(localStats.suspicious, localStats.invalid, localStats.processed, localStats.skipped)
			localStats = struct{ suspicious, invalid, processed, skipped int }{}
		case rawURL, ok := <-urls:
			if !ok {
				stats.UpdateStats(localStats.suspicious, localStats.invalid, localStats.processed, localStats.skipped)
				return
			}

			// Skip empty URLs quickly
			if strings.TrimSpace(rawURL) == "" {
				localStats.skipped++
				continue
			}

			if config.validateURLs && !isValidURL(rawURL) {
				localStats.invalid++
				localStats.processed++
				continue
			}

			if suspicious, category, reason := checker.isSuspicious(rawURL); suspicious {
				select {
				case results <- Result{
					URL:      rawURL,
					Category: category,
					Reason:   reason,
				}:
					localStats.suspicious++
				case <-ctx.Done():
					stats.UpdateStats(localStats.suspicious, localStats.invalid, localStats.processed, localStats.skipped)
					return
				}
			}
			localStats.processed++
		}
	}
}

// processURLs processes URLs concurrently with progress reporting
func processURLs(ctx context.Context, urls []string, checker *URLChecker,
	config *Config) ([]Result, *Stats, error) {
	stats := &Stats{
		TotalURLs: len(urls),
	}

	startTime := time.Now()
	defer func() {
		stats.Duration = time.Since(startTime)
		if stats.Duration.Seconds() > 0 {
			stats.ProcessingRate = float64(stats.ProcessedURLs) / stats.Duration.Seconds()
		}
	}()

	if len(urls) == 0 {
		return nil, stats, nil
	}

	numWorkers := config.workers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > maxWorkers {
		numWorkers = maxWorkers
	}

	// Optimize worker count based on workload
	if len(urls) < 1000 {
		numWorkers = min(numWorkers, len(urls)/10+1)
	}

	if config.verbose {
		fmt.Printf("Processing %d URLs with %d workers...\n", len(urls), numWorkers)
	}

	// Use buffered channels to reduce blocking
	urlChan := make(chan string, numWorkers*4)
	resultsChan := make(chan Result, numWorkers*2)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, i, urlChan, resultsChan, checker, config, stats, &wg)
	}

	// Progress reporting goroutine
	var progressWG sync.WaitGroup
	if config.verbose {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Fix: Use blank identifier for unused return values
					suspiciousCount, _, processedCount, _ := stats.GetStats()
					elapsed := time.Since(startTime)
					rate := float64(processedCount) / elapsed.Seconds()
					fmt.Printf("Progress: %d/%d processed (%.1f%%), %d suspicious, %.0f URLs/sec\n",
						processedCount, len(urls), float64(processedCount)*100/float64(len(urls)),
						suspiciousCount, rate)
				}
			}
		}()
	}

	// Send URLs to workers with batching
	go func() {
		defer close(urlChan)
		batch := make([]string, 0, 100)

		for i, url := range urls {
			batch = append(batch, url)

			// Send batch or when we reach the end
			if len(batch) >= 100 || i == len(urls)-1 {
				for _, batchURL := range batch {
					select {
					case <-ctx.Done():
						return
					case urlChan <- batchURL:
					}
				}
				batch = batch[:0] // Reset batch
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []Result
	for result := range resultsChan {
		results = append(results, result)
	}

	progressWG.Wait()

	if config.verbose {
		// These variables are used in the fmt.Printf, so no blank identifier needed here.
		suspicious, invalid, processed, skipped := stats.GetStats()
		fmt.Printf("Final: %d processed, %d suspicious, %d invalid, %d skipped\n",
			processed, suspicious, invalid, skipped)
	}

	return results, stats, ctx.Err()
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeResults writes results to output file or stdout
func writeResults(results []Result, outputPath string, verbose bool) error {
	if len(results) == 0 {
		fmt.Println("No suspicious URLs found.")
		return nil
	}

	var writer io.Writer
	var file *os.File
	var err error

	if outputPath == "" {
		writer = os.Stdout
	} else {
		file, err = os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("error creating output file: %w", err)
		}
		defer file.Close()
		writer = file
	}

	// Sort results by URL
	sort.Slice(results, func(i, j int) bool {
		return results[i].URL < results[j].URL
	})

	for _, result := range results {
		if verbose {
			fmt.Fprintf(writer, "%s [%s: %s]\n", result.URL, result.Category, result.Reason)
		} else {
			fmt.Fprintln(writer, result.URL)
		}
	}

	if outputPath != "" {
		fmt.Printf("Results written to: %s\n", outputPath)
	}

	return nil
}

// validateFile checks if file exists and is within size limits
func validateFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("error accessing file: %w", err)
	}

	if info.Size() > maxFileSize {
		return fmt.Errorf("file too large: %d bytes (max: %d bytes)", info.Size(), maxFileSize)
	}

	return nil
}

// processFile reads and processes URLs from input file with streaming
func processFile(ctx context.Context, config *Config) error {
	if err := validateFile(config.filePath); err != nil {
		return err
	}

	file, err := os.Open(config.filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	if config.verbose {
		info, _ := file.Stat()
		fmt.Printf("Processing file: %s (%.2f MB)\n", config.filePath, float64(info.Size())/(1024*1024))
	}

	// For very large files, process in chunks
	fileInfo, _ := file.Stat()
	isLargeFile := fileInfo.Size() > 50*1024*1024 // 50MB

	if isLargeFile {
		return processLargeFile(ctx, file, config)
	}

	// Load all URLs for smaller files
	var urls []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		urls = append(urls, line)

		// Periodic context check for large number of URLs
		if lineCount%progressInterval == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if config.verbose {
				fmt.Printf("Loaded %d URLs...\n", len(urls))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	if config.verbose {
		fmt.Printf("Loaded %d URLs from %s\n", len(urls), config.filePath)
	}

	results, stats, err := processURLs(ctx, urls, &config.urlChecker, config)
	if err != nil && err != context.DeadlineExceeded {
		return fmt.Errorf("error processing URLs: %w", err)
	}

	// Remove duplicates
	results = removeDuplicates(results)

	if config.verbose {
		printStats(stats)
	}

	return writeResults(results, config.outputPath, config.verbose)
}

// processLargeFile handles very large files with streaming processing
func processLargeFile(ctx context.Context, file *os.File, config *Config) error {
	if config.verbose {
		fmt.Println("Using streaming mode for large file...")
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	// Process in chunks
	chunkSize := 50000 // Process 50k URLs at a time
	chunk := make([]string, 0, chunkSize)
	allResults := make([]Result, 0)
	totalStats := &Stats{}

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		chunk = append(chunk, line)

		// Process chunk when full
		if len(chunk) >= chunkSize {
			if config.verbose {
				fmt.Printf("Processing chunk %d-%d...\n", lineCount-len(chunk)+1, lineCount)
			}

			results, stats, err := processURLs(ctx, chunk, &config.urlChecker, config)
			if err != nil && err != context.DeadlineExceeded {
				return fmt.Errorf("error processing chunk: %w", err)
			}

			allResults = append(allResults, results...)
			totalStats.TotalURLs += stats.TotalURLs
			totalStats.ProcessedURLs += stats.ProcessedURLs
			totalStats.SuspiciousURLs += stats.SuspiciousURLs
			totalStats.InvalidURLs += stats.InvalidURLs
			totalStats.Duration += stats.Duration

			chunk = chunk[:0] // Reset chunk

			// Check context
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
	}

	// Process remaining URLs
	if len(chunk) > 0 {
		if config.verbose {
			fmt.Printf("Processing final chunk of %d URLs...\n", len(chunk))
		}

		results, stats, err := processURLs(ctx, chunk, &config.urlChecker, config)
		if err != nil && err != context.DeadlineExceeded {
			return fmt.Errorf("error processing final chunk: %w", err)
		}

		allResults = append(allResults, results...)
		totalStats.TotalURLs += stats.TotalURLs
		totalStats.ProcessedURLs += stats.ProcessedURLs
		totalStats.SuspiciousURLs += stats.SuspiciousURLs
		totalStats.InvalidURLs += stats.InvalidURLs
		totalStats.Duration += stats.Duration
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Remove duplicates from all results
	allResults = removeDuplicates(allResults)

	if config.verbose {
		printStats(totalStats)
	}

	return writeResults(allResults, config.outputPath, config.verbose)
}

// printStats displays scanning statistics
func printStats(stats *Stats) {
	fmt.Printf("\n=== Scan Statistics ===\n")
	fmt.Printf("Total URLs: %d\n", stats.TotalURLs)
	fmt.Printf("Processed URLs: %d\n", stats.ProcessedURLs)
	fmt.Printf("Suspicious URLs: %d\n", stats.SuspiciousURLs)
	fmt.Printf("Invalid URLs: %d\n", stats.InvalidURLs)
	fmt.Printf("Skipped URLs: %d\n", stats.SkippedURLs)
	fmt.Printf("Duration: %v\n", stats.Duration)
	if stats.ProcessingRate > 0 {
		fmt.Printf("Processing Rate: %.0f URLs/sec\n", stats.ProcessingRate)
	}
	fmt.Printf("Success Rate: %.2f%%\n", float64(stats.SuspiciousURLs)*100/float64(max(stats.ProcessedURLs, 1)))
	fmt.Printf("========================\n")
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// removeDuplicates removes duplicate URLs while preserving order
func removeDuplicates(results []Result) []Result {
	seen := make(map[string]struct{}, len(results))
	unique := make([]Result, 0, len(results))

	for _, result := range results {
		if _, exists := seen[result.URL]; !exists {
			seen[result.URL] = struct{}{}
			unique = append(unique, result)
		}
	}

	return unique
}

// printUsage displays usage information
func printUsage() {
	fmt.Println("JuicyURLs - Fast and Safe URL Security Scanner")
	fmt.Println("\nUsage: juicyurls [options]")
	fmt.Println("\nRequired:")
	fmt.Println("  -l <path>        Path to the list of URLs")
	fmt.Println("\nOptional:")
	fmt.Println("  -h               Show this help message")
	fmt.Println("  -m <categories>  Comma-separated categories to check")
	fmt.Println("  -o <path>        Output file path (default: stdout)")
	fmt.Println("  -e <patterns>    Comma-separated patterns to exclude")
	fmt.Println("  -w <number>      Number of worker goroutines (default: CPU cores)")
	fmt.Println("  -t <duration>    Timeout for processing (default: 5m)")
	fmt.Println("  -v               Verbose output with statistics")
	fmt.Println("  -validate        Validate URL format before processing")
	fmt.Println("\nCategories: keywords, extensions, paths, hidden")
	fmt.Println("Default: all categories are checked")
	fmt.Println("\nExamples:")
	fmt.Println("  juicyurls -l urls.txt -o results.txt -v")
	fmt.Println("  juicyurls -l urls.txt -m keywords,paths -e cdn,static")
	fmt.Println("  juicyurls -l urls.txt -w 8 -t 60s")
}

func main() {
	config := &Config{}
	var timeoutStr string
	var showHelp bool

	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.StringVar(&config.filePath, "l", "", "Path to URL list file")
	flag.StringVar(&config.categories, "m", "", "Categories to check")
	flag.StringVar(&config.outputPath, "o", "", "Output file path")
	flag.StringVar(&config.excludes, "e", "", "Exclude patterns")
	flag.IntVar(&config.workers, "w", 0, "Number of workers (default: CPU cores)")
	flag.StringVar(&timeoutStr, "t", "300s", "Processing timeout (default: 5m)")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.validateURLs, "validate", false, "Validate URL format")

	flag.Parse()

	if showHelp || config.filePath == "" {
		printUsage()
		os.Exit(0)
	}

	// Parse timeout
	var err error
	config.timeout, err = time.ParseDuration(timeoutStr)
	if err != nil {
		log.Fatalf("Invalid timeout format: %v", err)
	}

	// Initialize URL checker with default settings
	config.urlChecker = URLChecker{
		checkKeywords:   true,
		checkExtensions: true,
		checkPaths:      true,
		checkHidden:     true,
	}

	// Parse exclude patterns
	if config.excludes != "" {
		config.urlChecker.excludePatterns = strings.Split(config.excludes, ",")
		for i, pattern := range config.urlChecker.excludePatterns {
			config.urlChecker.excludePatterns[i] = strings.TrimSpace(pattern)
		}
	}

	// Parse categories if specified
	if config.categories != "" {
		config.urlChecker = URLChecker{
			excludePatterns: config.urlChecker.excludePatterns,
		}

		categories := strings.Split(config.categories, ",")
		for _, category := range categories {
			switch strings.TrimSpace(strings.ToLower(category)) {
			case "keywords":
				config.urlChecker.checkKeywords = true
			case "extensions":
				config.urlChecker.checkExtensions = true
			case "paths":
				config.urlChecker.checkPaths = true
			case "hidden":
				config.urlChecker.checkHidden = true
			default:
				log.Fatalf("Invalid category: %s", category)
			}
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()

	// Process file
	if err := processFile(ctx, config); err != nil {
		log.Fatalf("Error: %v", err)
	}
}