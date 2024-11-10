package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/alwalxed/juicyurls/suspicious"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	maxURLLength = 2048
)

type URLChecker struct {
	checkKeywords   bool
	checkExtensions bool
	checkPaths      bool
	checkHidden     bool
	excludePatterns []string
}

type Config struct {
	filePath    string
	outputPath  string
	categories  string
	excludes    string
	urlChecker  URLChecker
}

func (c *URLChecker) isSuspicious(url string) bool {
	if url == "" || len(url) > maxURLLength {
		return false
	}

	urlLower := strings.ToLower(strings.TrimSpace(url))

	// Check excludes first
	for _, exclude := range c.excludePatterns {
		if strings.Contains(urlLower, strings.ToLower(exclude)) {
			return false
		}
	}

	if c.checkKeywords {
		for _, keyword := range suspicious.Keywords {
			if strings.Contains(urlLower, keyword) {
				return true
			}
		}
	}

	if c.checkExtensions {
		for _, ext := range suspicious.Extensions {
			if strings.HasSuffix(urlLower, ext) {
				return true
			}
		}
	}

	if c.checkPaths {
		for _, path := range suspicious.Paths {
			if strings.Contains(urlLower, path) {
				return true
			}
		}
	}

	if c.checkHidden {
		for _, hiddenFile := range suspicious.Hidden {
			if strings.Contains(urlLower, hiddenFile) {
				return true
			}
		}
	}

	return false
}

func processURLs(urls []string, checker *URLChecker, numWorkers int) []string {
	var (
		wg             sync.WaitGroup
		mutex          sync.Mutex
		suspiciousURLs []string
		urlChan        = make(chan string, len(urls))
	)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				if checker.isSuspicious(url) {
					mutex.Lock()
					suspiciousURLs = append(suspiciousURLs, url)
					mutex.Unlock()
				}
			}
		}()
	}

	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	return suspiciousURLs
}

func writeResults(urls []string, outputPath string) error {
	if len(urls) == 0 {
		fmt.Println("No suspicious URLs found.")
		return nil
	}

	if outputPath == "" {
		for _, url := range urls {
			fmt.Println(url)
		}
		return nil
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	for _, url := range urls {
		if _, err := fmt.Fprintln(file, url); err != nil {
			return fmt.Errorf("error writing to output file: %v", err)
		}
	}

	fmt.Printf("Results written to: %s\n", outputPath)
	return nil
}

func processFile(config *Config) error {
	file, err := os.Open(config.filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		if url := strings.TrimSpace(scanner.Text()); url != "" {
			if len(url) <= maxURLLength {
				urls = append(urls, url)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	suspiciousURLs := processURLs(urls, &config.urlChecker, 4)
	sort.Strings(suspiciousURLs)
	uniqueURLs := removeDuplicates(suspiciousURLs)

	return writeResults(uniqueURLs, config.outputPath)
}

func removeDuplicates(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	uniqueURLs := make([]string, 0, len(urls))

	for _, url := range urls {
		if _, exists := seen[url]; !exists {
			seen[url] = struct{}{}
			uniqueURLs = append(uniqueURLs, url)
		}
	}
	return uniqueURLs
}

func printUsage() {
	fmt.Println("Usage: juicyurls [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -h               Show this help message")
	fmt.Println("  -l <path>        Path to the list of URLs (required)")
	fmt.Println("  -m <categories>  Comma-separated list of categories (optional)")
	fmt.Println("  -o <path>        Output file path (optional)")
	fmt.Println("  -e <patterns>    Comma-separated patterns to exclude (optional)")
	fmt.Println("\nCategories: keywords, extensions, paths, hidden")
	fmt.Println("By default, all categories are checked.")
	os.Exit(0)
}

func main() {
	config := &Config{}

	flag.Usage = printUsage
	flag.StringVar(&config.filePath, "l", "", "")
	flag.StringVar(&config.categories, "m", "", "")
	flag.StringVar(&config.outputPath, "o", "", "")
	flag.StringVar(&config.excludes, "e", "", "")
	flag.Parse()

	if len(os.Args) < 2 || config.filePath == "" {
		printUsage()
	}

	// set default checking configuration
	config.urlChecker = URLChecker{
		checkKeywords:   true,
		checkExtensions: true,
		checkPaths:      true,
		checkHidden:     true,
	}

	// handle excludes
	if config.excludes != "" {
		config.urlChecker.excludePatterns = strings.Split(config.excludes, ",")
	}

	if config.categories != "" {
		config.urlChecker = URLChecker{
			excludePatterns: config.urlChecker.excludePatterns, // preserve excludes
		}
		categories := strings.Split(config.categories, ",")
		for _, category := range categories {
			switch strings.TrimSpace(category) {
			case "keywords":
				config.urlChecker.checkKeywords = true
			case "extensions":
				config.urlChecker.checkExtensions = true
			case "paths":
				config.urlChecker.checkPaths = true
			case "hidden":
				config.urlChecker.checkHidden = true
			default:
				printUsage()
			}
		}
	}

	if err := processFile(config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}