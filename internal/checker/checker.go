package checker

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/alwalxed/juicyurls/suspicious"
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

// NewURLChecker creates and initializes a new URLChecker
func NewURLChecker(categories, excludes string) *URLChecker {
	uc := &URLChecker{}

	// Parse exclude patterns
	if excludes != "" {
		uc.excludePatterns = strings.Split(excludes, ",")
		for i, pattern := range uc.excludePatterns {
			uc.excludePatterns[i] = strings.TrimSpace(pattern)
		}
	}

	// Parse categories if specified, otherwise enable all
	if categories != "" {
		cats := strings.Split(categories, ",")
		for _, category := range cats {
			switch strings.TrimSpace(strings.ToLower(category)) {
			case "keywords":
				uc.checkKeywords = true
			case "extensions":
				uc.checkExtensions = true
			case "paths":
				uc.checkPaths = true
			case "hidden":
				uc.checkHidden = true
			}
		}
	} else {
		uc.checkKeywords = true
		uc.checkExtensions = true
		uc.checkPaths = true
		uc.checkHidden = true
	}

	uc.compileRegexes() // Compile regexes upon creation

	return uc
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

// IsSuspicious checks if a URL matches suspicious patterns
func (c *URLChecker) IsSuspicious(rawURL string) (bool, string, string) {
	if rawURL == "" {
		return false, "", ""
	}

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

// IsValidURL performs basic URL validation
func IsValidURL(rawURL string) bool {
	if len(rawURL) == 0 {
		return false
	}

	// Basic URL parsing validation
	_, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check for common URL patterns
	return strings.HasPrefix(rawURL, "http://") ||
		strings.HasPrefix(rawURL, "https://") ||
		strings.HasPrefix(rawURL, "ftp://") ||
		strings.Contains(rawURL, ".")
}
