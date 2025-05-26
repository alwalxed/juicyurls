package main

import (
    "context"
    "reflect"
    "sort"
    "strings"
    "testing"
    "time"

    "github.com/alwalxed/juicyurls/suspicious"
)

// TestIsValidURL covers various valid/invalid URL cases
func TestIsValidURL(t *testing.T) {
    // longURL has length > maxURLLength
    longURL := "http://" + strings.Repeat("x", maxURLLength)
    cases := []struct {
        raw  string
        want bool
    }{
        {"http://example.com", true},
        {"https://foo.bar/baz", true},
        {"ftp://fileserver.local", true},
        // contains a dot, so considered valid by isValidURL
        {"no-scheme.com", true},
        {"justtext", false},
        {"", false},
        {longURL, false},
    }

    for _, c := range cases {
        got := isValidURL(c.raw)
        if got != c.want {
            t.Errorf("isValidURL(%q) = %v; want %v", c.raw, got, c.want)
        }
    }
}

// TestURLCheckerIsSuspicious verifies each category detection
func TestURLCheckerIsSuspicious(t *testing.T) {
    uc := &URLChecker{
        checkKeywords:   true,
        checkExtensions: true,
        checkPaths:      true,
        checkHidden:     true,
        excludePatterns: []string{"safe.com"},
    }
    // Override patterns for test determinism
    suspicious.Keywords = []string{"badword"}
    suspicious.Extensions = []string{".exe"}
    suspicious.Paths = []string{"/evil"}
    suspicious.Hidden = []string{".git"}

    tests := []struct {
        url      string
        wantFlag bool
        wantCat  string
    }{
        {"http://safe.com/badword", false, ""},
        {"http://example.com/badword", true, "keywords"},
        {"https://example.com/malware.exe", true, "extensions"},
        {"https://example.com/evil/path", true, "paths"},
        {"https://example.com/.git/config", true, "hidden"},
        {"https://example.com/clean", false, ""},
    }

    for _, tc := range tests {
        flag, cat, _ := uc.isSuspicious(tc.url)
        if flag != tc.wantFlag {
            t.Errorf("isSuspicious(%q) flag = %v; want %v", tc.url, flag, tc.wantFlag)
        }
        if cat != tc.wantCat {
            t.Errorf("isSuspicious(%q) category = %q; want %q", tc.url, cat, tc.wantCat)
        }
    }
}

// TestRemoveDuplicates ensures order is preserved and duplicates dropped
func TestRemoveDuplicates(t *testing.T) {
    input := []Result{
        {"a", "k", ""},
        {"b", "k", ""},
        {"a", "k", ""},
        {"c", "k", ""},
    }
    got := removeDuplicates(input)
    want := []Result{
        {"a", "k", ""},
        {"b", "k", ""},
        {"c", "k", ""},
    }
    if !reflect.DeepEqual(got, want) {
        t.Errorf("removeDuplicates = %v; want %v", got, want)
    }
}

// TestProcessURLs does a small end-to-end run of processURLs
func TestProcessURLs(t *testing.T) {
    urls := []string{
        "http://clean.com",
        "http://bad.com/evil",
        "http://bad.com/evil.exe",
        "://invalid-url",
    }

    uc := &URLChecker{
        checkKeywords:   false,
        checkExtensions: true,
        checkPaths:      true,
        checkHidden:     false,
    }
    suspicious.Extensions = []string{".exe"}
    suspicious.Paths = []string{"/evil"}

    cfg := &Config{workers: 2, validateURLs: true}
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    results, stats, err := processURLs(ctx, urls, uc, cfg)
    if err != nil {
        t.Fatalf("processURLs returned error: %v", err)
    }

    if stats.InvalidURLs != 1 {
        t.Errorf("InvalidURLs = %d; want 1", stats.InvalidURLs)
    }
    if stats.SuspiciousURLs != 2 {
        t.Errorf("SuspiciousURLs = %d; want 2", stats.SuspiciousURLs)
    }

    var gotURLs []string
    for _, r := range results {
        gotURLs = append(gotURLs, r.URL)
    }
    wantURLs := []string{
        "http://bad.com/evil",
        "http://bad.com/evil.exe",
    }
    sort.Strings(gotURLs)
    sort.Strings(wantURLs)
    if !reflect.DeepEqual(gotURLs, wantURLs) {
        t.Errorf("Result URLs = %v; want %v", gotURLs, wantURLs)
    }
}
