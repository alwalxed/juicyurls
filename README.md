# JuicyURLs

A powerful and fast CLI tool for scanning and identifying **suspicious URLs**. It helps you pinpoint potentially malicious or unwanted links by checking against categories like **keywords**, **file extensions**, **suspicious paths**, and **hidden files**.

## Features

- **Multi-category Scanning:** Detects suspicious URLs based on:
  - **Keywords:** Common terms found in phishing or malicious links.
  - **Extensions:** Risky file extensions (e.g., `.exe`, `.dll`).
  - **Paths:** Suspicious directory structures or patterns.
  - **Hidden:** URLs pointing to hidden files or directories.
- **High Performance:** Leverages **Go's concurrency** for fast processing of large URL lists.
- **Configurable Workers:** Adjust the number of concurrent workers to optimize scan speed based on your system resources.
- **Timeout Functionality:** Set a processing timeout to prevent scans from running indefinitely.
- **URL Validation:** Optionally validate the basic format of URLs before processing.
- **Flexible Output:** Print suspicious URLs to **stdout** or save them to a **file**.
- **Exclusion Patterns:** Define patterns to **exclude** specific URLs from the scan.
- **Verbose Output:** Get detailed statistics about your scan, including total URLs, suspicious URLs found, and processing duration.

## Installation

```bash
go install github.com/alwalxed/juicyurls@latest
```

## Usage

```Plaintext
juicyurls [options]

Required:
  -l <path>        Path to the list of URLs

Optional:
  -h               Show this help message
  -m <categories>  Comma-separated categories to check (e.g., "keywords,paths").
                   Default: all categories are checked.
  -o <path>        Output file path (default: stdout)
  -e <patterns>    Comma-separated patterns to exclude (e.g., "cdn.example.com,.js").
  -w <number>      Number of worker goroutines (default: CPU cores).
  -t <duration>    Timeout for processing (e.g., "30s", "1m"). Default: 30s.
  -v               Enable verbose output with scan statistics.
  -validate        Validate URL format before processing.
```

## Categories

By default, all categories are checked if -m is not specified.

- keywords: Checks for suspicious keywords in the URL.
- extensions: Checks for suspicious file extensions.
- paths: Checks for suspicious path patterns.
- hidden: Checks for URLs pointing to hidden files or directories.

## Examples

```bash
# Basic scan of URLs from a file, output to console
juicyurls -l urls.txt

# Scan specific categories and save results to a file
juicyurls -l urls.txt -m keywords,paths -o suspicious_urls.txt

# Scan with verbose output, showing statistics
juicyurls -l urls.txt -v

# Exclude specific patterns (e.g., CDN links or common file types)
juicyurls -l urls.txt -e cdn.example.com,.css,.js

# Increase the number of workers and set a longer timeout
juicyurls -l urls.txt -w 16 -t 2m

# Validate URL format before processing
juicyurls -l urls.txt -validate
```

## Contributing

Contributions are very welcome! Feel free to submit pull requests for bug fixes, new features, or improvements.

## License

This project is licensed under the [MIT](https://github.com/alwalxed/juicyurls/blob/main/LICENSE) License.
