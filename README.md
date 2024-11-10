# JuicyURLs

A CLI tool to scan and identify suspicious URLs based on categories like keywords, extensions, paths, and hidden files.

## Installation

```bash
go install github.com/alwalxed/juicyurls@latest
```

## Usage

```
juicyurls [options]

Options:
  -h               Show help message
  -l <path>        Path to the list of URLs (required)
  -m <categories>  Comma-separated categories to check (optional)
  -o <path>        Output file path (optional)
  -e <patterns>    Comma-separated patterns to exclude (optional)

Categories: keywords, extensions, paths, hidden
By default, all categories are checked.
```

## Examples

Scan URLs:
`juicyurls -l urls.txt`

Scan specific categories:
`juicyurls -l urls.txt -m keywords,paths`

Exclude patterns:
`juicyurls -l urls.txt -e .js,.css`

Save results:
`juicyurls -l urls.txt -o suspicious_urls.txt`

## Contributing

Contributions are welcome via pull requests.

## License

[MIT License](https://github.com/alwalxed/juicyurls/blob/main/LICENSE)
