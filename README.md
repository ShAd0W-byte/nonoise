
```markdown
# NoN0is3 - Silent Recon

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A passive-first reconnaissance tool focused on signal, not noise. Designed to collect, filter, and prioritize attack-relevant URLs.

## Features

- 🔍 **Passive Subdomain Discovery** - VirusTotal, SecurityTrails, crt.sh
- 🌐 **Multi-Source URL Collection** - Wayback Machine, CommonCrawl, AlienVault
- 🎯 **Smart Filtering** - Two-stage filtering to remove noise
- ⚡ **High Performance** - Concurrent processing with configurable workers
- 🔧 **WordPress Scanner** - Optional WordPress-specific enumeration
- 💾 **Cross-Platform** - Works on Windows, Linux, and macOS

## Installation

### From PyPI (Recommended)

```bash
pip install nonoise
```

### From Source

```bash
git clone https://github.com/yourusername/nonoise.git
cd nonoise
pip install -e .
```

### Requirements

- Python 3.8 or higher
- Internet connection
- (Optional) VirusTotal API key
- (Optional) SecurityTrails API key

## Quick Start

```bash
# Basic scan
nonoise -d example.com

# With WordPress enumeration
nonoise -d example.com -w

# Custom thread count
nonoise -d example.com -t 100

# Skip subdomain discovery
nonoise -d example.com -sd

# Interactive mode
nonoise --interactive
```

## Usage

### Command Line Options

```
nonoise [options]

Options:
  -d,  --domain              Target domain (example.com)
  -t,  --threads             Concurrent workers for URL visiting (default: 70)
  -w,  --wordpress           Enable WordPress-specific enumeration
  -sd, --skip-subdomains     Skip passive subdomain discovery
  -vapi, --virustotal-api    Set/update VirusTotal API key
  -sapi, --securitytrails-api Set/update SecurityTrails API key
  -i,  --interactive         Start interactive mode
  -h,  --help                Show help message
  -v,  --version             Show version
```

### API Keys Setup

```bash
# Set VirusTotal API key
nonoise -vapi YOUR_VT_API_KEY

# Set SecurityTrails API key
nonoise -sapi YOUR_ST_API_KEY
```

API keys are stored in `~/.config/nonoise/config.json`

### Important: Domain Format

Enter the EXACT domain format you want to scan:
- If the site uses `www.example.com` → enter `www.example.com`
- If the site uses `example.com` → enter `example.com`
- Wrong format will break subdomain enumeration

## Output

NoN0is3 generates the following outputs:

- `nonoise_output/` - Directory containing validated URLs
  - `{domain}_visited.txt` - URLs with status codes
- `subdomains_discovered.txt` - List of discovered subdomains (if enabled)
- `wordpress_results.txt` - WordPress enumeration results (if enabled)

## Architecture

### Pipeline Stages

1. **Subdomain Discovery** (Optional)
   - VirusTotal API
   - SecurityTrails API
   - crt.sh
   - Live domain validation

2. **URL Collection**
   - Wayback Machine
   - CommonCrawl (all indexes)
   - AlienVault OTX
   - Generated URLs (wordlist + cloud patterns)

3. **Filtering Stage 1**
   - Remove tracking parameters
   - Filter file extensions
   - Remove framework/CMS paths
   - Remove pagination URLs
   - Filter legal/info pages

4. **Filtering Stage 2**
   - Queue-based fan-out detection
   - Path depth analysis
   - Canonical key deduplication

5. **URL Validation**
   - Concurrent HEAD/GET requests
   - Status code validation
   - 301 redirect filtering

6. **WordPress Scanner** (Optional)
   - Async path enumeration
   - Fixed concurrency (30)
   - Top 500 WordPress paths

## Performance

- Default: 70 concurrent workers for URL visiting
- WordPress: Fixed 30 concurrent requests
- CommonCrawl: Up to 15 concurrent index queries
- Subdomain validation: 40 concurrent checks

## Configuration

Config file location: `~/.config/nonoise/config.json`

```json
{
  "virustotal_api_key": "your_key_here",
  "securitytrails_api_key": "your_key_here"
}
```

## Examples

### Basic Domain Scan

```bash
nonoise -d example.com
```

### Full Scan with WordPress

```bash
nonoise -d www.example.com -w -t 100
```

### Multiple Domains (Interactive)

```bash
nonoise --interactive
```

### Skip Subdomains, Fast Scan

```bash
nonoise -d example.com -sd -t 150
```

## Troubleshooting

### Common Issues

1. **Module not found**: Make sure you installed with `pip install -e .`
2. **Permission denied**: Check file permissions on output directories
3. **API rate limits**: Add delays or use API keys
4. **Timeout errors**: Reduce thread count with `-t` flag

### Debug Mode

Run with Python directly to see full error traces:

```bash
python -m nonoise -d example.com
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Wordlists

Place your wordlists in the `wordlists/` directory:

- `advanced-wordlist.txt` - For URL generation
- `wordpress-top500.txt` - For WordPress enumeration

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any domain you don't own.

## Credits

Created by **Sh4d0w**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v0.1.0 (2025-01-16)
- Initial release
- Cross-platform support (Windows, Linux, macOS)
- Passive subdomain discovery
- Multi-source URL collection
- Two-stage filtering system
- WordPress enumeration
- Concurrent processing
