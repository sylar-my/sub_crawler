# Sub_Crawler 🌐🔍

## Overview

Sub_Crawler is a fast and flexible subdomain enumeration tool designed to help security researchers, penetration testers, and network administrators discover subdomains of a target domain quickly and efficiently.


## Features

- 🚀 **High-Performance**: Multithreaded scanning for rapid subdomain discovery
- 📋 **Flexible Wordlists**: Multiple built-in wordlist options
- 🔧 **Customizable**: Support for custom wordlists and thread configurations
- 🎯 **Easy to Use**: Simple command-line interface

## Prerequisites

- Rust programming language (latest stable version recommended)
- Optional: SecLists wordlist collection

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/sylar-my/sub_crawler.git
cd sub_crawler
```

2. Build the project:
```bash
cargo build --release
```

3. Install the binary:
```bash
cargo install --path .
```

### Binary Release

Download the latest release from the [Releases](https://github.com/sylar-my/sub_crawler/releases) page.

## Usage

### Basic Scanning

```bash
sub_crawler example.com
```

### Advanced Options

```bash
# Use top 5000 wordlist with 20 threads
sub_crawler -w top5000 -t 20 example.com

# Use a custom wordlist
sub_crawler -w custom -c /path/to/custom_wordlist.txt example.com
```

### Wordlist Options

- `light`: Default lightweight wordlist
- `top5000`: Top 5000 most common subdomain names
- `top20000`: Extended subdomain list
- `top110000`: Comprehensive subdomain collection
- `custom`: User-provided custom wordlist

## Configuration

### Environment Variable

Set the SecLists path:
```bash
export SECLISTS_PATH=/path/to/seclists
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-w, --wordlist` | Wordlist type | `light` |
| `--seclists-path` | Custom SecLists directory path | - |
| `-c, --custom-wordlist` | Path to custom wordlist | - |
| `-t, --threads` | Number of concurrent threads | `10` |

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Project Link: [https://github.com/sylar-my/sub_crawler](https://github.com/sylar-my/sub_crawler)

## Acknowledgments

- [SecLists](https://github.com/danielmiessler/SecLists)
- Rust Community
