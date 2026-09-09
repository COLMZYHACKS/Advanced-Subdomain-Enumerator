# Advanced Subdomain Enumerator

A powerful, multi-threaded subdomain enumeration tool with DNS resolution, HTTP probing, wildcard detection, and intelligence gathering capabilities.

## Features

- **Multi-Threaded Scanning** - Fast subdomain discovery with configurable threads
- **DNS Resolution** - Resolves subdomains to IP addresses with multiple DNS servers
- **Wildcard Detection** - Automatically detects and filters wildcard DNS entries
- **HTTP Probing** - Checks if subdomains are live and extracts useful information
- **Banner Grabbing** - Identifies web servers and technologies
- **Title Extraction** - Gets page titles for context
- **Multiple Export Formats** - JSON, CSV, and TXT reports
- **Progress Tracking** - Real-time progress bar with batch processing
- **Comprehensive Wordlists** - Supports large wordlists (up to 1M+ entries)

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/COLMZYHACKS/Advanced-Subdomain-Enumerator.git
cd Advanced-Subdomain-Enumerator

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

#usage
python subdomain_enum.py