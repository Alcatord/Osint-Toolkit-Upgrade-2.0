# 🔍 OSINT Analyzer — Open Source Analysis Tool

<div align="center">

```

██████╗ ███████╗██╗███╗ ██╗███████╗
██╔═══██╗██╔════╝██║████╗ ██║╚══██╔══╝

██║ ██║███████╗██║██╔██╗ ██║ ██║
██║ ██║╚════██║██║██║╚██╗██║ ██║
╚██████╔╝███████║██║██║ ╚████║ ██║
╚═════╝ ╚═════╝╚═╝╚═╝ ╚═══╝ ╚═╝
```

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)
![Platforms Checked](https://img.shields.io/badge/Platforms%20Checked-100%2B-orange?style=flat-square)

**Open Source Python Digital Presence Analyzer**

No API Keys — No Registration — Works Immediately

</div>

---

## ⚠️ Legal and Ethical Notice

> This tool is intended **exclusively** for the following legitimate uses:

> - Checking your own digital presence

> - Penetration and security testing **with prior written permission** from the target

> - Academic and security research

> - Investigative journalism in accordance with local laws

>
> **It is prohibited** to use the tool to harass or track individuals without permission or to violate their privacy.

> The user is solely and fully legally responsible for any use.

---

## 📋 Contents
- [Features](#-Features)
- [Requirements](#-Requirements)
- [Installation](#-Installation)
- [How-to-Use](#-How-to-Use)
- [Modules](#-Modules)
- [Examples](#-Practical-Examples)
- [Report Formats](#-Report-Formats)
- [Project Structure](#-Project-Structure)
- [Resources Used](#-Resources-Used)
- [Contribution](#-Contribution)

---

## ✨ Features

| Feature | Details |

|--------|----------|

| 🔎 Username Scanning | Over 100 Platforms in Parallel |

| 📧 Email Analysis | MX, Gravatar, Associated Services |

| 🌐 Domain Analysis | WHOIS, DNS, SSL, Subdomains |

| 👤 People Search | Google Dorks, LinkedIn, Public Websites |

| 🖥️ IP Address Analysis | Geolocation, ASN, Blocking Ranking |

| 📊 Multiple Reports | JSON / HTML / TXT |

| ⚡ High Speed ​​| Configurable Parallel Threads |

| 🧅 Tor/Proxy Support | SOCKS5 / HTTP Proxy |

| 🎨 Colorful Interface | Professional Terminal View |

| 📡 No API Keys | Works Instantly Without Registration |

---

## 🛠️ Requirements

- Python 3.8 or later
- Internet connection
### Required Libraries

```
requests>=2.28.0
```
Optional Libraries (Improves Performance):

```
dnspython>=2.3.0 # Advanced DNS resolution
python-whois>=0.8.0 # WHOIS data
beautifulsoup4>=4.12 # HTML resolution
lxml>=4.9 # Faster XML/HTML processing
```

---

## 📦 Installation

### 1. Clone the repository

```bash
`git clone https://github.com/yourusername/osint-analyzer.git
`cd osint-analyzer
```

### 2. Create a virtual environment (Recommended) (By)

```bash
python3 -m venv venv
source venv/bin/activate # Linux / macOS
venv\Scripts\activate # Windows
```

### 3. Install Libraries

```bash
pip install -r requirements.txt
```

### 4. Run the Tool

```bash
python3 osint.py --help
```

---

## 🚀 How to Use It

### Basic Syntax

```bash
python3 osint.py -t <target> [options]
```

### Full Options

```
Mandatory Options:

-t, --target TARGET Target: Username / Email / Domain / IP / Person Name

Optional Options:

--type TYPE Target Type: auto|username|email|domain|person|ip|url

(Default: auto — Detects automatically)

-o, --output FILE Save the report:

report.json → JSON report

report.html → Interactive HTML report

report.txt → Text report

-m, --modules MODS Specify certain modules (separated by commas)

Example: --modules github, twitter, instagram

--timeout SECS Timeout of each request in seconds (default: 10)

--threads NUM Number of parallel threads (default: 10)

--proxy URL Proxy: socks5://127.0.0.1:9050

--- no-color Disable terminal colors
-v, --verbose Show additional details
-h, --help Show help

```

---

## 📡 Modules

### 1. `username` — Checks usernames

Checks the name across **100+ platforms** in parallel:

| Category | Platforms |

|-------|---------|

| Social Media | Twitter/X, Instagram, Facebook, TikTok, Reddit, Pinterest |

| Professional | LinkedIn, AngelList, Crunchbase |

| Development | GitHub, GitLab, Bitbucket, HackerNews, Dev.to, npm, PyPI |

| Creative | Behance, Dribbble, ArtStation, Flickr, 500px |

| Media | YouTube, Vimeo, Twitch, SoundCloud, Spotify |

| Blogs | Medium, Substack, WordPress, Blogger |

| Gaming | Steam, Discord, Xbox, Roblox |

| Education | Duolingo, Coursera, Kaggle |

| Other | Linktree, Gravatar, Keybase, HuggingFace |

### 2. `email` — Email Analysis

- ✅ Format Validation
- ✅ MX Record Check (DNS over HTTPS)
- ✅ Gravatar Search (Profile Picture)
- ✅ Email Provider Identification
- ✅ Search for Accounts Associated with the Same Name
- ✅ Initial Leakage Scanning from Public Sources

### 3. `domain` — Domain Analysis

- ✅ WHOIS (Registration, Expiration, Owner)
- ✅ DNS Records (A, MX, NS, TXT, CNAME)
- ✅ SSL/TLS Information (Certificate, Expiration, Issuer)
- ✅ Subdomain Discovery (crt.sh)
- ✅ Link and Technology Checking
- ✅