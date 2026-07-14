# jshunter 🔍

A fast, pipeline-friendly JavaScript secret scanner for bug bounty hunters.

Reads JS URLs from stdin, fetches each file, and prints any discovered secrets directly to the terminal — no HTML output, no clutter.

---

## Features

- **Pipeline-native** — designed for `cat urls.txt | jshunter`
- **Low false positives** — entropy checks, CamelCase filtering, word-boundary matching, and known-noisy URL skip list
- **30+ secret types** — AWS, GitHub, Slack, Stripe, Twilio, Firebase, OpenAI, Discord, Telegram, JWT, and more
- **Burp/proxy support** — route traffic through Burp Suite with `-p`
- **Cookie/header support** — scan authenticated JS files with `-c`
- **Color-coded output** — findings stand out, status messages go to stderr

---

## Installation

```bash
git clone https://github.com/Omar-OM7/jshunter
cd jshunter
pip install -r requirements.txt
chmod +x jshunter.py
sudo ln -s $(pwd)/jshunter.py /usr/local/bin/jshunter
```

---

## Usage

```bash
# Basic usage
cat js_urls.txt | jshunter

# Only print URLs with findings (cleaner output)
cat js_urls.txt | jshunter --only-findings

# With Burp Suite
cat js_urls.txt | jshunter -p 127.0.0.1:8080

# With cookies (authenticated JS)
cat js_urls.txt | jshunter -c "session=abc123; token=xyz"

# Pipe into grep for specific secret types
cat js_urls.txt | jshunter | grep aws

# Save findings to file
cat js_urls.txt | jshunter --only-findings | tee findings.txt
```

---

## Output Format

```
https://target.com/app.js [aws_access_key_id] AKIAIOSFODNN7EXAMPLE
https://target.com/app.js [google_api_key] AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
https://target.com/main.js [json_web_token] eyJhbGciOiJIUzI1NiJ9.eyJ...
```

- **Findings** → stdout (pipeable)
- **Status messages** → stderr (invisible when piping)

---

## Options

| Flag | Description |
|------|-------------|
| `--only-findings` | Suppress "nothing found" lines |
| `-c, --cookie` | Cookie header (e.g. `"session=abc"`) |
| `-p, --proxy` | Proxy host:port (e.g. `127.0.0.1:8080`) |
| `-H, --headers` | Extra headers (`"Name:Value\nName:Value"`) |
| `-t, --timeout` | Request timeout in seconds (default: 10) |
| `--no-color` | Disable ANSI colors |

---

## Detected Secret Types

| Category | Types |
|----------|-------|
| **AWS** | Access Key ID, Secret Access Key, MWS Token, S3 URLs |
| **Google** | API Key, OAuth Token |
| **GitHub** | PAT Classic, PAT Fine-Grained, OAuth, Actions, Refresh Token |
| **Slack** | Bot Token, User Token, App Token, Webhook |
| **Stripe** | Secret Key, Publishable Key, Test Secret, Restricted Key |
| **Twilio** | API Key, Account SID, App SID |
| **Firebase** | Server Key, Database URL |
| **OpenAI / Anthropic** | API Keys |
| **Discord** | Bot Token, Webhook |
| **Telegram** | Bot Token (context-aware) |
| **Shopify** | Access Token, Shared Secret, Custom App |
| **Email** | SendGrid, Mailgun, Mailchimp |
| **Payment** | PayPal/Braintree, Square |
| **Other** | npm token, Databricks, Heroku, Facebook |
| **Auth** | Basic, Bearer, API Key, JWT |
| **Crypto** | Private Keys (RSA, EC, DSA, OpenSSH, PGP) |
| **Generic** | Hardcoded passwords, generic secrets |

---

## Recommended Workflow

```bash
# 1. Collect JS URLs
echo "https://target.com" | gau --blacklist png,jpg,gif,css | grep "\.js$" > js_urls.txt

# OR with katana
katana -u https://target.com -jc -d 3 | grep "\.js$" >> js_urls.txt

# 2. Deduplicate
sort -u js_urls.txt -o js_urls.txt

# 3. Hunt
cat js_urls.txt | jshunter --only-findings | tee findings.txt
```

---

## False Positive Reduction

jshunter includes several layers of noise filtering:

- **Noisy URL skip list** — Cloudflare challenge scripts, Zaraz, reCAPTCHA loaders are skipped entirely
- **Entropy checks** — low-entropy matches are rejected (plain words, sequential chars)
- **CamelCase detection** — rejects Salesforce/LWC schema names that match token patterns
- **Hex-strict Twilio/Databricks** — SIDs and tokens are hex-only, rejecting alphanum class names
- **Word-boundary auth headers** — `basic`/`bearer` require whitespace after them, rejecting `basicPageSchema=`
- **Case-sensitive patterns** — AWS and token prefixes are matched exactly, not case-insensitively

---

## Requirements

```
requests
requests-file
jsbeautifier
urllib3
```

---

## Credits

Inspired by [SecretFinder](https://github.com/m4ll0k/SecretFinder) by m4ll0k.  
Built with additional false-positive filtering for real-world bug bounty use.

---

## Disclaimer

This tool is intended for authorized security testing only. Only use it against targets you have explicit permission to test. The author is not responsible for any misuse.
