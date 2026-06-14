#!/usr/bin/env python3
# jshunter - JS secret scanner for bug bounty hunters
# Scans JavaScript files for exposed API keys, tokens, and secrets
# Usage: cat js_urls.txt | jshunter
# GitHub: github.com/YOUR_USERNAME/jshunter

import os
import sys
import re
import argparse
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False

try:
    from requests_file import FileAdapter
    HAS_FILE_ADAPTER = True
except ImportError:
    HAS_FILE_ADAPTER = False

# ─────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────
REGEXES = {
    # Google
    'google_api_key'                : r'AIza[0-9A-Za-z\-_]{35}',
    'google_oauth'                  : r'ya29\.[0-9A-Za-z\-_]+',
    # NOTE: google_captcha (reCAPTCHA site key, '6L...') removed —
    # these are PUBLIC client-side keys by design, not secrets.

    # AWS
    'aws_access_key_id'            : r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    'aws_secret_access_key'        : r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z\/+]{40}[\'"]',
    'amazon_mws_auth_token'        : r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url'               : r's3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com',

    # GitHub
    'github_pat_classic'           : r'ghp_[a-zA-Z0-9]{36}',
    'github_pat_fine_grained'      : r'github_pat_[a-zA-Z0-9_]{82}',
    'github_oauth_token'           : r'gho_[a-zA-Z0-9]{36}',
    'github_actions_token'         : r'ghs_[a-zA-Z0-9]{36}',
    'github_refresh_token'         : r'ghr_[a-zA-Z0-9]{36}',
    'github_access_token'          : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com',

    # Slack
    'slack_bot_token'              : r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
    'slack_user_token'             : r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}',
    'slack_app_token'              : r'xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-zA-Z0-9]{80,}',
    'slack_webhook'                : r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',

    # Stripe
    'stripe_secret_key'            : r'sk_live_[0-9a-zA-Z]{99}',
    'stripe_publishable_key'       : r'pk_live_[0-9a-zA-Z]{99}',
    'stripe_test_secret'           : r'sk_test_[0-9a-zA-Z]{99}',
    'stripe_restricted_key'        : r'rk_live_[0-9a-zA-Z]{24}',

    # Twilio — SIDs are hex (0-9a-f), not arbitrary alphanum
    'twilio_api_key'               : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid'           : r'AC[0-9a-f]{32}',
    'twilio_app_sid'               : r'AP[0-9a-f]{32}',

    # Firebase
    'firebase_server_key'          : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}',
    'firebase_url'                 : r'https://[a-z0-9-]+\.firebaseio\.com',

    # OpenAI / Anthropic
    'openai_api_key'               : r'sk-[a-zA-Z0-9]{48}',
    'anthropic_api_key'            : r'sk-ant-[a-zA-Z0-9\-_]{93}',

    # Discord
    'discord_bot_token'            : r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}',
    'discord_webhook'              : r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}',

    # Telegram — require surrounding context keyword to avoid false positives
    # Real tokens appear near "bot", "telegram", "api.telegram.org", or inside a URL path
    'telegram_bot_token'           : r'(?i)(?:(?:bot|telegram)[^\n]{0,40}?|https://api\.telegram\.org/bot)[0-9]{8,10}:[a-zA-Z0-9_-]{35}',

    # Payment
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret'          : r'sq0csp-[0-9A-Za-z\-_]{43}',
    'square_access_token'          : r'sq0atp-[0-9A-Za-z\-_]{22}',

    # Email
    'sendgrid_api_key'             : r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
    'mailgun_api_key'              : r'key-[0-9a-zA-Z]{32}',
    'mailchimp_api_key'            : r'[0-9a-f]{32}-us[0-9]{1,2}',

    # Shopify
    'shopify_access_token'         : r'shpat_[a-fA-F0-9]{32}',
    'shopify_shared_secret'        : r'shpss_[a-fA-F0-9]{32}',
    'shopify_custom_app'           : r'shpca_[a-fA-F0-9]{32}',

    # Other
    'npm_token'                    : r'npm_[a-zA-Z0-9]{36}',
    'databricks_token'             : r'dapi[a-f0-9]{32}',
    'heroku_api_key'               : r'[hH]eroku.*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
    'facebook_access_token'        : r'EAACEdEose0cBA[0-9A-Za-z]+',

    # Auth
    'authorization_basic'          : r'(?i)\bbasic\s+[a-zA-Z0-9+/=]{8,}',
    'authorization_bearer'         : r'(?i)\bbearer\s+[a-zA-Z0-9_\-\.+/=]{8,}',
    'authorization_api'            : r'(?i)\bapi[_\s-]?key[\s]*[=:]+[\s]*["\']?[a-zA-Z0-9_\-]{8,}["\']?',
    'json_web_token'               : r'ey[A-Za-z0-9_-]*\.ey[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+',

    # Private Keys
    'private_key_generic'          : r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----',
    'pgp_private_block'            : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

    # Generic secrets
    'generic_secret'               : r'(?i)(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|auth_key)[\s]*[=:]+[\s]*["\']([a-zA-Z0-9_\-\.@#$%^&*]{8,})["\']',
    'hardcoded_password'           : r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
}

# ─────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────
class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    GRAY   = '\033[90m'

def colorize(enabled=True):
    if not enabled or not sys.stdout.isatty():
        for attr in ['RESET','BOLD','RED','GREEN','YELLOW','CYAN','GRAY']:
            setattr(C, attr, '')

# ─────────────────────────────────────────────
# HTTP fetch
# ─────────────────────────────────────────────
def fetch(url, cookie='', proxy='', headers_str='', timeout=10):
    headers = {
        'User-Agent'      : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept'          : '*/*',
        'Accept-Language' : 'en-US,en;q=0.9',
        'Accept-Encoding' : 'gzip, deflate',
    }
    if cookie:
        headers['Cookie'] = cookie
    if headers_str:
        for part in headers_str.split('\\n'):
            if ':' in part:
                k, v = part.split(':', 1)
                headers[k.strip()] = v.strip()

    proxies = {}
    if proxy:
        proxies = {'http': proxy, 'https': proxy}

    if url.startswith('file://'):
        if not HAS_FILE_ADAPTER:
            print(f"{C.RED}[!] requests-file not installed. Cannot read local files.{C.RESET}", file=sys.stderr)
            return None
        s = requests.Session()
        s.mount('file://', FileAdapter())
        return s.get(url).content.decode('utf-8', 'replace')

    try:
        resp = requests.get(url, verify=False, headers=headers, proxies=proxies, timeout=timeout)
        return resp.content.decode('utf-8', 'replace')
    except Exception as e:
        print(f"{C.GRAY}[!] Failed to fetch {url}: {e}{C.RESET}", file=sys.stderr)
        return None

# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# Noise filters
# ─────────────────────────────────────────────

# URLs whose content is known CDN/infra noise — skip entirely
SKIP_URL_PATTERNS = [
    r'cdn-cgi/challenge-platform',
    r'cdn-cgi/zaraz',
    r'recaptcha/api\.js',
    r'static\.cloudflareinsights',
]

def is_noisy_url(url):
    for p in SKIP_URL_PATTERNS:
        if re.search(p, url, re.IGNORECASE):
            return True
    return False


# ── Shannon entropy ──────────────────────────
def entropy(s):
    """Shannon entropy of a string. Real secrets are typically > 3.5."""
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ── CamelCase / PascalCase word detector ─────
_CAMEL_RE = re.compile(r'(?:[A-Z][a-z]{2,}){3,}')   # e.g. AppointmentCollectionOutput

def is_camel_word(s):
    """True if value looks like a CamelCase identifier rather than a token."""
    return bool(_CAMEL_RE.search(s))


# ── Per-type validation ───────────────────────
def looks_like_real_secret(secret_type, value):
    """
    Return False if the match is almost certainly a false positive.
    Checks are cheap and ordered from fastest to most expensive.
    """

    # ── Twilio App SID (AP + 32 alphanum) ────
    # Real SIDs are all hex or high-entropy random chars; CamelCase words are FP
    if secret_type == 'twilio_app_sid':
        token = value[2:]   # strip leading 'AP'
        if is_camel_word(value):
            return False
        # Real Twilio SIDs are hex (0-9a-f) — reject if contains uppercase letters
        # beyond the 'AP' prefix  that suggest a class name
        if re.search(r'[G-Z]', token):   # hex only goes up to F
            return False
        if entropy(token) < 3.2:
            return False

    # ── Twilio Account SID (AC + 32) ─────────
    elif secret_type == 'twilio_account_sid':
        token = value[2:]
        if is_camel_word(value):
            return False
        if re.search(r'[G-Z]', token):
            return False
        if entropy(token) < 3.2:
            return False

    # ── Databricks token (dapi + 32) ─────────
    # Real tokens: dapi[a-f0-9]{32} (hex); 'dApiName...' is a camelCase var
    elif secret_type == 'databricks_token':
        token = value[4:]   # strip 'dapi'
        # Must start lowercase 'dapi', not 'dApi'
        if value[:4] != 'dapi':
            return False
        if is_camel_word(value):
            return False
        if re.search(r'[G-Z]', token):   # hex only
            return False
        if entropy(token) < 3.2:
            return False

    # ── Authorization basic/bearer/api ───────
    elif secret_type in ('authorization_basic', 'authorization_bearer', 'authorization_api'):
        # Extract the credential portion after the keyword + separator
        token_part = re.split(r'(?i)(?:basic|bearer|api[_\s-]?key)[\s=:]+', value, maxsplit=1)
        if len(token_part) < 2:
            return False
        cred = token_part[1].strip('"\'')
        if len(cred) < 12:
            return False
        # Reject if cred itself contains JS syntax chars (means we matched into code, not a value)
        if re.search(r'[{}();<>]', cred):
            return False
        # Real base64/token creds have decent entropy; plain English words don't
        if entropy(cred) < 3.0:
            return False

    # ── Generic secret / hardcoded password ──
    elif secret_type in ('generic_secret', 'hardcoded_password'):
        # Pull out the actual value part
        m = re.search(r'[=:]\s*["\']?([A-Za-z0-9_\-\.@#$%^&*]{8,})["\']?', value)
        cred = m.group(1) if m else value
        if is_camel_word(cred):
            return False
        if entropy(cred) < 3.0:
            return False

    return True


def scan(content, url=''):
    """Return list of (secret_type, matched_value) tuples."""
    if is_noisy_url(url):
        return []

    if HAS_JSBEAUTIFIER:
        try:
            if len(content) <= 1_000_000:
                content = jsbeautifier.beautify(content)
            else:
                content = content.replace(';', ';\n').replace(',', ',\n')
        except Exception:
            pass

    found = []
    seen  = set()

    for name, pattern in REGEXES.items():
        try:
            compiled = re.compile(pattern, re.VERBOSE)
            for m in compiled.finditer(content):
                value = m.group(0)
                if value in seen:
                    continue
                if not looks_like_real_secret(name, value):
                    continue
                seen.add(value)
                found.append((name, value))
        except re.error:
            continue

    return found

# ─────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────
def print_results(url, results, no_color=False):
    if not results:
        print(f"{C.GRAY}[-] {url} → nothing found{C.RESET}", file=sys.stderr)
        return

    for secret_type, value in results:
        # Truncate very long values for readability (show first 120 chars)
        display_val = value if len(value) <= 120 else value[:120] + '…'
        print(f"{C.GREEN}{url}{C.RESET} {C.GRAY}[{secret_type}]{C.RESET} {C.YELLOW}{display_val}{C.RESET}")

# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='SecretFinder — pipeline edition. Reads URLs from stdin.',
        epilog='Example: cat js.txt | secretfinder'
    )
    parser.add_argument('-c', '--cookie',   default='', help='Cookie header value')
    parser.add_argument('-p', '--proxy',    default='', help='Proxy (host:port)')
    parser.add_argument('-H', '--headers',  default='', help='Extra headers (Name:Value\\\\nName:Value)')
    parser.add_argument('-t', '--timeout',  default=10, type=int, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-color',       action='store_true', help='Disable ANSI colors')
    parser.add_argument('--only-findings',  action='store_true', help='Suppress "nothing found" messages')
    args = parser.parse_args()

    colorize(not args.no_color)

    # Read URLs from stdin
    if sys.stdin.isatty():
        print(f"{C.RED}[!] No input detected. Pipe a file: cat js.txt | secretfinder{C.RESET}", file=sys.stderr)
        sys.exit(1)

    urls = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]

    if not urls:
        print(f"{C.RED}[!] No URLs found in input.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{C.CYAN}[*] Scanning {len(urls)} URL(s)...{C.RESET}", file=sys.stderr)

    total_findings = 0
    for url in urls:
        content = fetch(url, cookie=args.cookie, proxy=args.proxy,
                        headers_str=args.headers, timeout=args.timeout)
        if content is None:
            continue

        results = scan(content, url=url)
        total_findings += len(results)

        if args.only_findings and not results:
            continue

        print_results(url, results)

    print(f"{C.CYAN}[*] Done. Total findings: {total_findings}{C.RESET}", file=sys.stderr)


if __name__ == '__main__':
    main()
