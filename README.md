# 🪱 Thumper

**Shai-Hulud Detection + OSINT Recon Tool (Inspired by gitrecon by GONZOsint)**

*"What senses do we lack that we cannot see or hear another world all around us?"*

```
                                                /~~\
  ____                                         /'o  |
.~  | `\             ,-~~~\~-_               ,'  _/'|
`\_/   /'\         /'`\    \  ~,             |     .'
    `,/'  |      ,'_   |   |   |`\          ,'~~\  |
     |   /`:     |  `\ /~~~~\ /   |        ,'    `.'
     | /'  |     |   ,'      `\  /`|      /'\    /
     `|   / \_ _/ `\ |         |'   `----\   |  /'
      `./'  | ~ |   ,'         |    |     |  |/'
       `\   |   /  ,'           `\ /      |/~'
         `\/_ /~ _/               `~------'
             ~~~~   The Sleeper Has Awakened!
```

Thumper detects indicators of compromise from the Shai-Hulud npm supply chain attacks (Wave 1: September 2025, Wave 2: November 2025) while performing OSINT reconnaissance on GitHub accounts.

---

## Features

**Shai-Hulud Detection**
- Known compromised npm package detection (@asyncapi, @zapier, @ensdomains, @posthog, @postman, etc.)
- GitHub search for IOC repositories with malicious descriptions
- Leaked credentials search in exfiltration repos
- Random 18-character repository name detection (Wave 2)
- Migration repository pattern detection (Wave 1)
- Malicious workflow detection (`discussion.yaml`, `shai-hulud-workflow.yml`)
- Suspicious branch detection (`shai-hulud`)
- Attack window correlation (Wave 1: Sept 14-20, Wave 2: Nov 21-26)

**OSINT Reconnaissance**
- Full GitHub profile enumeration
- Leaked email discovery from commits and public events
- SSH key extraction
- Organization membership mapping
- External repository contributions (attack surface analysis)

**Risk Assessment**
- Exposure score calculation (0-100)
- Risk categorisation (Critical/High/Medium/Low)
- Actionable remediation guidance

**Reporting**
- Console output with ASCII sandworm on detection
- JSON export for integration with other tools
- CSV summary for spreadsheets
- HTML reports with dark theme dashboard

---

## Installation

```bash
# Clone or save thumper.py
# Requires Python 3.7+ and requests library

pip install requests
```

---

## Usage

### Basic Scan

```bash
# Single GitHub user
python3 thumper.py octocat

# Multiple users
python3 thumper.py user1 user2 user3
```

### With GitHub Token (Recommended)

Using a token increases rate limits from 60 to 5,000 requests/hour.

```bash
python3 thumper.py asyncapi -t ghp_your_token_here
```

Generate a token at: https://github.com/settings/tokens

### Search by Email or Domain

Check if an email or domain appears in leaked exfiltration data:

```bash
# Search by email
python3 thumper.py -e user@company.com -t ghp_token

# Search by domain
python3 thumper.py -d company.com -t ghp_token

# Both email and domain
python3 thumper.py -e user@company.com -d company.com -t ghp_token
```

### Batch Mode

Create a text file with usernames (one per line):

```text
# team-github-users.txt
# Lines starting with # are ignored

asyncapi
zapier
ensdomains
```

Run batch scan:

```bash
python3 thumper.py -f team-github-users.txt -t ghp_token
```

### Output Options

```bash
# JSON output
python3 thumper.py asyncapi --json -t ghp_token

# CSV output
python3 thumper.py asyncapi --csv -t ghp_token

# HTML report
python3 thumper.py asyncapi --html -t ghp_token

# All formats
python3 thumper.py asyncapi --json --csv --html -t ghp_token

# Custom output directory
python3 thumper.py asyncapi -o ./reports/ --html -t ghp_token

# Verbose output
python3 thumper.py asyncapi -v -t ghp_token
```

### Full Example

```bash
python3 thumper.py -f team.txt -t ghp_token -o results/ --html --json -v
```

This will:
1. Load usernames from `team.txt`
2. Authenticate with your GitHub token
3. Save results to `results/` directory
4. Generate HTML and JSON reports
5. Show verbose output

---

## Command Reference

```
usage: thumper.py [-h] [-f FILE] [-e EMAIL] [-d DOMAIN] [-t TOKEN] 
                  [-o OUTPUT] [--json] [--csv] [--html] [-v] 
                  [usernames ...]

positional arguments:
  usernames             GitHub username(s) to scan

optional arguments:
  -h, --help            show this help message and exit
  -f, --file FILE       File containing usernames (one per line)
  -e, --email EMAIL     Search for email in leaked data
  -d, --domain DOMAIN   Search for domain in leaked data
  -t, --token TOKEN     GitHub personal access token
  -o, --output OUTPUT   Output directory (default: results)
  --json                Save JSON report
  --csv                 Save CSV summary
  --html                Save HTML report
  -v, --verbose         Verbose output
```

---

## What Thumper Detects

### Known Compromised Packages

Thumper checks if the scanned user/org maintains any of these known compromised packages:

| Package | Affected Versions |
|---------|-------------------|
| @asyncapi/cli | Multiple |
| @zapier/zapier-sdk | 0.15.5 - 0.15.7 |
| zapier-platform-core | 18.0.2 - 18.0.4 |
| zapier-platform-cli | 18.0.2 - 18.0.4 |
| @ensdomains/ensjs | 4.0.3 |
| @ensdomains/content-hash | 3.0.1 |
| @posthog/agent | 1.24.1 |
| posthog-node | Multiple |
| @postman/postman-mcp-cli | Multiple |

### IOC Patterns

**Repository Descriptions**
- `Sha1-Hulud: The Second Coming` (Wave 2)
- `Shai-Hulud Migration` (Wave 1)
- `Shai-Hulud Repository` (Wave 1)

**Malicious Files**
- `cloud.json` - Exfiltrated cloud credentials
- `contents.json` - System info and GitHub token data
- `environment.json` - Environment variables
- `trufflesecrets.json` - Secrets found by TruffleHog
- `bun_environment.js` - Malicious payload
- `setup_bun.js` - Payload dropper
- `data.json` - Wave 1 exfiltration file

**Malicious Workflows**
- `discussion.yaml` - Backdoor for remote command execution
- `formatter_*.yml` - Secrets exfiltration workflow
- `shai-hulud-workflow.yml` - Wave 1 propagation workflow

**Suspicious Branches**
- `shai-hulud` - Created by Wave 1 for propagation

**Repository Name Patterns**
- Random 18-character alphanumeric names (Wave 2 exfil repos)
- Names ending in `-migration` (Wave 1)

---

## Risk Scoring

Thumper calculates an exposure score (0-100) based on:

| Factor | Weight |
|--------|--------|
| Compromised repos (IOC confirmed) | +50 |
| Known compromised packages | +30 |
| Credentials found in exfil repos | +40 |
| Suspicious repos | +10 each |
| Leaked emails | +5 each (max 15) |
| SSH keys exposed | +3 each (max 10) |
| External contributions | +2 each (max 10) |
| Organization memberships | +3 each (max 15) |

**Risk Levels:**
- **CRITICAL** (50+): Confirmed compromise, immediate action required
- **HIGH** (30-49): Strong indicators, investigate immediately
- **MEDIUM** (15-29): Some exposure, review findings
- **LOW** (0-14): Minimal exposure detected

---

## Example Output

```
 _____ _                                 
|_   _| |__  _   _ _ __ ___  _ __   ___ _ __ 
  | | | '_ \| | | | '_ ` _ \| '_ \ / _ \ '__|
  | | | | | | |_| | | | | | | |_) |  __/ |   
  |_| |_| |_|\__,_|_| |_| |_| .__/ \___|_|   
                            |_|              
    
============================================================
THUMPER - Shai-Hulud Detection + OSINT Recon
"Attracts the worm. Finds the compromise."
Wave 1: September 14-20, 2025 | Wave 2: November 21-26, 2025
============================================================

[*] Scanning 1 user(s)...

============================================================
THUMPER RECON: asyncapi
============================================================

[+] Found 48 repositories
[*] Checking for known compromised npm packages
[!!!] COMPROMISED PACKAGE: cli (matches: @asyncapi/cli)

============================================================
SHAI-HULUD DETECTION
============================================================

                                                /~~\
  ____                                         /'o  |
.~  | `\             ,-~~~\~-_               ,'  _/'|
`\_/   /'\         /'`\    \  ~,             |     .'
    `,/'  |      ,'_   |   |   |`\          ,'~~\  |
     |   /`:     |  `\ /~~~~\ /   |        ,'    `.'
     | /'  |     |   ,'      `\  /`|      /'\    /
     `|   / \_ _/ `\ |         |'   `----\   |  /'
      `./'  | ~ |   ,'         |    |     |  |/'
       `\   |   /  ,'           `\ /      |/~'
         `\/_ /~ _/               `~------'
             ~~~~   The Sleeper Has Awakened!

  [!!!] KNOWN COMPROMISED PACKAGES: 1
    - cli (matches: @asyncapi/cli)

============================================================
EXPOSURE ASSESSMENT
============================================================

  Exposure Score: 80/100 (CRITICAL)

  [!!!] IMMEDIATE ACTION REQUIRED:
    1. Rotate ALL GitHub tokens and PATs
    2. Rotate npm tokens
    3. Rotate cloud credentials (AWS/Azure/GCP)
    4. Remove suspicious repositories
    5. Audit workflow files
    6. Enable hardware-based 2FA
    7. Consider machine reimaging
```

---

## Remediation Steps

If Thumper finds indicators of compromise:

### 1. Rotate GitHub Credentials
```bash
# Revoke all Personal Access Tokens
# Go to: https://github.com/settings/tokens

# Regenerate SSH keys
ssh-keygen -t ed25519 -C "your_email@example.com"

# Enable hardware-based 2FA
# Go to: https://github.com/settings/security
```

### 2. Rotate npm Tokens
```bash
npm token revoke <token>
npm token create
```

### 3. Rotate Cloud Credentials
- **AWS**: Rotate access keys in IAM console
- **Azure**: Regenerate service principal secrets
- **GCP**: Rotate service account keys

### 4. Clean Up Repositories
- Delete suspicious repositories with IOC descriptions
- Review and remove unauthorized workflows
- Audit recent commits for malicious changes
- Check for `shai-hulud` branches and remove them

### 5. Secure Development Environment
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules
rm -rf node_modules

# Reinstall from clean state
npm install
```

### 6. Review Organisation Access
- Audit organization members
- Review third-party app authorizations
- Check for unauthorized OAuth apps

---

## Limitations

- **GitHub removes exfil repos quickly** — Many exfiltration repositories are removed by GitHub's security team, so live searches may miss historical compromises
- **Rate limiting** — GitHub API has rate limits (60/hour unauthenticated, 5,000/hour with token)
- **Code search restrictions** — GitHub's code search API has limitations on query patterns
- **Point-in-time scan** — Results reflect current state; compromised repos may have been cleaned up

For comprehensive leaked credential checks, consider also using dedicated threat intelligence platforms that maintain historical databases of the attack data.

---

## Integration Ideas

**CI/CD Pipeline**
```yaml
# GitHub Actions example
- name: Run Thumper scan
  run: |
    pip install requests
    python thumper.py ${{ github.repository_owner }} -t ${{ secrets.GH_TOKEN }} --json
```

**Scheduled Scans**
```bash
# Cron job for weekly scans
0 9 * * 1 python3 /path/to/thumper.py -f /path/to/team.txt -t $GH_TOKEN -o /path/to/reports/ --html
```

---

## Credits

- Inspired by [gitrecon](https://github.com/GONZOsint/gitrecon) by GONZOsint
- Shai-Hulud IOC research from Wiz, GitGuardian, Aikido, Check Point, SafeDep, and ReversingLabs
- Named after the thumpers used to attract sandworms in Frank Herbert's Dune

---

## Disclaimer

This tool is intended for security professionals to assess their own accounts and those they have authorisation to scan. Always obtain proper authorisation before scanning GitHub accounts. Use responsibly.

---

## License

MIT License
