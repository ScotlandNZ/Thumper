# 🪱 Thumper

**Shai-Hulud 2.0 Detection + OSINT Recon Tool**

*"What senses do we lack that we cannot see or hear another world all around us?"*

Thumper detects indicators of compromise from the Shai-Hulud 2.0 npm supply chain attack (November 2025) while performing OSINT reconnaissance on GitHub accounts.

---

## Features

**OSINT Reconnaissance**
- Full GitHub profile enumeration
- Leaked email discovery from commits and public events
- SSH key extraction
- Organization membership mapping
- External repository contributions (attack surface analysis)

**Shai-Hulud 2.0 Detection**
- Random 18-character repository name detection
- Malicious description pattern matching (`Sha1-Hulud: The Second Coming`)
- Attack window correlation (November 21-26, 2025)
- IOC file detection (`cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`, `bun_environment.js`, `setup_bun.js`)
- Malicious workflow detection (`discussion.yaml`, `formatter_*.yml`)

**Risk Assessment**
- Exposure score calculation (0-100)
- Risk categorisation (Critical/High/Medium/Low)
- Actionable remediation guidance

**Reporting**
- Console output with colour-coded findings
- JSON export for integration with other tools
- CSV summary for spreadsheets
- HTML reports with dark theme dashboard
- Batch summary report for multi-user scans

---

## Installation

```bash
# Clone or save thumper.py
# No external dependencies beyond Python standard library + requests

pip install requests
```

---

## Usage

### Basic Scan

```bash
# Single user
python thumper.py octocat

# Multiple users
python thumper.py user1 user2 user3
```

### With GitHub Token (Recommended)

Using a token increases rate limits from 60 to 5,000 requests/hour.

```bash
python thumper.py octocat -t ghp_your_token_here
```

Generate a token at: https://github.com/settings/tokens

### Batch Mode

Create a text file with usernames (one per line):

```text
# engineering-team.txt
# Lines starting with # are ignored

octocat
torvalds
mojombo
defunkt
```

Run batch scan:

```bash
python thumper.py -f engineering-team.txt
```

### Output Options

```bash
# JSON output
python thumper.py octocat --json

# CSV output
python thumper.py octocat --csv

# HTML report
python thumper.py octocat --html

# All formats
python thumper.py octocat --json --csv --html

# Custom output directory
python thumper.py octocat -o ./reports/ --html
```

### Full Example

```bash
python thumper.py -f team.txt -t ghp_token -o results/ --html --json -v
```

This will:
1. Load usernames from `team.txt`
2. Authenticate with your GitHub token
3. Save results to `results/` directory
4. Generate HTML reports (individual + batch summary)
5. Generate JSON files
6. Show verbose output

---

## Command Reference

```
usage: thumper.py [-h] [-f FILE] [-t TOKEN] [-o OUTPUT] 
                  [--json] [--csv] [--html] [-v] 
                  [usernames ...]

positional arguments:
  usernames             GitHub username(s) to scan

optional arguments:
  -h, --help            show this help message and exit
  -f, --file FILE       File containing usernames (one per line)
  -t, --token TOKEN     GitHub personal access token
  -o, --output OUTPUT   Output directory (default: results)
  --json                Save JSON report
  --csv                 Save CSV summary
  --html                Save HTML report
  -v, --verbose         Verbose output
```

---

## Output Files

| File | Description |
|------|-------------|
| `results/<username>.json` | Full scan data in JSON format |
| `results/<username>.csv` | Summary data in CSV format |
| `results/<username>.html` | Individual HTML report |
| `results/index.html` | Batch summary dashboard (multi-user scans) |

---

## Risk Scoring

Thumper calculates an exposure score (0-100) based on:

| Factor | Weight |
|--------|--------|
| Compromised repos (Shai-Hulud confirmed) | +50 |
| Suspicious repos (potential IOCs) | +10 each |
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

## Indicators of Compromise (IOCs)

Thumper detects the following Shai-Hulud 2.0 indicators:

**Repository Patterns**
- Description containing `sha1-hulud`, `shai-hulud`, or `the second coming`
- Random 18-character alphanumeric repository names
- Repositories created between November 21-26, 2025

**Malicious Files**
- `cloud.json` - Exfiltrated cloud credentials
- `contents.json` - System info and GitHub token data
- `environment.json` - Environment variables
- `truffleSecrets.json` - Secrets found by TruffleHog
- `bun_environment.js` - Malicious payload
- `setup_bun.js` - Payload dropper

**Malicious Workflows**
- `discussion.yaml` - Backdoor for remote command execution
- `formatter_*.yml` - Secrets exfiltration workflow

---

## Remediation Steps

If Thumper finds indicators of compromise:

1. **Rotate GitHub credentials**
   - Revoke all Personal Access Tokens
   - Regenerate SSH keys
   - Enable hardware-based 2FA

2. **Rotate npm tokens**
   ```bash
   npm token revoke <token>
   npm token create
   ```

3. **Rotate cloud credentials**
   - AWS: Rotate access keys in IAM
   - Azure: Regenerate service principal secrets
   - GCP: Rotate service account keys

4. **Clean up repositories**
   - Delete suspicious repositories
   - Review and remove unauthorized workflows
   - Audit recent commits for malicious changes

5. **Secure development environment**
   - Clear npm cache: `npm cache clean --force`
   - Remove node_modules: `rm -rf node_modules`
   - Consider reimaging affected machines

6. **Review organisation access**
   - Audit organization members
   - Review third-party app authorizations
   - Check for unauthorized OAuth apps

---

## Example Output

```
============================================================
THUMPER - Shai-Hulud 2.0 Detection + OSINT Recon
"Attracts the worm. Finds the compromise."
Attack Window: November 21-26, 2025
============================================================

[*] Scanning 1 user(s)...

============================================================
THUMPER RECON: octocat
============================================================

[*] Fetching profile for octocat
[*] Found 8 repositories
[*] Searching for leaked emails in events
[*] Fetching SSH keys
[*] Fetching organization memberships
[*] Scanning 8 repos for Shai-Hulud IOCs

============================================================
PROFILE
============================================================
  Username:     octocat
  Name:         The Octocat
  Email:        N/A
  Location:     San Francisco
  Company:      @github
  Repos:        8
  Followers:    9847
  Created:      2011-01-25T18:44:36Z

============================================================
SHAI-HULUD 2.0 DETECTION
============================================================

  [✓] No Shai-Hulud IOCs detected

============================================================
EXPOSURE ASSESSMENT
============================================================

  Exposure Score: 6/100 (LOW)
```

---

## Integration Ideas

**CI/CD Pipeline**
```yaml
# GitHub Actions example
- name: Run Thumper scan
  run: |
    python thumper.py -f team.txt -t ${{ secrets.GH_TOKEN }} --json
    # Parse results and fail if critical findings
```

**Scheduled Scans**
```bash
# Cron job for weekly scans
0 9 * * 1 /usr/bin/python3 /path/to/thumper.py -f /path/to/team.txt -o /path/to/reports/ --html --json
```

**Slack Alerting**
```bash
# Pipe critical findings to Slack webhook
python thumper.py -f team.txt --json | jq 'select(.exposure_score >= 50)' | curl -X POST -H 'Content-type: application/json' -d @- $SLACK_WEBHOOK
```

---

## Credits

- Inspired by [gitrecon](https://github.com/GONZOsint/gitrecon) by GONZOsint
- Shai-Hulud IOC research from Wiz, GitGuardian, Aikido, and Check Point

---

## Disclaimer

This tool is intended for security professionals to assess their own accounts and those they have authorization to scan. Always obtain proper authorization before scanning GitHub accounts. Use responsibly.
