#!/usr/bin/env python3
"""
 _____ _                                 
|_   _| |__  _   _ _ __ ___  _ __   ___ _ __ 
  | | | '_ \| | | | '_ ` _ \| '_ \ / _ \ '__|
  | | | | | | |_| | | | | | | |_) |  __/ |   
  |_| |_| |_|\__,_|_| |_| |_| .__/ \___|_|   
                            |_|              
  
Thumper - Shai-Hulud 2.0 Detection + OSINT Recon Tool
"What senses do we lack that we cannot see or hear another world all around us?"

Attracts the worm. Finds the compromise.

Features:
- Full GitHub profile enumeration
- Leaked email discovery from commits
- SSH key extraction
- Organization membership mapping
- Shai-Hulud 2.0 IOC detection
- Connected repo exposure analysis
- JSON/CSV reporting

Inspired by: https://github.com/GONZOsint/gitrecon
"""

import requests
import re
import argparse
import json
import os
from datetime import datetime
from collections import defaultdict
from typing import Optional
from dataclasses import dataclass, asdict, field

# GitHub API
GITHUB_API = "https://api.github.com"

# Shai-Hulud IOCs
SUSPICIOUS_DESCRIPTIONS = ["sha1-hulud", "shai-hulud", "the second coming"]
SUSPICIOUS_FILES = ["cloud.json", "contents.json", "environment.json", 
                    "truffleSecrets.json", "bun_environment.js", "setup_bun.js"]
SUSPICIOUS_WORKFLOWS = ["discussion.yaml", "formatter_"]
ATTACK_START = datetime(2025, 11, 21)
ATTACK_END = datetime(2025, 11, 26)


@dataclass
class GitHubProfile:
    username: str
    name: Optional[str] = None
    user_id: Optional[int] = None
    avatar_url: Optional[str] = None
    email: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    company: Optional[str] = None
    blog: Optional[str] = None
    twitter: Optional[str] = None
    followers: int = 0
    following: int = 0
    public_repos: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class ReconResults:
    profile: Optional[GitHubProfile] = None
    emails_leaked: list = field(default_factory=list)
    ssh_keys: list = field(default_factory=list)
    organizations: list = field(default_factory=list)
    repos_contributed: list = field(default_factory=list)
    shai_hulud_findings: dict = field(default_factory=dict)
    exposure_score: int = 0
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class Thumper:
    def __init__(self, token: Optional[str] = None, verbose: bool = False):
        self.token = token
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "ShaiHulud-Detector/2.0"
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
    
    def log(self, msg: str, level: str = "info"):
        icons = {"info": "[*]", "warn": "[!]", "error": "[X]", "success": "[✓]", "critical": "[!!!]"}
        if self.verbose or level in ["warn", "error", "critical"]:
            print(f"{icons.get(level, '[*]')} {msg}")

    def api_get(self, endpoint: str, params: dict = None) -> Optional[dict]:
        url = f"{GITHUB_API}{endpoint}" if endpoint.startswith("/") else endpoint
        try:
            resp = self.session.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            else:
                self.log(f"API error {resp.status_code}: {endpoint}", "warn")
                return None
        except Exception as e:
            self.log(f"Request failed: {e}", "error")
            return None

    def get_profile(self, username: str) -> Optional[GitHubProfile]:
        """Fetch full GitHub profile"""
        self.log(f"Fetching profile for {username}")
        data = self.api_get(f"/users/{username}")
        if not data:
            return None
        
        return GitHubProfile(
            username=data.get("login"),
            name=data.get("name"),
            user_id=data.get("id"),
            avatar_url=data.get("avatar_url"),
            email=data.get("email"),
            location=data.get("location"),
            bio=data.get("bio"),
            company=data.get("company"),
            blog=data.get("blog"),
            twitter=data.get("twitter_username"),
            followers=data.get("followers", 0),
            following=data.get("following", 0),
            public_repos=data.get("public_repos", 0),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )

    def get_emails_from_events(self, username: str) -> list:
        """Extract leaked emails from public events (gitrecon technique)"""
        self.log(f"Searching for leaked emails in events")
        emails = set()
        
        data = self.api_get(f"/users/{username}/events/public", {"per_page": 100})
        if not data:
            return []
        
        for event in data:
            if event.get("type") == "PushEvent":
                commits = event.get("payload", {}).get("commits", [])
                for commit in commits:
                    author = commit.get("author", {})
                    email = author.get("email", "")
                    if email and not email.endswith("@users.noreply.github.com"):
                        emails.add(email)
        
        return list(emails)

    def get_emails_from_commits(self, username: str, repos: list) -> list:
        """Deep scan repos for leaked emails in commit history"""
        self.log(f"Deep scanning commits for leaked emails")
        emails = set()
        
        for repo in repos[:10]:  # Limit to avoid rate limits
            repo_name = repo.get("name")
            commits = self.api_get(f"/repos/{username}/{repo_name}/commits", {"per_page": 30})
            if commits:
                for commit in commits:
                    commit_data = commit.get("commit", {})
                    for field in ["author", "committer"]:
                        person = commit_data.get(field, {})
                        email = person.get("email", "")
                        if email and not email.endswith("@users.noreply.github.com"):
                            emails.add(email)
        
        return list(emails)

    def get_ssh_keys(self, username: str) -> list:
        """Fetch public SSH keys"""
        self.log(f"Fetching SSH keys")
        data = self.api_get(f"/users/{username}/keys")
        if not data:
            return []
        
        return [{"id": k.get("id"), "key": k.get("key")[:50] + "..."} for k in data]

    def get_organizations(self, username: str) -> list:
        """Fetch organization memberships"""
        self.log(f"Fetching organization memberships")
        data = self.api_get(f"/users/{username}/orgs")
        if not data:
            return []
        
        return [{"login": o.get("login"), "id": o.get("id"), 
                 "url": f"https://github.com/{o.get('login')}"} for o in data]

    def get_repos(self, username: str) -> list:
        """Fetch all repositories"""
        self.log(f"Fetching repositories")
        repos = []
        page = 1
        
        while True:
            data = self.api_get(f"/users/{username}/repos", {"per_page": 100, "page": page})
            if not data:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        
        return repos

    def get_contributed_repos(self, username: str) -> list:
        """Find repos user has contributed to (potential exposure vector)"""
        self.log(f"Searching for contributed repos")
        repos = []
        
        # Search for commits by user in other repos
        data = self.api_get(f"/search/commits", {
            "q": f"author:{username}",
            "per_page": 50,
            "sort": "author-date"
        })
        
        if data and "items" in data:
            seen = set()
            for item in data["items"]:
                repo = item.get("repository", {})
                full_name = repo.get("full_name", "")
                if full_name and full_name not in seen and not full_name.startswith(f"{username}/"):
                    seen.add(full_name)
                    repos.append({
                        "full_name": full_name,
                        "url": repo.get("html_url"),
                        "owner": repo.get("owner", {}).get("login")
                    })
        
        return repos

    def check_repo_for_iocs(self, owner: str, repo_name: str, repo_data: dict) -> dict:
        """Check a single repo for Shai-Hulud IOCs"""
        findings = []
        
        # Check repo name pattern (random 18-char)
        if re.match(r'^[a-z0-9]{18}$', repo_name.lower()):
            findings.append({"type": "random_name", "detail": f"Suspicious 18-char name: {repo_name}"})
        
        # Check description
        desc = (repo_data.get("description") or "").lower()
        for pattern in SUSPICIOUS_DESCRIPTIONS:
            if pattern in desc:
                findings.append({"type": "description", "detail": f"IOC in description: {pattern}"})
        
        # Check creation date
        created = repo_data.get("created_at", "")
        in_attack_window = False
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")).replace(tzinfo=None)
            in_attack_window = ATTACK_START <= created_dt <= ATTACK_END
            if in_attack_window:
                findings.append({"type": "timing", "detail": f"Created during attack window: {created}"})
        except:
            pass
        
        # Deep check if suspicious or in attack window
        if findings or in_attack_window:
            # Check root files
            contents = self.api_get(f"/repos/{owner}/{repo_name}/contents/")
            if contents:
                for item in contents:
                    if item.get("name") in SUSPICIOUS_FILES:
                        findings.append({"type": "file", "detail": f"IOC file: {item.get('name')}"})
            
            # Check workflows
            workflows = self.api_get(f"/repos/{owner}/{repo_name}/contents/.github/workflows")
            if workflows:
                for item in workflows:
                    name = item.get("name", "").lower()
                    for pattern in SUSPICIOUS_WORKFLOWS:
                        if pattern in name:
                            findings.append({"type": "workflow", "detail": f"IOC workflow: {item.get('name')}"})
        
        return {
            "repo": f"{owner}/{repo_name}",
            "url": repo_data.get("html_url"),
            "created": created,
            "in_attack_window": in_attack_window,
            "findings": findings,
            "compromised": any("sha1-hulud" in f.get("detail", "").lower() or 
                             "second coming" in f.get("detail", "").lower() for f in findings)
        }

    def scan_for_shai_hulud(self, username: str, repos: list) -> dict:
        """Scan all repos for Shai-Hulud IOCs"""
        self.log(f"Scanning {len(repos)} repos for Shai-Hulud IOCs")
        
        results = {"compromised": [], "suspicious": [], "clean": 0}
        
        for repo in repos:
            repo_name = repo.get("name")
            check = self.check_repo_for_iocs(username, repo_name, repo)
            
            if check["compromised"]:
                results["compromised"].append(check)
                self.log(f"COMPROMISED: {repo_name}", "critical")
            elif check["findings"]:
                results["suspicious"].append(check)
                self.log(f"Suspicious: {repo_name}", "warn")
            else:
                results["clean"] += 1
        
        return results

    def calculate_exposure_score(self, results: ReconResults) -> int:
        """Calculate overall exposure risk score (0-100)"""
        score = 0
        
        # Shai-Hulud findings (highest weight)
        if results.shai_hulud_findings.get("compromised"):
            score += 50
        score += len(results.shai_hulud_findings.get("suspicious", [])) * 10
        
        # Leaked emails
        score += min(len(results.emails_leaked) * 5, 15)
        
        # SSH keys exposed
        score += min(len(results.ssh_keys) * 3, 10)
        
        # External contributions (attack surface)
        score += min(len(results.repos_contributed) * 2, 10)
        
        # Org memberships (lateral movement risk)
        score += min(len(results.organizations) * 3, 15)
        
        return min(score, 100)

    def full_recon(self, username: str) -> ReconResults:
        """Run full reconnaissance and IOC scan"""
        print(f"\n{'='*60}")
        print(f"THUMPER RECON: {username}")
        print(f"{'='*60}\n")
        
        results = ReconResults()
        
        # Profile
        results.profile = self.get_profile(username)
        if not results.profile:
            self.log(f"User {username} not found", "error")
            return results
        
        # Get repos first (needed for other scans)
        repos = self.get_repos(username)
        self.log(f"Found {len(repos)} repositories", "success")
        
        # OSINT recon
        results.emails_leaked = self.get_emails_from_events(username)
        results.emails_leaked.extend(self.get_emails_from_commits(username, repos))
        results.emails_leaked = list(set(results.emails_leaked))
        
        results.ssh_keys = self.get_ssh_keys(username)
        results.organizations = self.get_organizations(username)
        results.repos_contributed = self.get_contributed_repos(username)
        
        # Shai-Hulud scan
        results.shai_hulud_findings = self.scan_for_shai_hulud(username, repos)
        
        # Calculate risk
        results.exposure_score = self.calculate_exposure_score(results)
        
        return results

    def print_report(self, results: ReconResults):
        """Print formatted report"""
        if not results.profile:
            return
        
        p = results.profile
        print(f"\n{'='*60}")
        print("PROFILE")
        print(f"{'='*60}")
        print(f"  Username:     {p.username}")
        print(f"  Name:         {p.name or 'N/A'}")
        print(f"  Email:        {p.email or 'N/A'}")
        print(f"  Location:     {p.location or 'N/A'}")
        print(f"  Company:      {p.company or 'N/A'}")
        print(f"  Repos:        {p.public_repos}")
        print(f"  Followers:    {p.followers}")
        print(f"  Created:      {p.created_at}")
        
        if results.emails_leaked:
            print(f"\n{'='*60}")
            print(f"LEAKED EMAILS ({len(results.emails_leaked)} found)")
            print(f"{'='*60}")
            for email in results.emails_leaked:
                print(f"  • {email}")
        
        if results.ssh_keys:
            print(f"\n{'='*60}")
            print(f"SSH KEYS ({len(results.ssh_keys)} found)")
            print(f"{'='*60}")
            for key in results.ssh_keys:
                print(f"  • ID: {key['id']} - {key['key']}")
        
        if results.organizations:
            print(f"\n{'='*60}")
            print(f"ORGANIZATIONS ({len(results.organizations)} found)")
            print(f"{'='*60}")
            for org in results.organizations:
                print(f"  • {org['login']} - {org['url']}")
        
        if results.repos_contributed:
            print(f"\n{'='*60}")
            print(f"EXTERNAL CONTRIBUTIONS ({len(results.repos_contributed)} repos)")
            print(f"{'='*60}")
            for repo in results.repos_contributed[:10]:
                print(f"  • {repo['full_name']}")
        
        # Shai-Hulud findings
        sh = results.shai_hulud_findings
        print(f"\n{'='*60}")
        print("SHAI-HULUD 2.0 DETECTION")
        print(f"{'='*60}")
        
        if sh.get("compromised"):
            print(f"\n  [!!!] COMPROMISED REPOS: {len(sh['compromised'])}")
            for r in sh["compromised"]:
                print(f"\n    Repo: {r['repo']}")
                print(f"    URL:  {r['url']}")
                for f in r["findings"]:
                    print(f"      - {f['detail']}")
        
        if sh.get("suspicious"):
            print(f"\n  [!] SUSPICIOUS REPOS: {len(sh['suspicious'])}")
            for r in sh["suspicious"]:
                print(f"\n    Repo: {r['repo']}")
                print(f"    URL:  {r['url']}")
                for f in r["findings"]:
                    print(f"      - {f['detail']}")
        
        if not sh.get("compromised") and not sh.get("suspicious"):
            print("\n  [✓] No Shai-Hulud IOCs detected")
        
        # Risk score
        print(f"\n{'='*60}")
        print("EXPOSURE ASSESSMENT")
        print(f"{'='*60}")
        score = results.exposure_score
        risk = "CRITICAL" if score >= 50 else "HIGH" if score >= 30 else "MEDIUM" if score >= 15 else "LOW"
        print(f"\n  Exposure Score: {score}/100 ({risk})")
        
        if score >= 50:
            print("\n  [!!!] IMMEDIATE ACTION REQUIRED:")
            print("    1. Rotate ALL GitHub tokens and PATs")
            print("    2. Rotate npm tokens")
            print("    3. Rotate cloud credentials (AWS/Azure/GCP)")
            print("    4. Remove suspicious repositories")
            print("    5. Audit workflow files")
            print("    6. Enable hardware-based 2FA")
            print("    7. Consider machine reimaging")

    def save_json(self, results: ReconResults, filepath: str):
        """Save results to JSON"""
        data = {
            "profile": asdict(results.profile) if results.profile else None,
            "emails_leaked": results.emails_leaked,
            "ssh_keys": results.ssh_keys,
            "organizations": results.organizations,
            "repos_contributed": results.repos_contributed,
            "shai_hulud_findings": results.shai_hulud_findings,
            "exposure_score": results.exposure_score,
            "scan_timestamp": results.scan_timestamp
        }
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"\n[*] Results saved to {filepath}")

    def save_csv(self, results: ReconResults, filepath: str):
        """Save summary to CSV"""
        import csv
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Field", "Value"])
            
            if results.profile:
                writer.writerow(["Username", results.profile.username])
                writer.writerow(["Name", results.profile.name])
                writer.writerow(["Email", results.profile.email])
                writer.writerow(["Company", results.profile.company])
                writer.writerow(["Public Repos", results.profile.public_repos])
            
            writer.writerow(["Leaked Emails", ", ".join(results.emails_leaked)])
            writer.writerow(["SSH Keys", len(results.ssh_keys)])
            writer.writerow(["Organizations", ", ".join(o["login"] for o in results.organizations)])
            writer.writerow(["Compromised Repos", len(results.shai_hulud_findings.get("compromised", []))])
            writer.writerow(["Suspicious Repos", len(results.shai_hulud_findings.get("suspicious", []))])
            writer.writerow(["Exposure Score", results.exposure_score])
        
        print(f"[*] CSV saved to {filepath}")


    def save_html(self, results: ReconResults, filepath: str):
        """Generate HTML report"""
        p = results.profile
        if not p:
            self.log(f"Skipping HTML report - no profile data", "warn")
            return
        
        sh = results.shai_hulud_findings
        score = results.exposure_score
        risk = "CRITICAL" if score >= 50 else "HIGH" if score >= 30 else "MEDIUM" if score >= 15 else "LOW"
        risk_color = "#dc2626" if score >= 50 else "#f97316" if score >= 30 else "#eab308" if score >= 15 else "#22c55e"
        
        compromised_html = ""
        if sh.get("compromised"):
            for r in sh["compromised"]:
                findings = "".join(f"<li>{f['detail']}</li>" for f in r["findings"])
                compromised_html += f"""
                <div class="repo-card compromised">
                    <h4><a href="{r['url']}" target="_blank">{r['repo']}</a></h4>
                    <p class="created">Created: {r['created']}</p>
                    <ul>{findings}</ul>
                </div>"""
        
        suspicious_html = ""
        if sh.get("suspicious"):
            for r in sh["suspicious"]:
                findings = "".join(f"<li>{f['detail']}</li>" for f in r["findings"])
                suspicious_html += f"""
                <div class="repo-card suspicious">
                    <h4><a href="{r['url']}" target="_blank">{r['repo']}</a></h4>
                    <p class="created">Created: {r['created']}</p>
                    <ul>{findings}</ul>
                </div>"""
        
        emails_html = "".join(f"<li>{e}</li>" for e in results.emails_leaked) or "<li>None found</li>"
        keys_html = "".join(f"<li>ID: {k['id']} - {k['key']}</li>" for k in results.ssh_keys) or "<li>None found</li>"
        orgs_html = "".join(f'<li><a href="{o["url"]}" target="_blank">{o["login"]}</a></li>' for o in results.organizations) or "<li>None found</li>"
        contrib_html = "".join(f'<li><a href="{r["url"]}" target="_blank">{r["full_name"]}</a></li>' for r in results.repos_contributed[:15]) or "<li>None found</li>"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thumper Report - {p.username if p else 'Unknown'}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; margin-bottom: 3rem; padding: 2rem; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-radius: 1rem; border: 1px solid #334155; }}
        h1 {{ font-size: 2.5rem; color: #f59e0b; margin-bottom: 0.5rem; }}
        .tagline {{ color: #94a3b8; font-style: italic; }}
        .scan-info {{ margin-top: 1rem; color: #64748b; font-size: 0.9rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }}
        .card h3 {{ color: #f59e0b; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }}
        .card ul {{ list-style: none; }}
        .card li {{ padding: 0.5rem 0; border-bottom: 1px solid #334155; }}
        .card li:last-child {{ border-bottom: none; }}
        .card a {{ color: #38bdf8; text-decoration: none; }}
        .card a:hover {{ text-decoration: underline; }}
        .profile-header {{ display: flex; align-items: center; gap: 1.5rem; margin-bottom: 1.5rem; }}
        .avatar {{ width: 80px; height: 80px; border-radius: 50%; border: 3px solid #f59e0b; }}
        .profile-info h2 {{ color: #f1f5f9; }}
        .profile-info p {{ color: #94a3b8; }}
        .stats {{ display: flex; gap: 2rem; margin-top: 0.5rem; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 1.25rem; font-weight: bold; color: #f59e0b; }}
        .stat-label {{ font-size: 0.75rem; color: #64748b; }}
        .risk-score {{ text-align: center; padding: 2rem; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-radius: 1rem; border: 2px solid {risk_color}; margin-bottom: 2rem; }}
        .risk-score .score {{ font-size: 4rem; font-weight: bold; color: {risk_color}; }}
        .risk-score .label {{ font-size: 1.5rem; color: {risk_color}; margin-top: 0.5rem; }}
        .risk-score .subtitle {{ color: #94a3b8; margin-top: 0.5rem; }}
        .section {{ margin-bottom: 2rem; }}
        .section h2 {{ color: #f59e0b; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #334155; }}
        .repo-card {{ background: #1e293b; border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; border-left: 4px solid #64748b; }}
        .repo-card.compromised {{ border-left-color: #dc2626; background: #1e1618; }}
        .repo-card.suspicious {{ border-left-color: #f97316; background: #1e1a16; }}
        .repo-card h4 {{ margin-bottom: 0.5rem; }}
        .repo-card h4 a {{ color: #f1f5f9; }}
        .repo-card .created {{ font-size: 0.85rem; color: #64748b; margin-bottom: 0.5rem; }}
        .repo-card ul {{ margin-left: 1rem; }}
        .repo-card li {{ color: #fca5a5; font-size: 0.9rem; padding: 0.25rem 0; border: none; }}
        .remediation {{ background: linear-gradient(135deg, #7f1d1d 0%, #1e293b 100%); border: 1px solid #dc2626; border-radius: 0.75rem; padding: 1.5rem; }}
        .remediation h3 {{ color: #fca5a5; margin-bottom: 1rem; }}
        .remediation ol {{ margin-left: 1.5rem; }}
        .remediation li {{ padding: 0.5rem 0; color: #fecaca; }}
        .clean {{ text-align: center; padding: 2rem; color: #22c55e; }}
        .clean svg {{ width: 48px; height: 48px; margin-bottom: 1rem; }}
        footer {{ text-align: center; margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #334155; color: #64748b; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🪱 Thumper Report</h1>
            <p class="tagline">"Attracts the worm. Finds the compromise."</p>
            <p class="scan-info">Scan completed: {results.scan_timestamp}</p>
        </header>
        
        <div class="card" style="margin-bottom: 2rem;">
            <div class="profile-header">
                <img src="{p.avatar_url}" alt="Avatar" class="avatar">
                <div class="profile-info">
                    <h2>{p.name or p.username}</h2>
                    <p>@{p.username}</p>
                    <div class="stats">
                        <div class="stat"><div class="stat-value">{p.public_repos}</div><div class="stat-label">Repos</div></div>
                        <div class="stat"><div class="stat-value">{p.followers}</div><div class="stat-label">Followers</div></div>
                        <div class="stat"><div class="stat-value">{p.following}</div><div class="stat-label">Following</div></div>
                    </div>
                </div>
            </div>
            <p><strong>Location:</strong> {p.location or 'N/A'} | <strong>Company:</strong> {p.company or 'N/A'} | <strong>Email:</strong> {p.email or 'N/A'}</p>
        </div>
        
        <div class="risk-score">
            <div class="score">{score}</div>
            <div class="label">{risk} RISK</div>
            <div class="subtitle">Exposure Score (0-100)</div>
        </div>
        
        <div class="section">
            <h2>🐛 Shai-Hulud 2.0 Detection</h2>
            {"<div class='compromised-section'><h3 style='color: #dc2626;'>⚠️ COMPROMISED REPOSITORIES</h3>" + compromised_html + "</div>" if compromised_html else ""}
            {"<div class='suspicious-section'><h3 style='color: #f97316; margin-top: 1.5rem;'>⚡ Suspicious Repositories</h3>" + suspicious_html + "</div>" if suspicious_html else ""}
            {f"<div class='clean'><svg fill='currentColor' viewBox='0 0 20 20'><path fill-rule='evenodd' d='M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z' clip-rule='evenodd'/></svg><p>No Shai-Hulud IOCs detected</p><p style='color: #64748b;'>{sh.get('clean', 0)} repositories scanned</p></div>" if not compromised_html and not suspicious_html else ""}
        </div>
        
        {f'''<div class="remediation">
            <h3>🚨 Immediate Actions Required</h3>
            <ol>
                <li>Revoke and rotate ALL GitHub tokens and PATs immediately</li>
                <li>Rotate npm tokens (<code>npm token revoke</code>)</li>
                <li>Rotate cloud credentials (AWS, Azure, GCP)</li>
                <li>Remove suspicious repositories listed above</li>
                <li>Audit all workflow files for unauthorized changes</li>
                <li>Enable hardware-based 2FA on GitHub</li>
                <li>Consider full machine reimaging if local dev environment was affected</li>
            </ol>
        </div>''' if score >= 50 else ""}
        
        <div class="grid">
            <div class="card">
                <h3>📧 Leaked Emails</h3>
                <ul>{emails_html}</ul>
            </div>
            <div class="card">
                <h3>🔑 SSH Keys</h3>
                <ul>{keys_html}</ul>
            </div>
            <div class="card">
                <h3>🏢 Organizations</h3>
                <ul>{orgs_html}</ul>
            </div>
            <div class="card">
                <h3>🔗 External Contributions</h3>
                <ul>{contrib_html}</ul>
            </div>
        </div>
        
        <footer>
            <p>Generated by Thumper | Shai-Hulud 2.0 Detection + OSINT Recon</p>
            <p>Attack Window: November 21-26, 2025</p>
        </footer>
    </div>
</body>
</html>"""
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            f.write(html)
        print(f"[*] HTML report saved to {filepath}")

    def save_batch_html(self, all_results: dict, filepath: str):
        """Generate combined HTML report for batch scan"""
        rows = ""
        for username, results in all_results.items():
            if not results.profile:
                continue
            p = results.profile
            score = results.exposure_score
            risk = "CRITICAL" if score >= 50 else "HIGH" if score >= 30 else "MEDIUM" if score >= 15 else "LOW"
            risk_color = "#dc2626" if score >= 50 else "#f97316" if score >= 30 else "#eab308" if score >= 15 else "#22c55e"
            sh = results.shai_hulud_findings
            
            rows += f"""
            <tr>
                <td><a href="{username}.html">{username}</a></td>
                <td>{p.name or 'N/A'}</td>
                <td>{len(results.emails_leaked)}</td>
                <td>{len(results.organizations)}</td>
                <td>{len(sh.get('compromised', []))}</td>
                <td>{len(sh.get('suspicious', []))}</td>
                <td style="color: {risk_color}; font-weight: bold;">{score}</td>
                <td style="color: {risk_color}; font-weight: bold;">{risk}</td>
            </tr>"""
        
        total_users = len(all_results)
        total_compromised = sum(len(r.shai_hulud_findings.get("compromised", [])) for r in all_results.values())
        total_suspicious = sum(len(r.shai_hulud_findings.get("suspicious", [])) for r in all_results.values())
        high_risk = sum(1 for r in all_results.values() if r.exposure_score >= 30)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thumper Batch Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; margin-bottom: 3rem; padding: 2rem; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-radius: 1rem; border: 1px solid #334155; }}
        h1 {{ font-size: 2.5rem; color: #f59e0b; margin-bottom: 0.5rem; }}
        .tagline {{ color: #94a3b8; font-style: italic; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .summary-card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; text-align: center; border: 1px solid #334155; }}
        .summary-card .value {{ font-size: 2.5rem; font-weight: bold; color: #f59e0b; }}
        .summary-card .label {{ color: #94a3b8; margin-top: 0.5rem; }}
        .summary-card.danger .value {{ color: #dc2626; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.75rem; overflow: hidden; }}
        th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #334155; color: #f59e0b; font-weight: 600; }}
        tr:hover {{ background: #334155; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        footer {{ text-align: center; margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #334155; color: #64748b; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🪱 Thumper Batch Report</h1>
            <p class="tagline">"Attracts the worm. Finds the compromise."</p>
            <p style="color: #64748b; margin-top: 1rem;">Generated: {datetime.now().isoformat()}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card">
                <div class="value">{total_users}</div>
                <div class="label">Users Scanned</div>
            </div>
            <div class="summary-card danger">
                <div class="value">{total_compromised}</div>
                <div class="label">Compromised Repos</div>
            </div>
            <div class="summary-card">
                <div class="value">{total_suspicious}</div>
                <div class="label">Suspicious Repos</div>
            </div>
            <div class="summary-card danger">
                <div class="value">{high_risk}</div>
                <div class="label">High Risk Users</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Name</th>
                    <th>Leaked Emails</th>
                    <th>Orgs</th>
                    <th>Compromised</th>
                    <th>Suspicious</th>
                    <th>Score</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        
        <footer>
            <p>Generated by Thumper | Shai-Hulud 2.0 Detection + OSINT Recon</p>
            <p>Attack Window: November 21-26, 2025</p>
        </footer>
    </div>
</body>
</html>"""
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            f.write(html)
        print(f"[*] Batch HTML report saved to {filepath}")


def load_usernames_from_file(filepath: str) -> list:
    """Load usernames from a text file (one per line)"""
    usernames = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    usernames.append(line)
        print(f"[*] Loaded {len(usernames)} usernames from {filepath}")
    except Exception as e:
        print(f"[X] Error reading file: {e}")
    return usernames


def main():
    banner = """
 _____ _                                 
|_   _| |__  _   _ _ __ ___  _ __   ___ _ __ 
  | | | '_ \\| | | | '_ ` _ \\| '_ \\ / _ \\ '__|
  | | | | | | |_| | | | | | | |_) |  __/ |   
  |_| |_| |_|\\__,_|_| |_| |_| .__/ \\___|_|   
                            |_|              
    """
    
    parser = argparse.ArgumentParser(
        description="Thumper - Shai-Hulud 2.0 Detection + OSINT Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python thumper.py octocat
  python thumper.py user1 user2 -t ghp_token
  python thumper.py -f users.txt -o results/ --html
  python thumper.py octocat -o results/ --json --csv --html
        """
    )
    parser.add_argument("usernames", nargs="*", help="GitHub username(s) to scan")
    parser.add_argument("-f", "--file", help="File containing usernames (one per line)")
    parser.add_argument("-t", "--token", help="GitHub personal access token")
    parser.add_argument("-o", "--output", help="Output directory", default="results")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--csv", action="store_true", help="Save CSV summary")
    parser.add_argument("--html", action="store_true", help="Save HTML report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Collect usernames from args and/or file
    usernames = list(args.usernames) if args.usernames else []
    if args.file:
        usernames.extend(load_usernames_from_file(args.file))
    
    if not usernames:
        parser.error("No usernames provided. Use positional args or -f/--file")
    
    # Dedupe while preserving order
    seen = set()
    usernames = [u for u in usernames if not (u in seen or seen.add(u))]
    
    print(banner)
    print("="*60)
    print("THUMPER - Shai-Hulud 2.0 Detection + OSINT Recon")
    print("\"Attracts the worm. Finds the compromise.\"")
    print("Attack Window: November 21-26, 2025")
    print("="*60)
    print(f"\n[*] Scanning {len(usernames)} user(s)...")
    
    thumper = Thumper(token=args.token, verbose=args.verbose)
    
    all_results = {}
    for username in usernames:
        results = thumper.full_recon(username)
        all_results[username] = results
        thumper.print_report(results)
        
        if args.json:
            thumper.save_json(results, f"{args.output}/{username}.json")
        if args.csv:
            thumper.save_csv(results, f"{args.output}/{username}.csv")
        if args.html and results.profile:
            thumper.save_html(results, f"{args.output}/{username}.html")
    
    # Generate batch summary report
    if args.html and len(usernames) > 1:
        thumper.save_batch_html(all_results, f"{args.output}/index.html")
    
    # Multi-user summary
    if len(usernames) > 1:
        print(f"\n{'='*60}")
        print("MULTI-USER SUMMARY")
        print(f"{'='*60}")
        
        total_compromised = sum(
            len(r.shai_hulud_findings.get("compromised", [])) 
            for r in all_results.values()
        )
        total_suspicious = sum(
            len(r.shai_hulud_findings.get("suspicious", [])) 
            for r in all_results.values()
        )
        
        print(f"\n  Users scanned:      {len(usernames)}")
        print(f"  Compromised repos:  {total_compromised}")
        print(f"  Suspicious repos:   {total_suspicious}")
        
        high_risk = [u for u, r in all_results.items() if r.exposure_score >= 30]
        if high_risk:
            print(f"\n  High-risk users: {', '.join(high_risk)}")


if __name__ == "__main__":
    main()
