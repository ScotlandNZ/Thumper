#!/usr/bin/env python3
"""
 _____ _                                 
|_   _| |__  _   _ _ __ ___  _ __   ___ _ __ 
  | | | '_ \| | | | '_ ` _ \| '_ \ / _ \ '__|
  | | | | | | |_| | | | | | | |_) |  __/ |   
  |_| |_| |_|\__,_|_| |_| |_| .__/ \___|_|   
                            |_|              
  
Thumper - Shai-Hulud Detection + OSINT Recon Tool
"What senses do we lack that we cannot see or hear another world all around us?"

Attracts the worm. Finds the compromise.

Features:
- Full GitHub profile enumeration
- Leaked email discovery from commits
- SSH key extraction
- Organization membership mapping
- Shai-Hulud IOC detection (Wave 1 + Wave 2)
- Connected repo exposure analysis
- JSON/CSV/HTML reporting

Inspired by: https://github.com/GONZOsint/gitrecon
"""

import requests
import re
import argparse
import json
import os
import glob
from datetime import datetime
from collections import defaultdict
from typing import Optional
from dataclasses import dataclass, asdict, field

GITHUB_API = "https://api.github.com"

SUSPICIOUS_DESCRIPTIONS = [
    "sha1-hulud: the second coming",
    "sha1-hulud",
    "the second coming",
    "shai-hulud migration",
    "shai-hulud repository",
    "shai-hulud"
]

SUSPICIOUS_FILES = [
    "cloud.json",
    "contents.json",
    "environment.json",
    "trufflesecrets.json",
    "bun_environment.js",
    "setup_bun.js",
    "data.json"
]

SUSPICIOUS_WORKFLOWS = [
    "discussion.yaml",
    "formatter_",
    "shai-hulud-workflow.yml",
    "shai-hulud"
]

SUSPICIOUS_BRANCHES = ["shai-hulud"]

REPO_PATTERN_MIGRATION = re.compile(r"-migration$")
REPO_PATTERN_RANDOM = re.compile(r"^[a-z0-9]{18}$")

SANDWORM_ASCII = r"""
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
"""

KNOWN_COMPROMISED_PACKAGES = [
    "@asyncapi/cli",
    "@asyncapi/generator",
    "@zapier/zapier-sdk",
    "zapier-platform-core",
    "zapier-platform-cli", 
    "zapier-platform-schema",
    "@zapier/mcp-integration",
    "@zapier/secret-scrubber",
    "@zapier/ai-actions-react",
    "@zapier/stubtree",
    "zapier-scripts",
    "@ensdomains/ens-validation",
    "@ensdomains/content-hash",
    "ethereum-ens",
    "@ensdomains/react-ens-address",
    "@ensdomains/ens-contracts",
    "@ensdomains/ensjs",
    "@ensdomains/dnssecoraclejs",
    "@ensdomains/address-encoder",
    "@posthog/agent",
    "posthog-node",
    "@postman/postman-mcp-cli"
]

WAVE1_START = datetime(2025, 9, 14)
WAVE1_END = datetime(2025, 9, 20)
WAVE2_START = datetime(2025, 11, 21)
WAVE2_END = datetime(2025, 11, 26)


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
            "User-Agent": "Thumper/2.0"
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
    
    def log(self, msg: str, level: str = "info"):
        icons = {"info": "[*]", "warn": "[!]", "error": "[X]", "success": "[+]", "critical": "[!!!]"}
        if self.verbose or level in ["warn", "error", "critical", "success"]:
            print(f"{icons.get(level, '[*]')} {msg}")

    def api_get(self, endpoint: str, params: dict = None):
        url = f"{GITHUB_API}{endpoint}" if endpoint.startswith("/") else endpoint
        try:
            resp = self.session.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                self.log(f"Not found: {endpoint}", "warn")
                return None
            elif resp.status_code == 403:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                reset = resp.headers.get("X-RateLimit-Reset", "?")
                self.log(f"Rate limited: {endpoint} (remaining: {remaining})", "error")
                self.log("Use -t/--token to increase rate limits", "warn")
                return None
            elif resp.status_code == 401:
                self.log("Authentication failed - check your token", "error")
                return None
            else:
                self.log(f"API error {resp.status_code}: {endpoint}", "warn")
                return None
        except Exception as e:
            self.log(f"Request failed: {e}", "error")
            return None

    def get_profile(self, username: str):
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
        self.log("Searching for leaked emails in events")
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
        self.log("Deep scanning commits for leaked emails")
        emails = set()
        for repo in repos[:10]:
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
        self.log("Fetching SSH keys")
        data = self.api_get(f"/users/{username}/keys")
        if not data:
            return []
        return [{"id": k.get("id"), "key": k.get("key")[:50] + "..."} for k in data]

    def get_organizations(self, username: str) -> list:
        self.log("Fetching organization memberships")
        data = self.api_get(f"/users/{username}/orgs")
        if not data:
            return []
        return [{"login": o.get("login"), "id": o.get("id"), "url": f"https://github.com/{o.get('login')}"} for o in data]

    def get_repos(self, username: str) -> list:
        self.log("Fetching repositories")
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
        self.log("Searching for contributed repos")
        repos = []
        data = self.api_get("/search/commits", {"q": f"author:{username}", "per_page": 50, "sort": "author-date"})
        if data and "items" in data:
            seen = set()
            for item in data["items"]:
                repo = item.get("repository", {})
                full_name = repo.get("full_name", "")
                if full_name and full_name not in seen and not full_name.startswith(f"{username}/"):
                    seen.add(full_name)
                    repos.append({"full_name": full_name, "url": repo.get("html_url"), "owner": repo.get("owner", {}).get("login")})
        return repos

    def check_for_compromised_packages(self, username: str, repos: list) -> list:
        """Check if user maintains any known compromised packages"""
        self.log("Checking for known compromised npm packages")
        compromised = []
        
        for repo in repos:
            repo_name = repo.get("name", "").lower()
            full_name = f"{username}/{repo_name}".lower()
            
            for pkg in KNOWN_COMPROMISED_PACKAGES:
                pkg_name = pkg.lower().replace("@", "").replace("/", "-")
                if pkg_name in repo_name or repo_name in pkg_name:
                    compromised.append({
                        "repo": repo.get("name"),
                        "url": repo.get("html_url"),
                        "matched_package": pkg,
                        "type": "npm_package_match"
                    })
                    self.log(f"COMPROMISED PACKAGE: {repo.get('name')} matches {pkg}", "critical")
        
        package_json_repos = []
        for repo in repos[:20]:
            repo_name = repo.get("name")
            contents = self.api_get(f"/repos/{username}/{repo_name}/contents/package.json")
            if contents and contents.get("download_url"):
                package_json_repos.append({
                    "repo": repo_name,
                    "url": repo.get("html_url")
                })
        
        return compromised

    def search_user_for_ioc_repos(self, username: str) -> list:
        self.log("Searching GitHub for IOC repos owned by user")
        ioc_repos = []
        search_queries = [
            f"user:{username} \"Sha1-Hulud: The Second Coming\" in:description",
            f"user:{username} \"Shai-Hulud Migration\" in:description",
            f"user:{username} \"Shai-Hulud Repository\" in:description",
        ]
        for query in search_queries:
            data = self.api_get("/search/repositories", {"q": query, "per_page": 100})
            if data and "items" in data:
                for repo in data["items"]:
                    ioc_repos.append({
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "url": repo.get("html_url"),
                        "description": repo.get("description"),
                        "created_at": repo.get("created_at"),
                        "source": "github_search"
                    })
        seen = set()
        unique_repos = []
        for repo in ioc_repos:
            if repo["name"] not in seen:
                seen.add(repo["name"])
                unique_repos.append(repo)
        if unique_repos:
            self.log(f"Found {len(unique_repos)} IOC repos owned by user", "critical")
        return unique_repos

    def search_leaked_data(self, email: str = None, domain: str = None, username: str = None) -> dict:
        """Search for user's credentials in Shai-Hulud exfiltration repos"""
        self.log("Searching for leaked credentials in Shai-Hulud exfil repos")
        
        results = {
            "found_in_repos": [],
            "total_repos": 0,
            "search_terms_found": [],
            "exfil_repos_checked": 0
        }
        
        search_terms = []
        if email:
            search_terms.append(email)
        if domain:
            search_terms.append(domain)
        if username:
            search_terms.append(username)
        
        if not search_terms:
            return results
        
        exfil_repos = []
        repo_search_queries = [
            '"Sha1-Hulud: The Second Coming" in:description',
            '"Shai-Hulud Migration" in:description',
            '"Shai-Hulud Repository" in:description'
        ]
        
        for query in repo_search_queries:
            self.log(f"Finding exfil repos: {query[:50]}...")
            data = self.api_get("/search/repositories", {"q": query, "per_page": 100, "sort": "updated"})
            if data and "items" in data:
                for repo in data["items"]:
                    repo_info = {
                        "full_name": repo.get("full_name"),
                        "url": repo.get("html_url"),
                        "description": repo.get("description")
                    }
                    if repo_info["full_name"] not in [r["full_name"] for r in exfil_repos]:
                        exfil_repos.append(repo_info)
        
        self.log(f"Found {len(exfil_repos)} exfiltration repos to check", "info")
        results["exfil_repos_checked"] = len(exfil_repos)
        
        for term in search_terms:
            query = f'"{term}"'
            self.log(f"Searching code for: {term}")
            
            data = self.api_get("/search/code", {"q": query, "per_page": 100})
            if data and "items" in data:
                for item in data["items"]:
                    repo = item.get("repository", {})
                    repo_full_name = repo.get("full_name", "")
                    repo_desc = (repo.get("description") or "").lower()
                    
                    is_exfil_repo = any(
                        pattern in repo_desc 
                        for pattern in ["hulud", "second coming", "migration"]
                    )
                    
                    if is_exfil_repo:
                        repo_info = {
                            "repo": repo_full_name,
                            "url": repo.get("html_url"),
                            "file": item.get("name"),
                            "file_url": item.get("html_url"),
                            "search_term": term
                        }
                        if repo_info["repo"] not in [r["repo"] for r in results["found_in_repos"]]:
                            results["found_in_repos"].append(repo_info)
                            if term not in results["search_terms_found"]:
                                results["search_terms_found"].append(term)
            elif data is None:
                self.log(f"Code search failed for: {term}", "warn")
        
        results["total_repos"] = len(results["found_in_repos"])
        
        if results["total_repos"] > 0:
            self.log(f"FOUND credentials in {results['total_repos']} exfiltration repos!", "critical")
        else:
            self.log("No leaked credentials found via GitHub search", "info")
            self.log("Note: GitHub removes exfil repos quickly. Check dedicated IOC databases for complete coverage.", "warn")
        
        return results

    def get_branches(self, owner: str, repo: str) -> list:
        data = self.api_get(f"/repos/{owner}/{repo}/branches", {"per_page": 100})
        if not data:
            return []
        return [b.get("name", "") for b in data]

    def check_repo_for_iocs(self, owner: str, repo_name: str, repo_data: dict) -> dict:
        findings = []
        
        if REPO_PATTERN_MIGRATION.search(repo_name.lower()) or REPO_PATTERN_RANDOM.match(repo_name.lower()):
            findings.append({"type": "repo_name", "detail": f"Suspicious repo name: {repo_name}"})
        
        desc = (repo_data.get("description") or "").lower()
        for pattern in SUSPICIOUS_DESCRIPTIONS:
            if pattern in desc:
                findings.append({"type": "description", "detail": f"IOC in description: {pattern}"})
                break
        
        created = repo_data.get("created_at", "")
        in_attack_window = False
        wave = None
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")).replace(tzinfo=None)
            if WAVE1_START <= created_dt <= WAVE1_END:
                in_attack_window = True
                wave = 1
                findings.append({"type": "timing", "detail": f"Created during Wave 1: {created}"})
            elif WAVE2_START <= created_dt <= WAVE2_END:
                in_attack_window = True
                wave = 2
                findings.append({"type": "timing", "detail": f"Created during Wave 2: {created}"})
        except:
            pass
        
        if findings or in_attack_window:
            contents = self.api_get(f"/repos/{owner}/{repo_name}/contents/")
            if contents and isinstance(contents, list):
                for item in contents:
                    name = item.get("name", "").lower()
                    if name in [f.lower() for f in SUSPICIOUS_FILES]:
                        findings.append({"type": "file", "detail": f"IOC file: {item.get('name')}"})
            
            workflows = self.api_get(f"/repos/{owner}/{repo_name}/contents/.github/workflows")
            if workflows and isinstance(workflows, list):
                for item in workflows:
                    wf_name = item.get("name", "").lower()
                    for pattern in SUSPICIOUS_WORKFLOWS:
                        if pattern.lower() in wf_name:
                            findings.append({"type": "workflow", "detail": f"IOC workflow: {item.get('name')}"})
                            break
            
            branches = self.get_branches(owner, repo_name)
            for branch in branches:
                if branch.lower() in [b.lower() for b in SUSPICIOUS_BRANCHES]:
                    findings.append({"type": "branch", "detail": f"IOC branch: {branch}"})
        
        is_compromised = False
        for f in findings:
            detail = f.get("detail", "").lower()
            ftype = f.get("type", "")
            if "sha1-hulud" in detail or "shai-hulud" in detail or "second coming" in detail:
                is_compromised = True
                break
            if ftype == "description" and "migration" in detail:
                is_compromised = True
                break
        
        return {
            "repo": f"{owner}/{repo_name}",
            "url": repo_data.get("html_url"),
            "created": created,
            "in_attack_window": in_attack_window,
            "wave": wave,
            "findings": findings,
            "compromised": is_compromised
        }

    def scan_for_shai_hulud(self, username: str, repos: list, email: str = None, domain: str = None) -> dict:
        self.log(f"Scanning {len(repos)} repos for Shai-Hulud IOCs")
        results = {
            "compromised": [], 
            "suspicious": [], 
            "clean": 0, 
            "search_hits": [], 
            "leaked_in": {"found_in_repos": [], "total_repos": 0},
            "compromised_packages": []
        }
        
        pkg_matches = self.check_for_compromised_packages(username, repos)
        if pkg_matches:
            results["compromised_packages"] = pkg_matches
            for match in pkg_matches:
                results["compromised"].append({
                    "repo": f"{username}/{match['repo']}",
                    "url": match["url"],
                    "created": "",
                    "in_attack_window": True,
                    "wave": None,
                    "findings": [{"type": "compromised_package", "detail": f"Known compromised package: {match['matched_package']}"}],
                    "compromised": True
                })
        
        search_hits = self.search_user_for_ioc_repos(username)
        if search_hits:
            for hit in search_hits:
                desc_preview = hit["description"][:80] if hit["description"] else "N/A"
                results["compromised"].append({
                    "repo": hit["full_name"],
                    "url": hit["url"],
                    "created": hit["created_at"],
                    "in_attack_window": True,
                    "wave": None,
                    "findings": [{"type": "search_hit", "detail": f"GitHub search IOC: {desc_preview}"}],
                    "compromised": True
                })
                self.log(f"COMPROMISED (owns IOC repo): {hit['name']}", "critical")
            results["search_hits"] = search_hits
        
        leaked_data = self.search_leaked_data(email=email, domain=domain, username=username)
        if leaked_data["total_repos"] > 0:
            results["leaked_in"] = leaked_data
            self.log(f"LEAKED: Credentials found in {leaked_data['total_repos']} exfiltration repos", "critical")
        
        search_repo_names = {h["name"] for h in search_hits}
        
        for repo in repos:
            repo_name = repo.get("name")
            if repo_name in search_repo_names:
                continue
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
        score = 0
        sh = results.shai_hulud_findings
        if sh.get("compromised"):
            score += 50
        if sh.get("compromised_packages"):
            score += 30
        if sh.get("leaked_in", {}).get("total_repos", 0) > 0:
            score += 40
        score += len(sh.get("suspicious", [])) * 10
        score += min(len(results.emails_leaked) * 5, 15)
        score += min(len(results.ssh_keys) * 3, 10)
        score += min(len(results.repos_contributed) * 2, 10)
        score += min(len(results.organizations) * 3, 15)
        return min(score, 100)

    def full_recon(self, username: str) -> ReconResults:
        print(f"\n{'='*60}")
        print(f"THUMPER RECON: {username}")
        print(f"{'='*60}\n")
        
        results = ReconResults()
        results.profile = self.get_profile(username)
        if not results.profile:
            self.log(f"User {username} not found", "error")
            return results
        
        repos = self.get_repos(username)
        self.log(f"Found {len(repos)} repositories", "success")
        
        results.emails_leaked = self.get_emails_from_events(username)
        results.emails_leaked.extend(self.get_emails_from_commits(username, repos))
        results.emails_leaked = list(set(results.emails_leaked))
        results.ssh_keys = self.get_ssh_keys(username)
        results.organizations = self.get_organizations(username)
        results.repos_contributed = self.get_contributed_repos(username)
        
        profile_email = results.profile.email if results.profile else None
        domain = None
        if profile_email and "@" in profile_email:
            domain = profile_email.split("@")[1]
        
        results.shai_hulud_findings = self.scan_for_shai_hulud(username, repos, email=profile_email, domain=domain)
        results.exposure_score = self.calculate_exposure_score(results)
        
        return results

    def print_report(self, results: ReconResults):
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
                print(f"  * {email}")
        
        if results.ssh_keys:
            print(f"\n{'='*60}")
            print(f"SSH KEYS ({len(results.ssh_keys)} found)")
            print(f"{'='*60}")
            for key in results.ssh_keys:
                print(f"  * ID: {key['id']} - {key['key']}")
        
        if results.organizations:
            print(f"\n{'='*60}")
            print(f"ORGANIZATIONS ({len(results.organizations)} found)")
            print(f"{'='*60}")
            for org in results.organizations:
                print(f"  * {org['login']} - {org['url']}")
        
        if results.repos_contributed:
            print(f"\n{'='*60}")
            print(f"EXTERNAL CONTRIBUTIONS ({len(results.repos_contributed)} repos)")
            print(f"{'='*60}")
            for repo in results.repos_contributed[:10]:
                print(f"  * {repo['full_name']}")
        
        sh = results.shai_hulud_findings
        print(f"\n{'='*60}")
        print("SHAI-HULUD DETECTION")
        print(f"{'='*60}")
        
        has_findings = (
            sh.get("compromised_packages") or 
            sh.get("compromised") or 
            sh.get("leaked_in", {}).get("total_repos", 0) > 0
        )
        
        if has_findings:
            print(SANDWORM_ASCII)
        
        if sh.get("compromised_packages"):
            print(f"\n  [!!!] KNOWN COMPROMISED PACKAGES: {len(sh['compromised_packages'])}")
            for pkg in sh["compromised_packages"]:
                print(f"    - {pkg['repo']} (matches: {pkg['matched_package']})")
        
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
        
        leaked = sh.get("leaked_in", {})
        if leaked.get("total_repos", 0) > 0:
            print(f"\n  [!!!] CREDENTIALS LEAKED IN {leaked['total_repos']} EXFILTRATION REPOS:")
            print(f"    Search terms found: {', '.join(leaked.get('search_terms_found', []))}")
            for repo in leaked.get("found_in_repos", [])[:10]:
                print(f"\n    Repo: {repo['repo']}")
                print(f"    File: {repo['file']}")
                print(f"    URL:  {repo['file_url']}")
            if len(leaked.get("found_in_repos", [])) > 10:
                print(f"\n    ... and {len(leaked['found_in_repos']) - 10} more repos")
        
        if not sh.get("compromised") and not sh.get("suspicious") and leaked.get("total_repos", 0) == 0:
            print("\n  [+] No Shai-Hulud IOCs detected")
        
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
        p = results.profile
        if not p:
            self.log("Skipping HTML report - no profile data", "warn")
            return
        
        sh = results.shai_hulud_findings
        score = results.exposure_score
        risk = "CRITICAL" if score >= 50 else "HIGH" if score >= 30 else "MEDIUM" if score >= 15 else "LOW"
        risk_color = "#dc2626" if score >= 50 else "#f97316" if score >= 30 else "#eab308" if score >= 15 else "#22c55e"
        
        compromised_html = ""
        if sh.get("compromised"):
            for r in sh["compromised"]:
                findings = "".join(f"<li>{f['detail']}</li>" for f in r["findings"])
                compromised_html += f'<div class="repo-card compromised"><h4><a href="{r["url"]}" target="_blank">{r["repo"]}</a></h4><p class="created">Created: {r["created"]}</p><ul>{findings}</ul></div>'
        
        suspicious_html = ""
        if sh.get("suspicious"):
            for r in sh["suspicious"]:
                findings = "".join(f"<li>{f['detail']}</li>" for f in r["findings"])
                suspicious_html += f'<div class="repo-card suspicious"><h4><a href="{r["url"]}" target="_blank">{r["repo"]}</a></h4><p class="created">Created: {r["created"]}</p><ul>{findings}</ul></div>'
        
        emails_html = "".join(f"<li>{e}</li>" for e in results.emails_leaked) or "<li>None found</li>"
        keys_html = "".join(f"<li>ID: {k['id']} - {k['key']}</li>" for k in results.ssh_keys) or "<li>None found</li>"
        orgs_html = "".join(f'<li><a href="{o["url"]}" target="_blank">{o["login"]}</a></li>' for o in results.organizations) or "<li>None found</li>"
        contrib_html = "".join(f'<li><a href="{r["url"]}" target="_blank">{r["full_name"]}</a></li>' for r in results.repos_contributed[:15]) or "<li>None found</li>"
        
        detection_content = ""
        if compromised_html:
            detection_content += f'<div class="compromised-section"><h3 style="color: #dc2626;">COMPROMISED REPOSITORIES</h3>{compromised_html}</div>'
        if suspicious_html:
            detection_content += f'<div class="suspicious-section"><h3 style="color: #f97316; margin-top: 1.5rem;">Suspicious Repositories</h3>{suspicious_html}</div>'
        if not compromised_html and not suspicious_html:
            clean_count = sh.get("clean", 0)
            detection_content = f'<div class="clean"><p style="color: #22c55e; font-size: 1.2rem;">No Shai-Hulud IOCs detected</p><p style="color: #64748b;">{clean_count} repositories scanned</p></div>'
        
        remediation_html = ""
        if score >= 50:
            remediation_html = '<div class="remediation"><h3>IMMEDIATE ACTIONS REQUIRED</h3><ol><li>Revoke and rotate ALL GitHub tokens and PATs immediately</li><li>Rotate npm tokens</li><li>Rotate cloud credentials (AWS, Azure, GCP)</li><li>Remove suspicious repositories listed above</li><li>Audit all workflow files for unauthorized changes</li><li>Enable hardware-based 2FA on GitHub</li><li>Consider full machine reimaging if local dev environment was affected</li></ol></div>'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Thumper Report - {p.username}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
header {{ text-align: center; margin-bottom: 3rem; padding: 2rem; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-radius: 1rem; border: 1px solid #334155; }}
h1 {{ font-size: 2.5rem; color: #f59e0b; margin-bottom: 0.5rem; }}
.tagline {{ color: #94a3b8; font-style: italic; }}
.scan-info {{ margin-top: 1rem; color: #64748b; font-size: 0.9rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
.card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }}
.card h3 {{ color: #f59e0b; margin-bottom: 1rem; }}
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
.remediation {{ background: linear-gradient(135deg, #7f1d1d 0%, #1e293b 100%); border: 1px solid #dc2626; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 2rem; }}
.remediation h3 {{ color: #fca5a5; margin-bottom: 1rem; }}
.remediation ol {{ margin-left: 1.5rem; }}
.remediation li {{ padding: 0.5rem 0; color: #fecaca; }}
.clean {{ text-align: center; padding: 2rem; }}
footer {{ text-align: center; margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #334155; color: #64748b; }}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Thumper Report</h1>
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
<p><strong>Location:</strong> {p.location or "N/A"} | <strong>Company:</strong> {p.company or "N/A"} | <strong>Email:</strong> {p.email or "N/A"}</p>
</div>
<div class="risk-score">
<div class="score">{score}</div>
<div class="label">{risk} RISK</div>
<div class="subtitle">Exposure Score (0-100)</div>
</div>
<div class="section">
<h2>Shai-Hulud Detection</h2>
{detection_content}
</div>
{remediation_html}
<div class="grid">
<div class="card"><h3>Leaked Emails</h3><ul>{emails_html}</ul></div>
<div class="card"><h3>SSH Keys</h3><ul>{keys_html}</ul></div>
<div class="card"><h3>Organizations</h3><ul>{orgs_html}</ul></div>
<div class="card"><h3>External Contributions</h3><ul>{contrib_html}</ul></div>
</div>
<footer>
<p>Generated by Thumper | Shai-Hulud Detection + OSINT Recon</p>
<p>Wave 1: September 14-20, 2025 | Wave 2: November 21-26, 2025</p>
</footer>
</div>
</body>
</html>'''
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            f.write(html)
        print(f"[*] HTML report saved to {filepath}")


def load_usernames_from_file(filepath: str) -> list:
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
    banner = r"""
 _____ _                                 
|_   _| |__  _   _ _ __ ___  _ __   ___ _ __ 
  | | | '_ \| | | | '_ ` _ \| '_ \ / _ \ '__|
  | | | | | | |_| | | | | | | |_) |  __/ |   
  |_| |_| |_|\__,_|_| |_| |_| .__/ \___|_|   
                            |_|              
    """
    
    parser = argparse.ArgumentParser(
        description="Thumper - Shai-Hulud Detection + OSINT Recon",
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
    parser.add_argument("-e", "--email", help="Search for email in leaked data")
    parser.add_argument("-d", "--domain", help="Search for domain in leaked data")
    parser.add_argument("-t", "--token", help="GitHub personal access token")
    parser.add_argument("-o", "--output", help="Output directory", default="results")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--csv", action="store_true", help="Save CSV summary")
    parser.add_argument("--html", action="store_true", help="Save HTML report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    usernames = list(args.usernames) if args.usernames else []
    if args.file:
        usernames.extend(load_usernames_from_file(args.file))
    
    if not usernames and not args.email and not args.domain:
        parser.error("No usernames, email, or domain provided. Use positional args, -f/--file, -e/--email, or -d/--domain")
    
    seen = set()
    usernames = [u for u in usernames if not (u in seen or seen.add(u))]
    
    print(banner)
    print("=" * 60)
    print("THUMPER - Shai-Hulud Detection + OSINT Recon")
    print('"Attracts the worm. Finds the compromise."')
    print("Wave 1: September 14-20, 2025 | Wave 2: November 21-26, 2025")
    print("=" * 60)
    
    thumper = Thumper(token=args.token, verbose=args.verbose)
    
    if args.email or args.domain:
        print(f"\n[*] Searching leaked data for: {args.email or ''} {args.domain or ''}")
        leaked = thumper.search_leaked_data(email=args.email, domain=args.domain)
        
        print(f"\n{'='*60}")
        print("LEAKED CREDENTIALS SEARCH")
        print(f"{'='*60}")
        
        if leaked["total_repos"] > 0:
            print(f"\n  [!!!] FOUND IN {leaked['total_repos']} EXFILTRATION REPOS!")
            print(f"  Search terms matched: {', '.join(leaked['search_terms_found'])}")
            print(f"\n  Repositories containing your data:")
            for repo in leaked["found_in_repos"][:20]:
                print(f"\n    Repo: {repo['repo']}")
                print(f"    File: {repo['file']}")
                print(f"    URL:  {repo['file_url']}")
            if len(leaked["found_in_repos"]) > 20:
                print(f"\n    ... and {len(leaked['found_in_repos']) - 20} more repos")
            
            print(f"\n  [!!!] IMMEDIATE ACTION REQUIRED:")
            print("    1. Rotate ALL credentials immediately")
            print("    2. Rotate npm/GitHub tokens")
            print("    3. Rotate cloud credentials (AWS/Azure/GCP)")
            print("    4. Enable hardware-based 2FA")
            print("    5. Audit systems for unauthorized access")
        else:
            print(f"\n  [+] No leaked credentials found for: {args.email or ''} {args.domain or ''}")
        
        if not usernames:
            return
    
    if usernames:
        print(f"\n[*] Scanning {len(usernames)} user(s)...")
    
    if usernames:
        print(f"\n[*] Scanning {len(usernames)} user(s)...")
        
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
        
        if len(usernames) > 1:
            print(f"\n{'='*60}")
            print("MULTI-USER SUMMARY")
            print(f"{'='*60}")
            
            total_compromised = sum(len(r.shai_hulud_findings.get("compromised", [])) for r in all_results.values())
            total_suspicious = sum(len(r.shai_hulud_findings.get("suspicious", [])) for r in all_results.values())
            total_leaked = sum(r.shai_hulud_findings.get("leaked_in", {}).get("total_repos", 0) for r in all_results.values())
            
            print(f"\n  Users scanned:      {len(usernames)}")
            print(f"  Compromised repos:  {total_compromised}")
            print(f"  Suspicious repos:   {total_suspicious}")
            print(f"  Leaked in repos:    {total_leaked}")
            
            high_risk = [u for u, r in all_results.items() if r.exposure_score >= 30]
            if high_risk:
                print(f"\n  High-risk users: {', '.join(high_risk)}")


if __name__ == "__main__":
    main()
