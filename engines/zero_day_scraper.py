import requests
import os
import time
from engines.utils import log

class ZeroDayScraper:
    def __init__(self):
        self.github_api_url = "https://api.github.com/search/repositories"
        self.keywords = [
            "router exploit poc",
            "camera exploit poc",
            "hikvision bypass",
            "cve router rce python",
            "iot exploit script"
        ]
        self.download_dir = "scripts/new_pocs"

    def search_and_download(self):
        """Searches GitHub for new PoCs and downloads them."""
        log("Starting GitHub Zero-Day PoC Scraper...", "INFO")
        os.makedirs(self.download_dir, exist_ok=True)
        
        headers = {"Accept": "application/vnd.github.v3+json"}
        found_repos = []

        for keyword in self.keywords:
            query = f"{keyword} in:readme,description language:python created:>2025-01-01"
            params = {"q": query, "sort": "updated", "order": "desc", "per_page": 5}
            
            try:
                log(f"  Searching GitHub for: '{keyword}'...", "INFO")
                response = requests.get(self.github_api_url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("items", []):
                        repo_name = item["full_name"]
                        clone_url = item["clone_url"]
                        description = item["description"]
                        
                        if repo_name not in [r["name"] for r in found_repos]:
                            found_repos.append({
                                "name": repo_name,
                                "url": clone_url,
                                "desc": description
                            })
                elif response.status_code == 403: # Rate limit
                    log("GitHub API rate limit reached. Pausing scraper.", "WARNING")
                    break
                
                time.sleep(2) # Be polite to API
            except Exception as e:
                log(f"GitHub search failed for '{keyword}': {e}", "ERROR")

        if found_repos:
            log(f"Found {len(found_repos)} new/updated PoC repositories!", "SUCCESS")
            for repo in found_repos:
                log(f"  [+] {repo['name']} - {repo['desc']}", "PWN")
                
                # Clone the repo into our new_pocs directory
                repo_path = os.path.join(self.download_dir, repo['name'].split('/')[1])
                if not os.path.exists(repo_path):
                    try:
                        import subprocess
                        subprocess.run(["git", "clone", repo['url'], repo_path], capture_output=True, check=True)
                        log(f"      Downloaded to: {repo_path}", "SUCCESS")
                    except Exception as e:
                        log(f"      Failed to clone {repo['name']}: {e}", "ERROR")
                else:
                    log(f"      Already downloaded: {repo_path}", "INFO")
        else:
            log("No new PoCs found on GitHub matching criteria.", "INFO")
            
        return found_repos

if __name__ == "__main__":
    scraper = ZeroDayScraper()
    scraper.search_and_download()
