# Scan things

## TLDR

Assumes you have a GITHUB_TOKEN set. Checks the CVEs maintained [here](https://github.com/CVEProject/cvelistV5)

```bash
brew install node # or whatever your package manager is

npm install

# scan all things using all takes a while
node scan.js all
# or scan things gitlab reported as CNA
node scan.js all --assigner="Gitlab"
#or scan for things gitlab reported as CNA about product Gitlab
node scan.js all --assigner="Gitlab" --product="Gitlab"
#or scan for cves reported from any CNA for a product
node scan.js all --product="Gitlab"
# Scan for anything reported in the delta release (today) for gitlab
node scan.js --product="Gitlab"
# Scan for anything reported in the delta release
node scan.js
#or scan for things atlassian reported as CNA about anything in the Jira product family
node scan.js all --assigner="atlassian" --product="Jira"
#or scan for things atlassian reported as CNA about anything in the Jira Align
node scan.js all --assigner="atlassian" --product="Jira Align"
#or scan for things reported by any CNA about anything in the Jira product family
node scan.js all --product="Jira"
```
