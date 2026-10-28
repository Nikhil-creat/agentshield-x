# Publishing AgentShield-X to GitHub

Your GitHub account is `Nikhil-creat`. Nothing here is automatic: you run each command yourself.

## 0. One-time setup
```bash
git --version                       # install git if missing
git config --global user.name  "Nikhil Chary Sriramoju"
git config --global user.email "<your GitHub noreply or commit email>"
```
Use the `ID+username@users.noreply.github.com` address (GitHub → Settings → Emails) if you do not want your real email in commit history.

## 1. Unpack and check before the first commit
```bash
sha256sum -c agentshield-x-2.2.0.zip.sha256        # integrity of the download (run next to the zip)
unzip agentshield-x-2.2.0.zip && cd agentshield-x-2.2.0
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,api]"
make test policy redteam                            # must be green before you publish
ls -a | grep -E '^\.env$|^keys$|^secrets$' || echo "no secrets present (good)"
```

## 2. Create the repository and push
**Option A - GitHub CLI**
```bash
gh auth login
git init -b main && git add . && git commit -m "feat: AgentShield-X 2.2.0"
gh repo create Nikhil-creat/agentshield-x --public --source . --remote origin --push \
  --description "Zero-trust security and governance fabric for LLM, RAG and multi-agent systems"
```
**Option B - website**
1. github.com → **New repository** → name `agentshield-x`, *no* README/.gitignore/licence (the zip already has them) → Create.
2. ```bash
   git init -b main && git add . && git commit -m "feat: AgentShield-X 2.2.0"
   git remote add origin https://github.com/Nikhil-creat/agentshield-x.git
   git push -u origin main
   ```
   (GitHub no longer accepts account passwords for `git push`; sign in through the browser prompt/Git Credential Manager or use a fine-grained personal access token.)

Run `git status` before `git add .` and confirm no `.env`, `keys/` or `*.pem` private key is listed. If you ever commit a secret,
rotate it - deleting it in a later commit does not remove it from history.

## 3. Turn on the protections (Settings)
| Where | Setting |
|---|---|
| Code security | **Private vulnerability reporting** → enable (SECURITY.md points here) |
| Code security | **Dependabot alerts** and **security updates** → enable (`.github/dependabot.yml` is already included) |
| Code security | **Secret scanning** and **push protection** → enable |
| Code security | **Code scanning** → the `Security` workflow runs CodeQL; confirm results appear under *Security* |
| Branches | Add a ruleset for `main`: require pull request, require status checks `test`, `policy-as-code`, `deploy-manifests`, block force pushes |
| Actions → General | Workflow permissions: *Read repository contents*; allow GitHub-authored and verified actions only |
| General | Add topics: `llm-security`, `prompt-injection`, `ai-agents`, `rag`, `zero-trust`, `mcp`, `fastapi`, `post-quantum` |

The first CI run is the first time the workflows execute anywhere. **Expect to fix a few things**: they were written but never run.
Open the *Actions* tab, read the failing step's log, fix, push. The `lint` job is advisory (`continue-on-error`) until the code is ruff/mypy clean.

## 4. Release
```bash
git tag -a v2.2.0 -m "AgentShield-X 2.2.0" && git push origin v2.2.0
```
The `Release` workflow tests, builds the wheel/sdist and SBOM, pushes a signed image to `ghcr.io/nikhil-creat/agentshield-x`,
attaches build provenance and publishes a GitHub release. Make the package public under *Packages* if you want others to pull it.

## 5. Make the repo look finished
- Pin it on your profile; add a screenshot of `/console` to the README.
- Add the repo to your resume under projects with an honest one-liner (see README "Verification status" for what is and is not proven).
- Keep `CHANGELOG.md` current for each release.
