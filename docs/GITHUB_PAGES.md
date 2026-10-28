# Publish the project site with GitHub Pages

The repository builds a static site (landing page + rendered docs) with `scripts/build_site.py` and deploys it with the
`Pages` workflow (`.github/workflows/pages.yml`). Your site address will be:

**https://nikhil-creat.github.io/agentshield-x/**

## Steps
1. Push the repository to GitHub (see [Publish to GitHub](github-guide.html)). The repo must be public for Pages on a free account.
2. On GitHub open **Settings → Pages**. Under **Build and deployment → Source**, choose **GitHub Actions**. (Do not pick "Deploy from a branch".)
3. Go to the **Actions** tab, open the **Pages** workflow and press **Run workflow** (it also runs on every push to `main` that touches the site, docs or engine).
4. When the run is green, the deploy job prints the URL. The first publish can take a minute or two to appear.
5. Add the URL to the repository's **About** box (gear icon → Website) and to your profile README / resume.

## Preview locally
```bash
pip install markdown
python scripts/build_site.py          # writes _site/
python -m http.server -d _site 8000   # open http://localhost:8000
```

## Notes
- All links are relative, so the site works under `/agentshield-x/` and on a custom domain. For a custom domain add it under *Settings → Pages* and create the DNS record GitHub tells you to.
- The pages carry a strict Content-Security-Policy via a meta tag (no inline scripts, no third-party requests). GitHub Pages cannot set HTTP headers, so other headers (HSTS etc.) are GitHub's defaults.
- The "Real results" on the home page are produced by running the engine during the build; they refresh on every deploy and will fail the build if the ledger does not verify.
- If the workflow fails on **Set up Pages**, Pages is not yet set to *GitHub Actions* (step 2).
