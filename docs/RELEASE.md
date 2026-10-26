# GitHub release checklist

## Before committing

```powershell
python -m pytest -q
git status --short
git ls-files | Select-String -Pattern '(^|/)(\.env$|\.venv/|__pycache__/|\.pytest_cache/)' 
```

The last command should produce no tracked secret or cache paths. Review `git diff --cached` before pushing. Do not print or share API keys. If a key was ever committed, rotate it and assess the Git history; deleting it in a new commit is not sufficient.

## Commit documentation and push

```powershell
git add README.md docs/
git diff --cached --stat
git commit -m "docs: add architecture, setup, roadmap and release guidance"
git push origin main
```

## Optional version tag

Only tag the exact code version you intend to release. If your repository has not yet tagged v1.2.0:

```powershell
git tag -a v1.2.0 -m "VulnAgent AI v1.2.0 MVP"
git push origin v1.2.0
```

Then create a release on GitHub from the tag. The tag points to the current commit, including documentation if you tag after committing it.
