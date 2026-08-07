<!--
Thanks for the PR! Keep it focused and reviewable. Delete sections that
don't apply. CI (the `test` check) must pass before this can merge.
-->

## Summary

<!-- What does this change and why? Link related issues (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Docs
- [ ] Test / CI
- [ ] Refactor / chore

## How was this tested?

<!-- Commands you ran, new/updated tests, manual verification. -->

```
python3 -m pytest tests/ -q
```

## Checklist

- [ ] Branched off `main`; branch is focused on one change
- [ ] `python3 -m pytest tests/ -q` passes locally
- [ ] Added/updated tests for the change (and they're hermetic — no live network)
- [ ] Updated docs (README / INSTALL / relevant `docs/`) if behavior changed
- [ ] Dependency change? Updated **both** `pyproject.toml`/`uv.lock` **and** `requirements.txt`
- [ ] **No secrets** (API keys, tokens, private keys) in code, tests, docs, or history
- [ ] Commit messages explain *why*; author identity is correct
