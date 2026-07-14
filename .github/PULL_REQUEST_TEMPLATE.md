## What changed

Describe the focused change and the user-visible effect.

## Why

Explain the evidence, bug, false positive, missing workflow, or official Apple source update.

## Validation

- [ ] `python3 -m py_compile app_store_review/scripts/*.py`
- [ ] `python3 app_store_review/scripts/run_self_tests.py`
- [ ] `sh -n install.sh update.sh uninstall.sh`
- [ ] Relevant clean install, update, or uninstall checks
- [ ] Fixture tree is unchanged after tests

## Source and safety review

- [ ] Mandatory Apple claims link to a current official Apple page.
- [ ] Conditional requirements and exceptions are explicit.
- [ ] No secrets, private project data, signing material, generated reports, or build artifacts are included.
- [ ] Scanner changes include a focused regression test.
- [ ] Documentation makes no approval guarantee or unsupported effectiveness claim.
