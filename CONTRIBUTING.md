# 🤝 Contributing to recon.sh

First off — thanks for taking the time to contribute! All contributions are welcome.

---

## Ways to Contribute

- 🐛 **Bug reports** — found something broken? Open an issue
- 💡 **Feature requests** — have an idea? Open an issue with the `enhancement` label
- 🔧 **Pull requests** — fix a bug or add a feature
- 📖 **Documentation** — improve the README, INSTALL.md, or add examples
- ⭐ **Star the repo** — helps others discover the project

---

## Before You Open a PR

1. **Fork** the repository
2. Create a **new branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. **Test** your changes on a live target you have permission to scan
5. Push and open a Pull Request

---

## Code Style Guidelines

This is a Bash project. Please follow these conventions:

- Use `snake_case` for variable and function names
- Quote all variables: `"${VAR}"` not `$VAR`
- Use `[[ ]]` for conditionals, not `[ ]`
- Add a comment above any non-obvious logic
- Keep functions small and focused
- Handle errors — use `|| true` when a failure is acceptable, otherwise handle it explicitly
- Log actions using the helper functions: `info`, `success`, `warn`, `error`

---

## Adding a New Finding Type

1. Add the finding type and its CVSS profile inside `cvss_for_finding()` in `recon.sh`
2. Call `add_finding "YOUR_FINDING_TYPE" "$target" "$detail"` where it's detected
3. Update this table in the README under **CVSS v3.1 Scoring**

---

## Adding a New Tool Integration

1. Add the tool to the check list in the `Checking Installed Tools` section
2. Wrap your tool usage with a check:
   ```bash
   if command -v yourtool &>/dev/null; then
       # use it
   else
       warn "yourtool not found, skipping..."
   fi
   ```
3. Add install instructions in `INSTALL.md` and `install_tools.sh`

---

## Reporting Bugs

Open a GitHub Issue and include:
- Your OS and bash version (`bash --version`)
- Which tools are installed
- The exact command you ran (redact the target if needed)
- The relevant lines from `recon.log`

---

## Code of Conduct

- Be respectful and constructive
- This tool is for **legal, authorised** security testing only
- Do not submit contributions that add features intended to bypass legal safeguards or harm systems without permission
