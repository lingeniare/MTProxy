# Contributing

Thanks for your interest in the project! Here are a few ways to help:

## Bug Reports

Open an Issue with the following details:
- Ubuntu version
- Full script output (if there's an error)
- Steps to reproduce

## Pull Requests

1. Fork the repository
2. Create a branch: `git checkout -b fix/description`
3. Make your changes
4. Ensure the script passes `shellcheck install_mtproxy.sh`
5. Open a Pull Request

## Code Style

- Bash with `set -euo pipefail`
- Logging functions: `info()`, `ok()`, `warn()`, `fail()`
- Comments in English or Russian
