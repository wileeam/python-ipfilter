# qBittorrent IPFilter Updater

This Python script automatically downloads, merges, and converts multiple IP filter blocklists from [I-Blocklist](https://www.iblocklist.com/) into a single `ipfilter.dat` file for use with **qBittorrent** or compatible clients.

## Features

- Downloads and processes multiple known blocklists (Level 1, Anti-Infringement, Spamhaus, etc.)
- Merges all entries into a single, valid `ipfilter.dat` file
- Automatically corrects common formatting issues
- Validates and logs malformed or corrected entries
- Displays download progress using `tqdm`
- Creates a detailed `log.txt` file with per-list statistics

## Blocklists Included

The following lists are included by default:

- Level 1  
- Anti-Infringement  
- Spamhaus DROP  
- CINS Army  
- badpeers  
- spyware  
- ads (optional)

Each list is fetched as a compressed `.gz` file and processed accordingly.

## Migration from previous structure

The repository previously maintained two language-specific subdirectories:

- `english/ipfilter.py` — English version of the script
- `deutsch/ipfilter.py` — German version of the script
- `docs/README_de.md` — German documentation

These have been consolidated. **`ipfilter.py` now lives at the repository root** and is the single authoritative script. The German-language version has been removed; all functionality is identical. If you were referencing either of the old paths (e.g. in scripts, CI pipelines, or documentation), update them to point to `./ipfilter.py`.

## Usage

### Prerequisites

- Python 3.8+
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```

### Running the script

```bash
python ipfilter.py
```

By default, `ipfilter.dat` and `log.txt` are written to the current directory. Use the optional flags below to customise behaviour.

### CLI options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output-dir DIR` | `-o` | current directory | Directory where `ipfilter.dat` and `log.txt` are written |
| `--yes` | `-y` | — | Skip the overwrite prompt and automatically overwrite an existing `ipfilter.dat` |

**Examples:**

```bash
# Write output to a specific directory
python ipfilter.py --output-dir /etc/qbittorrent

# Non-interactive mode (e.g. for use in CI or cron jobs)
python ipfilter.py --yes
```

### Using the generated filter in qBittorrent

1. Go to **Tools → Options → Connection → IP Filtering**
2. Enable IP filtering and point the filter file to the generated `ipfilter.dat`

## Development

### Running Tests

The repository includes a comprehensive test suite covering IP validation, conversion, range merging, and file parsing logic.

To run the tests:

```bash
python -m unittest test_ipfilter -v
```

All tests must pass before merging pull requests.

### Continuous Integration

This repository uses GitHub Actions for CI/CD:

- **Test Suite** (`.github/workflows/test.yml`): Runs on all pull requests and pushes to main branches. Tests are run across Python versions 3.8, 3.9, 3.10, 3.11, and 3.12.
- **Update IPFilter** (`.github/workflows/update-ipfilter.yml`): Automatically updates `ipfilter.dat` daily at 03:00 UTC and creates a pull request with the changes.

### Branch Protection

To ensure code quality, configure branch protection rules on your main branch:

1. Go to **Settings → Branches → Branch protection rules**
2. Add a rule for your main branch (e.g., `main` or `master`)
3. Enable: **Require status checks to pass before merging**
4. Select all required status checks produced by the **Test Suite** workflow for each Python version in the test matrix (for example, the version-specific checks for Python 3.8, 3.9, 3.10, 3.11, and 3.12), rather than a single check named `test`
5. Enable: **Require branches to be up to date before merging**

This will prevent merging pull requests unless every required CI test job is passing.

