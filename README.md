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

- Python 3.6+
- Dependencies:
  ```bash
  pip install requests tqdm
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
