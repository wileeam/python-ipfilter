#!/usr/bin/env python3
import os
import requests
import gzip
import shutil
import datetime
import ipaddress
import re
from tqdm import tqdm
import argparse

# List definitions, more can be added
LISTS = [
    ("Level 1", "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz"),
    ("Anti-Infringement", "http://list.iblocklist.com/?list=dufcxgnbjsdwmwctgfuj&fileformat=p2p&archiveformat=gz"),
    ("Spamhaus DROP", "http://list.iblocklist.com/?list=zbdlwrqkabxbcppvrnos&fileformat=p2p&archiveformat=gz"),
    ("CINS Army", "http://list.iblocklist.com/?list=npkuuhuxcsllnhoamkvm&fileformat=p2p&archiveformat=gz"),
    ("badpeers", "http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz"),
    ("spyware", "http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz"),
    ("ads (optional)", "http://list.iblocklist.com/?list=dgxtneitpuvgqqcpfulq&fileformat=p2p&archiveformat=gz")
]

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def ip_to_int(ip_str):
    """Convert IP address string to integer for efficient comparison."""
    ip = ipaddress.ip_address(ip_str)
    return int(ip)

def int_to_ip(ip_int):
    """Convert integer back to IP address string."""
    return str(ipaddress.ip_address(ip_int))

def merge_ip_ranges(ranges):
    """
    Merge overlapping and adjacent IP ranges.

    Args:
        ranges: List of tuples (start_ip_str, end_ip_str, description)

    Returns:
        List of merged tuples (start_ip_str, end_ip_str, description)
        Statistics dict with raw_count, merged_count, reduction_percent
    """
    if not ranges:
        return [], {'raw_count': 0, 'merged_count': 0, 'reduction_percent': 0}

    # Convert to integers and sort
    int_ranges = []
    for start_ip, end_ip, desc in ranges:
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        if start_int <= end_int:
            int_ranges.append((start_int, end_int, desc))

    # Sort by start IP, then by end IP
    int_ranges.sort(key=lambda x: (x[0], x[1]))

    raw_count = len(int_ranges)
    merged = []

    if int_ranges:
        current_start, current_end, current_desc = int_ranges[0]

        for start, end, desc in int_ranges[1:]:
            # Check if ranges overlap or are adjacent (within 1 IP)
            if start <= current_end + 1:
                # Merge: extend current range if needed
                current_end = max(current_end, end)
                # Keep the first description for merged ranges
            else:
                # No overlap: save current range and start new one
                merged.append((int_to_ip(current_start), int_to_ip(current_end), current_desc))
                current_start, current_end, current_desc = start, end, desc

        # Don't forget the last range
        merged.append((int_to_ip(current_start), int_to_ip(current_end), current_desc))

    merged_count = len(merged)
    reduction_percent = ((raw_count - merged_count) * 100 // raw_count) if raw_count > 0 else 0

    stats = {
        'raw_count': raw_count,
        'merged_count': merged_count,
        'reduction_percent': reduction_percent
    }

    return merged, stats

def parse_ip_ranges_from_file(source_path, log_lines, list_name=""):
    """
    Parse IP ranges from a source file without writing to disk.

    Returns:
        List of tuples (start_ip, end_ip, description)
    """
    ranges = []
    converted = 0
    skipped = 0
    corrected = 0

    with open(source_path, 'r', encoding='utf-8') as src:
        for line_num, line in enumerate(src, start=1):
            original_line = line.strip()
            if not original_line or original_line.startswith('#'):
                continue

            match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$', original_line)
            if not match:
                skipped += 1
                log_lines.append(f"[{list_name}] [ERROR] Line {line_num}: Invalid IP range → {original_line}")
                continue

            ip_start, ip_end = match.groups()
            if not (is_valid_ip(ip_start) and is_valid_ip(ip_end)):
                skipped += 1
                log_lines.append(f"[{list_name}] [ERROR] Line {line_num}: Invalid IP address → {original_line}")
                continue

            description = original_line[:match.start()].rstrip(' :').strip()
            if not description:
                description = list_name

            ranges.append((ip_start, ip_end, description))
            converted += 1

            if not original_line.endswith(f"{ip_start}-{ip_end}"):
                corrected += 1

    log_lines.append(f"[{list_name}] Summary: {converted} processed, {corrected} corrected, {skipped} skipped")
    return ranges

def write_merged_ranges(ranges, destination_path, log_lines):
    """Write merged IP ranges to destination file."""
    with open(destination_path, 'w', encoding='utf-8') as dst:
        for ip_start, ip_end, description in ranges:
            converted_line = f"{ip_start} - {ip_end} , 000 , {description}"
            dst.write(converted_line + '\n')

    log_lines.append(f"Written {len(ranges)} merged ranges to {destination_path}")

def download_and_process_lists(block_list_path, overwrite=False):
    block_list_path_resolved = os.path.abspath(block_list_path)
    final_ipfilter_file = os.path.join(block_list_path_resolved, 'ipfilter.dat')
    temp_file = os.path.join(block_list_path_resolved, 'temp_download.gz')
    raw_file = os.path.join(block_list_path_resolved, 'ipfilter_raw.p2p')
    log_file_path = os.path.join(block_list_path_resolved, 'log.txt')
    log_lines = []

    # Header with timestamp
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines.append(f"===== IPFilter update started: {now} =====\n")

    if os.path.exists(final_ipfilter_file):
        if not overwrite:
            answer = input(f"The file '{final_ipfilter_file}' already exists. Overwrite? (y/n): ").strip().lower()
            if answer != 'y':
                print("Aborted. The file was not overwritten.")
                return
        else:
            # Overwrite without prompting
            log_lines.append(f"Existing file '{final_ipfilter_file}' will be overwritten by automation.")

    print("The following IP filter lists will be downloaded and merged:\n")
    for name, _ in LISTS:
        print(f"- {name}")
    print()

    # Collect all IP ranges from all lists
    all_ranges = []

    for name, url in LISTS:
        print(f"\n→ Downloading list: {name}")
        log_lines.append(f"[{name}] Download started")

        try:
            response = requests.get(url, headers={'User-Agent': 'curl/8.7.1'}, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            block_size = 1024

            with open(temp_file, 'wb') as f, tqdm(total=total_size, unit='iB', unit_scale=True) as bar:
                for data in response.iter_content(block_size):
                    f.write(data)
                    bar.update(len(data))

            with gzip.open(temp_file, 'rb') as f_in:
                with open(raw_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            log_lines.append(f"[{name}] Download successful")

            # Parse ranges from this list
            ranges = parse_ip_ranges_from_file(raw_file, log_lines, list_name=name)
            all_ranges.extend(ranges)
            log_lines.append(f"[{name}] Extracted {len(ranges)} IP ranges")

            os.remove(raw_file)

        except Exception as e:
            log_lines.append(f"[{name}] Download failed: {str(e)}")
            print(f"✗ Failed to download {name}: {str(e)}")

    if os.path.exists(temp_file):
        os.remove(temp_file)

    # Merge overlapping and adjacent IP ranges
    print(f"\n→ Merging {len(all_ranges)} IP ranges...")
    log_lines.append(f"\n[MERGE] Starting merge process with {len(all_ranges)} total ranges")

    merged_ranges, merge_stats = merge_ip_ranges(all_ranges)

    log_lines.append(f"[MERGE] Raw ranges: {merge_stats['raw_count']}")
    log_lines.append(f"[MERGE] Merged ranges: {merge_stats['merged_count']}")
    log_lines.append(f"[MERGE] Reduction: {merge_stats['reduction_percent']}%")
    log_lines.append(f"[MERGE] Eliminated {merge_stats['raw_count'] - merge_stats['merged_count']} duplicate/overlapping ranges\n")

    # Write merged ranges to file
    write_merged_ranges(merged_ranges, final_ipfilter_file, log_lines)

    log_lines.append(f"\n===== Processing completed =====\n")

    with open(log_file_path, 'w', encoding='utf-8') as log:
        log.write('\n'.join(log_lines))

    print("\n✅ All lists downloaded and merged.")
    print(f"→ Output file: {final_ipfilter_file}")
    print(f"→ Total entries: {merge_stats['merged_count']:,} (reduced from {merge_stats['raw_count']:,})")
    print(f"→ Space savings: {merge_stats['reduction_percent']}%")
    print(f"→ Log file   : {log_file_path}")

    print("\nTo use the IP filter in qBittorrent:")
    print("* Go to: Tools → Options → Connection → IP Filtering")
    print(f"* Set the filter file to: '{final_ipfilter_file}'")

# Run script when executed directly; provide CLI for CI automation
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download and build ipfilter.dat from configured lists')
    parser.add_argument('--output-dir', '-o', default=os.getcwd(), help='Directory to write ipfilter.dat and log.txt')
    parser.add_argument('--yes', '-y', action='store_true', help='Automatically overwrite existing ipfilter.dat without prompting')
    args = parser.parse_args()

    download_and_process_lists(args.output_dir, overwrite=args.yes)
