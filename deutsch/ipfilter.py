import os
import requests
import gzip
import shutil
import datetime
import ipaddress
import re
from tqdm import tqdm

# Listen-Definitionen, weitere können hinzugefügt werden
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
    """IP-Adresse als String in Integer umwandeln für effiziente Vergleiche."""
    ip = ipaddress.ip_address(ip_str)
    return int(ip)

def int_to_ip(ip_int):
    """Integer zurück in IP-Adresse String umwandeln."""
    return str(ipaddress.ip_address(ip_int))

def merge_ip_ranges(ranges):
    """
    Überlappende und benachbarte IP-Bereiche zusammenführen.

    Args:
        ranges: Liste von Tupeln (start_ip_str, end_ip_str, beschreibung)

    Returns:
        Liste zusammengeführter Tupel (start_ip_str, end_ip_str, beschreibung)
        Statistik-Dict mit raw_count, merged_count, reduction_percent
    """
    if not ranges:
        return [], {'raw_count': 0, 'merged_count': 0, 'reduction_percent': 0}

    # In Integers konvertieren und sortieren
    int_ranges = []
    for start_ip, end_ip, desc in ranges:
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        if start_int <= end_int:
            int_ranges.append((start_int, end_int, desc))

    # Nach Start-IP sortieren, dann nach End-IP
    int_ranges.sort(key=lambda x: (x[0], x[1]))

    raw_count = len(int_ranges)
    merged = []

    if int_ranges:
        current_start, current_end, current_desc = int_ranges[0]

        for start, end, desc in int_ranges[1:]:
            # Prüfen ob Bereiche überlappen oder benachbart sind (innerhalb 1 IP)
            if start <= current_end + 1:
                # Zusammenführen: aktuellen Bereich erweitern falls nötig
                current_end = max(current_end, end)
                # Erste Beschreibung für zusammengeführte Bereiche beibehalten
            else:
                # Keine Überlappung: aktuellen Bereich speichern und neuen starten
                merged.append((int_to_ip(current_start), int_to_ip(current_end), current_desc))
                current_start, current_end, current_desc = start, end, desc

        # Letzten Bereich nicht vergessen
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
    IP-Bereiche aus Quelldatei parsen ohne auf Festplatte zu schreiben.

    Returns:
        Liste von Tupeln (start_ip, end_ip, beschreibung)
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
                log_lines.append(f"[{list_name}] [FEHLER] Zeile {line_num}: Kein gültiger IP-Bereich → {original_line}")
                continue

            ip_start, ip_end = match.groups()
            if not (is_valid_ip(ip_start) and is_valid_ip(ip_end)):
                skipped += 1
                log_lines.append(f"[{list_name}] [FEHLER] Zeile {line_num}: Ungültige IP-Adresse → {original_line}")
                continue

            description = original_line[:match.start()].rstrip(' :').strip()
            if not description:
                description = list_name

            ranges.append((ip_start, ip_end, description))
            converted += 1

            if not original_line.endswith(f"{ip_start}-{ip_end}"):
                corrected += 1

    log_lines.append(f"[{list_name}] Statistik: {converted} verarbeitet, {corrected} korrigiert, {skipped} übersprungen")
    return ranges

def write_merged_ranges(ranges, destination_path, log_lines):
    """Zusammengeführte IP-Bereiche in Zieldatei schreiben."""
    with open(destination_path, 'w', encoding='utf-8') as dst:
        for ip_start, ip_end, description in ranges:
            converted_line = f"{ip_start} - {ip_end} , 000 , {description}"
            dst.write(converted_line + '\n')

    log_lines.append(f"{len(ranges)} zusammengeführte Bereiche nach {destination_path} geschrieben")

def download_and_process_lists(block_list_path):
    block_list_path_resolved = os.path.abspath(block_list_path)
    final_ipfilter_file = os.path.join(block_list_path_resolved, 'ipfilter.dat')
    temp_file = os.path.join(block_list_path_resolved, 'temp_download.gz')
    raw_file = os.path.join(block_list_path_resolved, 'ipfilter_raw.p2p')
    log_file_path = os.path.join(block_list_path_resolved, 'log.txt')
    log_lines = []

    # Log-Kopf mit Datum
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines.append(f"===== IPFilter-Update gestartet: {now} =====\n")

    if os.path.exists(final_ipfilter_file):
        antwort = input(f"Die Datei '{final_ipfilter_file}' existiert bereits. Überschreiben? (j/n): ").strip().lower()
        if antwort != 'j':
            print("Abgebrochen. Die Datei wurde nicht überschrieben.")
            return

    print("Folgende IP-Filterlisten werden heruntergeladen und zusammengeführt:\n")
    for name, _ in LISTS:
        print(f"- {name}")
    print()

    # Alle IP-Bereiche von allen Listen sammeln
    all_ranges = []

    for name, url in LISTS:
        print(f"\n→ Lade Liste: {name}")
        log_lines.append(f"[{name}] Download gestartet")

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

            log_lines.append(f"[{name}] Download erfolgreich")

            # Bereiche aus dieser Liste parsen
            ranges = parse_ip_ranges_from_file(raw_file, log_lines, list_name=name)
            all_ranges.extend(ranges)
            log_lines.append(f"[{name}] {len(ranges)} IP-Bereiche extrahiert")

            os.remove(raw_file)

        except Exception as e:
            log_lines.append(f"[{name}] Download fehlgeschlagen: {str(e)}")
            print(f"✗ Download fehlgeschlagen {name}: {str(e)}")

    if os.path.exists(temp_file):
        os.remove(temp_file)

    # Überlappende und benachbarte IP-Bereiche zusammenführen
    print(f"\n→ Führe {len(all_ranges)} IP-Bereiche zusammen...")
    log_lines.append(f"\n[MERGE] Starte Zusammenführung mit {len(all_ranges)} Gesamtbereichen")

    merged_ranges, merge_stats = merge_ip_ranges(all_ranges)

    log_lines.append(f"[MERGE] Rohe Bereiche: {merge_stats['raw_count']}")
    log_lines.append(f"[MERGE] Zusammengeführte Bereiche: {merge_stats['merged_count']}")
    log_lines.append(f"[MERGE] Reduzierung: {merge_stats['reduction_percent']}%")
    log_lines.append(f"[MERGE] {merge_stats['raw_count'] - merge_stats['merged_count']} doppelte/überlappende Bereiche eliminiert\n")

    # Zusammengeführte Bereiche in Datei schreiben
    write_merged_ranges(merged_ranges, final_ipfilter_file, log_lines)

    log_lines.append(f"\n===== Verarbeitung abgeschlossen =====\n")

    with open(log_file_path, 'w', encoding='utf-8') as log:
        log.write('\n'.join(log_lines))

    print("\n✅ Alle Listen verarbeitet und zusammengeführt.")
    print(f"→ Ergebnis: {final_ipfilter_file}")
    print(f"→ Gesamteinträge: {merge_stats['merged_count']:,} (reduziert von {merge_stats['raw_count']:,})")
    print(f"→ Platzeinsparung: {merge_stats['reduction_percent']}%")
    print(f"→ Protokoll: {log_file_path}")

    print("\nUm die IP-Filterdatei in qBittorrent zu verwenden:")
    print(f"* Öffne qBittorrent → Einstellungen → Verbindung → IP-Filterung")
    print(f"* Wähle die Datei: '{final_ipfilter_file}'")

# Skript ausführen
block_list_path = os.getcwd()
download_and_process_lists(block_list_path)
