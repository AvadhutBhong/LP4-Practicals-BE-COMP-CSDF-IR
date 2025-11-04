import re
import csv
import argparse
from datetime import datetime, timedelta
from collections import Counter, defaultdict

# Regular expression to parse syslog-like Wi-Fi log lines
# Example: "Oct 14 10:25:15 hostapd: wlan0: STA 00:11:22:33:44:55 had failed authentication."
LOG_LINE_REGEX = re.compile(r'(\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)\s+(.*)')

# Regex to extract MAC addresses like 00:11:22:33:44:55
MAC_REGEX = re.compile(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', re.I)

# Suspicious keywords and their forensic meaning
SUSPICIOUS_KEYWORDS = {
    'deauthenticated': 'Potential Deauth Attack',
    'disassociated': 'Unexpected Disconnection',
    'failed authentication': 'Failed Connection Attempt',
    'authentication with': 'Authentication timeout/failed',
    'probe request': 'Network Discovery Attempt',
    'rogue ap': 'Possible Rogue Access Point'
}


def _parse_ts_with_year(ts_str):
    """Parse 'Mon DD HH:MM:SS' safely by appending current year for a full timestamp."""
    try:
        full = f"{ts_str} {datetime.now().year}"
        return datetime.strptime(full, "%b %d %H:%M:%S %Y")
    except Exception:
        return None


def analyze_log_file(log_file_path, output_csv_path, blocked_out,
                     fail_threshold=5, window_minutes=10):
    """
    Analyzes Wi-Fi log file for suspicious access attempts and detects repeated authentication failures.
    Generates CSV and blocked MAC list.
    """
    forensic_events = []  # List of detected suspicious events
    mac_failures = defaultdict(list)  # MAC → list of timestamps for failure events
    all_timestamps = []  # For calculating overall time range

    try:
        with open(log_file_path, 'r', encoding='utf-8') as log_file:
            for line_num, line in enumerate(log_file, 1):
                lower = line.lower()
                for keyword, desc in SUSPICIOUS_KEYWORDS.items():
                    if keyword in lower:
                        # Match date-time at start of log line
                        match = LOG_LINE_REGEX.search(line)
                        ts = None
                        message = line.strip()
                        if match:
                            ts_raw = match.group(1)
                            ts = _parse_ts_with_year(ts_raw) or datetime.now()
                            message = match.group(2).strip()

                        # Extract MAC address
                        m = MAC_REGEX.search(line)
                        mac = m.group(1).lower() if m else ""

                        # Record this suspicious event
                        forensic_events.append({
                            'Timestamp': (ts or datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                            'Line': line_num,
                            'MAC': mac,
                            'Description': desc,
                            'Log Entry': message
                        })
                        all_timestamps.append(ts or datetime.now())

                        # If it looks like an authentication failure, record it for rate analysis
                        if any(k in desc.lower() for k in ('fail', 'authentication', 'timeout')):
                            if mac:
                                mac_failures[mac].append(ts or datetime.now())
                        break
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file_path}")
        return None

    # Detect brute-force attempts: repeated failures in short time window
    blocked = set()
    window = timedelta(minutes=window_minutes)
    for mac, times in mac_failures.items():
        times = sorted(t for t in times if t)
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            if (j - i + 1) >= fail_threshold:
                blocked.add(mac)
                break

    # Write suspicious event log (CSV)
    if forensic_events:
        try:
            with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
                fieldnames = ['Timestamp', 'Line', 'MAC', 'Description', 'Log Entry']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(forensic_events)
        except IOError as e:
            print(f"[ERROR] Cannot write CSV report: {e}")
            return None

    # Write blocked MACs
    try:
        with open(blocked_out, 'w', encoding='utf-8') as bf:
            for m in sorted(blocked):
                bf.write(m + "\n")
    except Exception as e:
        print(f"[WARN] Failed to write blocked MACs: {e}")

    # Summary report for console
    summary = {
        "events": len(forensic_events),
        "unique_macs": len({e['MAC'] for e in forensic_events if e['MAC']}),
        "most_common_reasons": Counter(e['Description'] for e in forensic_events).most_common(),
        "top_macs_by_failures": Counter({mac: len(times) for mac, times in mac_failures.items()}).most_common(5),
        "blocked": sorted(blocked),
        "time_range": None
    }
    if all_timestamps:
        start = min(all_timestamps).strftime('%Y-%m-%d %H:%M:%S')
        end = max(all_timestamps).strftime('%Y-%m-%d %H:%M:%S')
        summary["time_range"] = (start, end)

    return summary


def create_sample_log(file_path):
    """Creates a demo log simulating repeated failed authentication attempts."""
    lines = [
        "Oct 14 10:01:15 hostapd: wlan0: STA ac:87:a3:11:22:33 IEEE 802.11: authenticated",
        "Oct 14 10:15:30 hostapd: wlan0: STA bc:99:c4:44:55:66 IEEE 802.11: deauthenticated due to inactivity.",
        "Oct 14 10:25:15 hostapd: wlan0: STA 54:45:65:76:87:98 had failed authentication.",
    ]
    # Add multiple failures for the same MAC to simulate brute-force attempt
    for i in range(6):
        lines.append(f"Oct 14 10:{30+i:02d}:00 hostapd: wlan0: STA 00:11:22:33:44:55 had failed authentication.")
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print(f"[INFO] Sample log created: {file_path}")


def print_summary(summary, out_prefix, csv_path, blocked_path):
    """Prints human-readable summary on console."""
    if summary is None:
        print("[ERROR] Analysis failed.")
        return
    print("\n=== Wi-Fi Forensic Summary ===")
    print(f"Total suspicious events: {summary['events']}")
    print(f"Unique MACs observed: {summary['unique_macs']}")
    if summary['time_range']:
        print(f"Time range: {summary['time_range'][0]}  to  {summary['time_range'][1]}")
    print("\nTop reasons:")
    for reason, cnt in summary['most_common_reasons'][:5]:
        print(f"  - {reason}: {cnt}")
    print("\nTop MACs by failure count:")
    for mac, cnt in summary['top_macs_by_failures']:
        print(f"  - {mac}: {cnt} failures")
    if summary['blocked']:
        print("\nBlocked MACs (suggested):")
        for m in summary['blocked']:
            print(f"  - {m}")
    else:
        print("\nNo MACs exceeded failure threshold.")
    print(f"\nReports written: {csv_path}  ,  {blocked_path}")
    print("Suggested action: add blocked MACs to AP deny-list or firewall (manual/admin step).")


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Intrusion Detection Simulator")
    parser.add_argument("-i", "--input", default="./wifi.log", help="Log file to analyze")
    parser.add_argument("-o", "--out", default="./forensic_log_analysis.csv", help="CSV output path")
    parser.add_argument("-b", "--blocked", default="./blocked_macs.txt", help="Blocked MACs output path")
    parser.add_argument("--gen-sample", action="store_true", help="Generate sample wifi.log and exit")
    parser.add_argument("--threshold", type=int, default=5, help="Failure threshold to block MAC")
    parser.add_argument("--window", type=int, default=10, help="Sliding window (minutes) for failures")
    args = parser.parse_args()

    if args.gen_sample:
        create_sample_log(args.input)
        return 

    summary = analyze_log_file(args.input, args.out, args.blocked,
                               fail_threshold=args.threshold, window_minutes=args.window)
    print_summary(summary, args.out, args.out, args.blocked)


if __name__ == "__main__":
    main()


"""
Theory (Detailed)

Approach and Working:
---------------------
This program simulates a Wi-Fi Intrusion Detection and Prevention System (IDPS)
designed to detect brute-force or repeated failed authentication attempts
against a wireless network (IEEE 802.11-based).

It works by analyzing wireless log files (typically generated by the Access Point
or hostapd service). These logs contain entries such as authentication attempts,
deauthentication events, probe requests, etc.

Our approach involves:
1. Reading Wi-Fi event logs line by line.
2. Matching suspicious keywords (e.g., "failed authentication", "probe request").
3. Extracting timestamps and MAC addresses of devices from those log lines.
4. Tracking repeated failures within a sliding time window (default: 10 minutes).
5. Automatically flagging any MAC address that exceeds a defined failure threshold (default: 5).
6. Generating a forensic CSV report and a “blocked MAC list” for further administrative action.

Program Flow:
-------------
- Input: A Wi-Fi log file (default `wifi.log`)
- Step 1: Parse the log using regular expressions:
  * `LOG_LINE_REGEX` extracts date and message.
  * `MAC_REGEX` extracts MAC addresses like 00:11:22:33:44:55.
- Step 2: Identify suspicious events by checking for any `SUSPICIOUS_KEYWORDS`.
- Step 3: For each matched line, store:
  - Timestamp
  - MAC address
  - Description (e.g., "Failed Connection Attempt")
  - Original log message
- Step 4: Count repeated failures from the same MAC within a time window.
  Devices that fail too many times are suspected of password cracking/brute-force attempts.
- Step 5: Write all detected events into a CSV report for further analysis.
- Step 6: Write all blocked MACs into a separate text file.
- Step 7: Print a detailed summary (unique MACs, top reasons, time range, etc.)

How to Run:
-----------
1. To generate a demo log:
      python wifi_detect.py --gen-sample
2. To analyze a log:
      python wifi_detect.py -i wifi.log -o report.csv -b blocked.txt
3. To customize thresholds:
      python wifi_detect.py -i wifi.log --threshold 4 --window 15

Understanding the Regex:
------------------------
1. LOG_LINE_REGEX = r'(\\b\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\b)\\s+(.*)'
   - Captures lines like: "Oct 14 10:25:15 hostapd: wlan0: STA ..."
   - Group 1: timestamp (Mon DD HH:MM:SS)
   - Group 2: remainder of log message
2. MAC_REGEX = r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})'
   - Matches MAC addresses such as 00:11:22:33:44:55 (case-insensitive).
   - Explanation:
     * [0-9a-f]{2} matches two hexadecimal digits.
     * (?: : [0-9a-f]{2}){5} repeats “:xx” five more times.

IEEE 802.11 Context:
--------------------
- The program assumes a standard Wi-Fi network with an Access Point (AP)
  and multiple stations (STAs or clients).
- Events like “deauthenticated” or “failed authentication” originate
  from 802.11 management frames and are logged by AP software (e.g., hostapd).
- A brute-force attacker near the network repeatedly tries passwords
  for the same SSID. The AP logs these repeated failures.

Simulated Configuration:
------------------------
- Wi-Fi adapter and Access Point configured via `hostapd.conf`.
- The AP generates logs like `/var/log/syslog` or `/var/log/hostapd.log`.
- Our script reads such logs and automatically detects intrusions.

Forensic Interpretation:
------------------------
- “Failed authentication” indicates password-guessing attempts.
- “Probe request” means scanning for available networks (possible reconnaissance).
- “Deauthenticated” or “disassociated” may indicate denial-of-service attacks.
- Multiple failures from the same MAC → password cracking attempt.

Blocking Policy:
----------------
Once a MAC address exceeds the failure threshold within the specified window:
- It is added to a blocklist file (`blocked_macs.txt`).
- Administrators can manually add these MACs to the Access Point’s deny list.

Security Relevance:
-------------------
This kind of detection protects Wi-Fi resources (e.g., IP printers, routers)
from unauthorized users or attackers trying to exploit network access.
While it cannot fully prevent sophisticated attacks, it provides valuable
local intrusion detection and forensic auditing capability.

Limitations and Future Enhancements:
-----------------------------------
- Real-time monitoring (via socket tailing) can be added for live detection.
- Integration with firewall or AP controller APIs can automate MAC blocking.
- Machine learning can improve anomaly detection (e.g., time-of-day, device behavior).
- Could be extended to include deauth flood detection and rogue AP identification.

In short:
---------
This program demonstrates the forensic detection of unauthorized Wi-Fi access attempts
by analyzing IEEE 802.11 log data. It simulates a real-world access point monitoring tool
and showcases how repeated failed authentications can reveal password-cracking attempts.
"""
