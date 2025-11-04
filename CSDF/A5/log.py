import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
import argparse

# LOG_PATTERNS dictionary maps descriptive event types to regex patterns
# Each regex helps detect specific security events in log files.
LOG_PATTERNS = {
    # Detect failed SSH login attempts: captures username and IP address
    'failed_login': re.compile(r'sshd.*Failed password for (\w+) from ([\d\.]+)'),

    # Detect successful SSH logins: captures username and IP address
    'accepted_login': re.compile(r'sshd.*Accepted password for (\w+) from ([\d\.]+)'),

    # Detect 'sudo' command attempts (user privilege escalation)
    # Captures username, terminal (TTY), working directory (PWD), target user, and executed command
    'sudo_attempt': re.compile(r'sudo.*(\w+)\s*:\s*TTY=([^\s;]+)\s*;\s*PWD=([^;]+)\s*;\s*USER=(\w+)\s*;\s*COMMAND=(.*)'),

    # Detect successful 'sudo' sessions (root access granted)
    'sudo_success': re.compile(r'sudo.*session opened for user (\w+) by (\w+)'),

    # Detect authentication failures in general (common PAM format)
    'auth_failure': re.compile(r'authentication failure;.*rhost=([\d\.]+)\s+user=(\w*)'),

    # Detect closed SSH connections and extract IP
    'connection_closed': re.compile(r'sshd.*Connection closed by ([\d\.]+)'),

    # Detect invalid login attempts using non-existent users
    'invalid_user': re.compile(r'sshd.*Invalid user (\w+) from ([\d\.]+)'),

    # Detect potential port scanning attempts where connection not fully established
    'port_scan': re.compile(r'sshd.*Did not receive identification string from ([\d\.]+)'),

    # Detect repeated identical messages (e.g., brute-force retry attempts)
    'brute_force': re.compile(r'sshd.*message repeated (\d+) times'),

    # Detect firewall drops or rejects, capturing source IP
    'firewall_block': re.compile(r'iptables.*(DROP|REJECT).*SRC=([\d\.]+)')
}


# Class to represent a single security event parsed from logs
class SecurityEvent:
    def __init__(self, timestamp, event_type, details):
        self.timestamp = timestamp
        self.event_type = event_type
        self.details = details


# Main Analyzer class responsible for correlating and summarizing logs
class LogAnalyzer:
    def __init__(self):
        self.events = defaultdict(list)          # Stores events grouped by type
        self.ip_activity = defaultdict(list)     # Tracks activity per IP address
        self.user_activity = defaultdict(list)   # Tracks activity per user
        self.suspicious_ips = set()              # Stores IPs flagged for rapid/failed attempts
        self.attack_patterns = defaultdict(int)  # Counts of attack patterns detected

    def analyze_line(self, line):
        # Extract timestamp (e.g., "Oct 14 10:01:15") using regex at line start
        timestamp_match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        if not timestamp_match:
            return  # skip if line doesn't contain a timestamp

        timestamp = timestamp_match.group(1)

        # Match the line against each known event pattern
        for event_type, pattern in LOG_PATTERNS.items():
            match = pattern.search(line)
            if match:
                # Create SecurityEvent object if pattern matches
                event = SecurityEvent(timestamp, event_type, match.groups())
                self.process_event(event)
                break  # stop at first match to avoid multiple classification

    def process_event(self, event):
        # Store event by its type
        self.events[event.event_type].append(event)
        
        ip = None
        user = None
        
        # For failed logins or invalid users, capture IP and username
        if event.event_type in ('failed_login', 'invalid_user'):
            user, ip = event.details[0], event.details[1]

            # Record per-IP event
            if ip:
                self.ip_activity[ip].append(event)
                # Detect rapid multiple attempts within 60 seconds
                if len(self.ip_activity[ip]) >= 3:
                    recent = self.ip_activity[ip][-3:]
                    if self.is_rapid_succession(recent):
                        self.suspicious_ips.add(ip)
                        self.attack_patterns['rapid_attempts'] += 1

            # Record per-user activity
            if user:
                self.user_activity[user].append(event)
                # Sensitive accounts (root/admin) are marked as critical
                if user in ('root', 'admin', 'administrator'):
                    self.attack_patterns['sensitive_user_attempt'] += 1

    def is_rapid_succession(self, events):
        # Detect if multiple failed logins occurred within 1 minute window
        if len(events) < 2:
            return False
        try:
            times = [datetime.strptime(e.timestamp, "%b %d %H:%M:%S") for e in events]
            return (times[-1] - times[0]).seconds <= 60
        except:
            return False

    def print_detailed_report(self):
        print("\n" + "="*80)
        print(" SECURITY LOG ANALYSIS REPORT")
        print("="*80)
        
        # ----- Temporal Analysis -----
        print("\n TEMPORAL ANALYSIS")
        print("-"*50)
        timestamps = [
            datetime.strptime(e.timestamp, "%b %d %H:%M:%S") 
            for events in self.events.values() 
            for e in events
        ]
        if timestamps:
            print(f"First Event: {min(timestamps).strftime('%b %d %H:%M:%S')}")
            print(f"Last Event:  {max(timestamps).strftime('%b %d %H:%M:%S')}")
            print(f"Time Span:   {str(max(timestamps) - min(timestamps))}")
        
        # ----- Authentication Statistics -----
        print("\n AUTHENTICATION EVENTS")
        print("-"*50)
        failed = len(self.events['failed_login'])
        success = len(self.events['accepted_login'])
        total = failed + success
        if total > 0:
            fail_rate = (failed / total) * 100
            print(f"Total Auth Attempts: {total:,}")
            print(f"Failed Attempts:     {failed:,} ({fail_rate:.1f}%)")
            print(f"Successful Logins:  {success:,} ({100-fail_rate:.1f}%)")
        
        # ----- Suspicious Activity -----
        print("\n SUSPICIOUS ACTIVITY")
        print("-"*50)
        if self.suspicious_ips:
            print(f"Detected {len(self.suspicious_ips)} suspicious IPs:")
            for ip in sorted(self.suspicious_ips):
                attempts = len([e for e in self.ip_activity[ip] 
                              if e.event_type in ('failed_login', 'invalid_user')])
                print(f"\n• IP: {ip}")
                print(f"  └─ Failed Attempts: {attempts}")
                print(f"  └─ First Seen: {self.ip_activity[ip][0].timestamp}")
                print(f"  └─ Last Seen:  {self.ip_activity[ip][-1].timestamp}")
        
        # ----- User Activity -----
        print("\n USER ACTIVITY ANALYSIS")
        print("-"*50)
        for user, events in self.user_activity.items():
            failed = len([e for e in events if e.event_type == 'failed_login'])
            success = len([e for e in events if e.event_type == 'accepted_login'])
            unique_ips = len(set(e.details[1] for e in events if len(e.details) > 1))
            
            if failed + success > 0:
                print(f"\nUser: {user}")
                print(f"  ├─ Total Attempts: {failed + success}")
                print(f"  ├─ Failed Logins: {failed}")
                print(f"  ├─ Successful Logins: {success}")
                print(f"  └─ Unique IPs: {unique_ips}")
        
        # ----- Attack Pattern Summary -----
        print("\n ATTACK PATTERN ANALYSIS")
        print("-"*50)
        if self.attack_patterns:
            for pattern, count in self.attack_patterns.items():
                print(f"• {pattern.replace('_', ' ').title()}: {count} instances")
        
        print("\n" + "="*80)
        print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Enhanced Security Log Analyzer")
    parser.add_argument("-f", "--file", default="sys.log", help="Log file to analyze")
    args = parser.parse_args()

    analyzer = LogAnalyzer()
    
    try:
        with open(args.file, 'r') as f:
            print(f"\n🔍 Analyzing log file: {args.file}")
            for line in f:
                analyzer.analyze_line(line.strip())
    except FileNotFoundError:
        print(f" Error: Could not find log file '{args.file}'")
        return

    analyzer.print_detailed_report()


if __name__ == "__main__":
    main()


"""
============================================
THEORY: LOG CAPTURING AND EVENT CORRELATION
============================================

**Objective:**
This experiment focuses on collecting system logs, identifying security events, 
and correlating them to detect potential cyberattacks or abnormal system behavior.

**Approach:**
1. System logs (e.g., /var/log/auth.log, syslog) are parsed line by line.
2. Each line is matched against a set of regex patterns designed to detect:
   - Failed and successful logins (via SSH)
   - Privilege escalations (sudo usage)
   - Firewall blocks and authentication failures
   - Suspicious repeated messages indicating brute-force attempts
3. Extracted events are grouped and analyzed by user, IP, and time.
4. Correlation logic identifies:
   - Rapid failed attempts from the same IP (brute-force attacks)
   - Repeated access to sensitive accounts (root/admin)
   - Time-based analysis for identifying coordinated attempts
5. A summary report shows suspicious users, IPs, and attack patterns.

**Explanation of Regex Patterns:**
- `r'sshd.*Failed password for (\w+) from ([\d\.]+)'`
  → Matches “Failed password” logs from SSHD, capturing username & IP.
- `r'sudo.*COMMAND=(.*)'`
  → Captures commands executed via `sudo` for tracking privilege escalation.
- `r'sshd.*Invalid user (\w+) from ([\d\.]+)'`
  → Detects login attempts by invalid/nonexistent users.
- `r'sshd.*message repeated (\d+) times'`
  → Indicates repeated identical log messages, common in brute-force attempts.

**Event Correlation:**
- Uses time windows (1 minute) to detect rapid repeated attempts.
- Maintains counters of failed vs successful logins per user and IP.
- Flags IPs making 3 or more failed attempts within 60 seconds.

**Concepts Demonstrated:**
- Log parsing and regex-based extraction
- Event correlation (temporal + contextual)
- Intrusion detection basics
- Attack surface monitoring and alert generation
- Security auditing and forensic data extraction

**How to Run:**
1. Prepare a sample log file (e.g., `sys.log`) with system events.
2. Run the program using:
      python log_analysis.py -f sys.log
3. It will print a detailed terminal report highlighting:
   - Time range of captured events
   - Failed/success login ratio
   - Suspicious IPs and users
   - Possible attack patterns

**Outcome:**
The experiment demonstrates how real-world security systems (like SIEM tools)
analyze logs to detect anomalies and potential breaches by correlating multiple
event sources in time and context.
"""
