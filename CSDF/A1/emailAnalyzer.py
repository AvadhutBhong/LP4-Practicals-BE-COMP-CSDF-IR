import re
import json
import argparse
from email import message_from_string

# suspicious words we flag in subject (lowercase matching later)
SUSPICIOUS_SUBJECT = {"urgent", "win", "lottery", "verify", "click here", "offer", "free"}
# phishing-like keywords we look for inside the plain-text body (lowercase matching later)
PHISHING_WORDS = {"password", "account suspended", "verify", "click below", "update info", "bank", "ssn"}


def extract_basic_fields(msg):
    # collect a fixed set of header fields for quick inspection and inclusion in reports
    # msg.get(name, "") returns the header value if present else an empty string
    fields = {}
    for name in ("From", "To", "Subject", "Date", "Return-Path", "Message-ID"):
        fields[name] = msg.get(name, "")
    return fields


def extract_received_ips(msg):
    # parse 'Received' headers to extract IPv4 addresses. Received headers are added by MTAs
    # as the mail traverses servers and are the primary source for tracing email hops.
    ips = []
    # msg.get_all("Received", []) returns a list of strings (each Received header) or [] if none.
    for r in msg.get_all("Received", []) or []:
        # regex explanation (the pattern used below):
        # r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?"
        # - \[?         : optional opening square bracket '[' (some Received headers enclose IPs in [])
        # - (           : start capture group 1 (we want the IPv4 string)
        #   \d{1,3}     : 1 to 3 decimal digits (first octet)
        #   (?:\.\d{1,3}){3} : non-capturing group (a dot followed by 1-3 digits) repeated 3 times -> completes 4 octets
        # - )           : end capture group
        # - \]?         : optional closing square bracket ']'
        # This captures typical IPv4 appearances like 192.168.0.1 or [203.0.113.5].
        m = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", r)
        if m:
            # append the captured IP string (group 1)
            ips.append(m.group(1))
    return ips


def get_body_text(msg):
    # Extracts and returns the plain text body of the email (concatenates multiple text/plain parts).
    # Handles multipart messages and single-part messages.
    text = ""
    try:
        if msg.is_multipart():
            # msg.walk() iterates over all MIME parts (text/plain, text/html, attachments, etc.)
            for part in msg.walk():
                # We take only text/plain parts to avoid HTML, attachments and binary content.
                if part.get_content_type() == "text/plain":
                    # get_payload(decode=True) returns bytes when content-transfer-encoding is used
                    payload = part.get_payload(decode=True)
                    if payload:
                        # decode bytes to str; ignore decode errors to be robust against bad encodings
                        text += payload.decode(errors="ignore")
        else:
            # single-part messages: payload may be bytes or already a string
            payload = msg.get_payload(decode=True)
            if isinstance(payload, (bytes, bytearray)):
                text = payload.decode(errors="ignore")
            else:
                # if decode=True returned None (no encoding) or content already str
                text = msg.get_payload() or ""
    except Exception:
        # On any unexpected structure or decoding issue, return empty string instead of raising
        text = ""
    return text


def analyze(raw_email):
    # Main analysis function: parse the raw RFC-822 email text and produce a structured report.
    # message_from_string builds an email.message.Message object from raw headers+body.
    msg = message_from_string(raw_email)

    # prepare the initial report structure
    report = {"fields": extract_basic_fields(msg), "score": 0, "reasons": [], "ips": []}

    # lowercase the raw text to simplify substring checks for tokens like "spf=fail"
    header_lower = raw_email.lower()

    # Authentication checks:
    # Many MTAs or spam filters append authentication results (SPF/DKIM/DMARC) into headers.
    # Presence of tokens like "spf=fail", "dkim=fail" or "dmarc=fail" is a strong indicator
    # of authentication failure (increasing suspicion).
    if "spf=fail" in header_lower or "dkim=fail" in header_lower or "dmarc=fail" in header_lower:
        report["score"] += 2
        report["reasons"].append("Authentication failure token found")

    # Domain mismatch check:
    # Compare domain part of From header vs Return-Path (SMTP envelope sender).
    # A mismatch can indicate forged From headers (common in phishing).
    from_addr = report["fields"].get("From", "")
    ret_path = report["fields"].get("Return-Path", "")
    if "@" in from_addr and "@" in ret_path:
        # strip angle brackets and whitespace, extract domain (part after last '@') and lowercase
        from_dom = from_addr.split("@")[-1].strip(" <>").lower()
        ret_dom = ret_path.split("@")[-1].strip(" <>").lower()
        if from_dom and ret_dom and from_dom != ret_dom:
            report["score"] += 1
            report["reasons"].append(f"Domain mismatch: From({from_dom}) != Return-Path({ret_dom})")

    # Subject heuristics:
    # If subject contains any of the predefined suspicious words, raise score.
    subj = (report["fields"].get("Subject") or "").lower()
    if any(w in subj for w in SUSPICIOUS_SUBJECT):
        report["score"] += 2
        report["reasons"].append("Suspicious words in subject")

    # Body checks:
    # Look for URLs and phishing-like keywords in the extracted plain-text body.
    body = get_body_text(msg)
    if re.search(r"http[s]?://", body or ""):
        # presence of external links is common in phishing attempts
        report["score"] += 1
        report["reasons"].append("External link detected in body")
    if any(w in (body or "").lower() for w in PHISHING_WORDS):
        report["score"] += 2
        report["reasons"].append("Phishing-like keywords in body")

    # Received hops analysis:
    # Extract IPs from Received headers and count hops. More hops or zero hops can be meaningful.
    ips = extract_received_ips(msg)
    report["ips"] = ips
    report["hops"] = len(ips)
    if len(ips) == 0:
        # If no Received headers exist, tracing the origin is not possible from headers alone.
        report["reasons"].append("No Received headers found (cannot trace hops)")
    elif len(ips) > 6:
        # unusually many hops could indicate complex routing (or forwarded through many relays)
        report["score"] += 1
        report["reasons"].append(f"High hop count: {len(ips)}")

    # Verdict thresholds (these are simple heuristics; adjustable in real deployments)
    s = report["score"]
    if s >= 5:
        report["verdict"] = "Very likely SPAM/PHISHING"
    elif s >= 3:
        report["verdict"] = "Suspicious - manual review recommended"
    else:
        report["verdict"] = "Likely legitimate"

    return report


def save_report(report, out_prefix="email_report"):
    # Persist both a machine-readable JSON report and a human-readable text summary.
    with open(out_prefix + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(out_prefix + ".txt", "w", encoding="utf-8") as f:
        f.write("=== EMAIL ANALYSIS SUMMARY ===\n\n")
        for k, v in report["fields"].items():
            f.write(f"{k}: {v}\n")
        f.write(f"\nVerdict: {report['verdict']}\nScore: {report['score']}\n\nReasons:\n")
        for r in report["reasons"]:
            f.write(" - " + r + "\n")
        f.write("\nHops (IPs): " + ", ".join(report.get("ips", [])) + "\n")


def main():
    # CLI argument parsing: input file and output prefix (both optional with defaults)
    parser = argparse.ArgumentParser(description="Simple email header analyzer")
    parser.add_argument("-i", "--input", default="email_sample.txt", help="Raw email file")
    parser.add_argument("-o", "--out", default="email_report", help="Output report prefix")
    args = parser.parse_args()

    try:
        # Read the raw email file as plain text (must include full headers and body)
        with open(args.input, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        print("Failed to read input file:", e)
        return

    # Run analysis and save results
    report = analyze(raw)
    save_report(report, args.out)

    # Print a compact summary to the console for quick inspection
    print("From:", report["fields"].get("From"))
    print("Subject:", report["fields"].get("Subject"))
    print("Verdict:", report["verdict"])
    print("Score:", report["score"])
    print("Hops:", report.get("hops"))
    print(f"Reports: {args.out}.json  {args.out}.txt")


if __name__ == "__main__":
    main()


"""
Theory (very detailed)

Approach summary (what we do and how the program works)
-------------------------------------------------------
This script performs a lightweight forensic analysis of an email. The overall approach:
1. Read a raw email file (RFC-822 format: full headers + body).
2. Parse it into a structured email.message.Message object using Python's `email` package.
3. Extract a set of important headers (From, To, Subject, Date, Return-Path, Message-ID).
4. Extract Received headers and parse IPv4 addresses from them to build a hop list (trace path).
5. Extract plain-text body content (handle multipart emails robustly).
6. Apply a series of heuristics:
   - Check for SPF/DKIM/DMARC failure tokens in headers.
   - Compare domain in From vs Return-Path for possible forgery.
   - Look for suspicious words in Subject.
   - Look for URLs and phishing keywords in the body.
   - Penalize unusual hop counts or missing Received headers.
7. Aggregate heuristic results into a numeric score and derive a simple verdict:
   - score >= 5 -> "Very likely SPAM/PHISHING"
   - score >= 3 -> "Suspicious - manual review recommended"
   - else -> "Likely legitimate"
8. Produce both machine-readable (JSON) and human-readable (TXT) reports.

How to run the program
----------------------
1. Prepare a raw email file that includes headers and body (example: copy headers+body from an email client -> save as email_sample.txt).
2. Run from command line:
   python your_script.py -i email_sample.txt -o my_report_prefix
   - If you omit -i, it defaults to "email_sample.txt".
   - The script writes my_report_prefix.json and my_report_prefix.txt.
3. Inspect console output for a quick verdict, then open the JSON/TXT files for full details.

Important implementation details and reasoning
----------------------------------------------
1) Parsing the email:
   - `message_from_string(raw)` converts raw RFC-822 format into an object where headers and body
     can be accessed via `msg.get(...)`, `msg.get_all(...)`, `msg.is_multipart()`, `msg.walk()`, and `msg.get_payload()`.
   - It's crucial to preserve the raw email for forensic integrity; do not alter headers before analysis.

2) Received headers and hop tracing:
   - Each MTA that handles the message typically appends a Received header (top-to-bottom). These headers often contain IP addresses.
   - We extract IPv4-like patterns from Received header strings with a regex. The earliest public IP (usually the last relevant in the chain) often indicates the originating MTA.
   - Be aware of internal/private IPs or relays — not every IP directly links to the actor (could be a compromised relay).

3) Regex explanation (used in extract_received_ips):
   - Pattern: r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?"
     - `\[?` optionally matches '[' because Received headers sometimes show IPs as [1.2.3.4].
     - `(\d{1,3}(?:\.\d{1,3}){3})` captures four decimal octets:
         - `\d{1,3}` matches 1 to 3 digits (an octet).
         - `(?:\.\d{1,3}){3}` matches a dot + 1-3 digits three times (non-capturing).
       Together they match typical IPv4 forms like 192.168.0.1.
     - `\]?` optionally matches the closing bracket.
   - Limitations: This does not validate that each octet <= 255. It is deliberately simple for speed and coverage.
     For stricter validation, further checks or a more complex regex would be needed.

4) Extracting body text:
   - Emails often include both text/plain and text/html parts; this script prefers text/plain for analysis.
   - For multipart messages, `msg.walk()` visits all parts; we collect text/plain parts and decode them.
   - We call `part.get_payload(decode=True)` to get bytes (if encoded) and decode with error-ignoring fallback.
   - If only HTML is present, this script won't analyze HTML content unless converted to text — an improvement for production.

5) Heuristics & scoring:
   - Score increments are additive and represent suspicion level. The chosen values are heuristic and intentionally simple for teaching.
   - Authentication failures are weighted higher (SPF/DKIM/DMARC failures are strong indicators).
   - Presence of links and phishing keywords in body are also strong signals.
   - Domain mismatch between From and Return-Path suggests forgery/spoofing (Return-Path is the SMTP envelope sender).
   - Hop counts: zero hops reduce traceability; unusually many hops can suggest forwarding through many systems (or botnets).
   - These heuristics are not definitive proof — they are triage indicators for manual review.

6) Limitations and evasion techniques:
   - Headers can be forged by attackers; Received headers may be altered by relays.
   - Attackers may send through legitimate servers (compromised accounts), producing "clean" headers and bypassing simple checks.
   - URL obfuscation, use of URL shorteners, HTML-only content, or images with embedded text can defeat keyword searches.
   - Short, targeted phishing emails (no suspicious words) may evade detection.

7) Enhancements for a production system (suggestions without changing current script logic):
   - Parse Authentication-Results header explicitly to extract structured SPF/DKIM/DMARC results rather than substring matching.
   - Expand regex to handle IPv6 and validate IPv4 octet ranges.
   - Convert HTML to plain text (e.g., using an HTML parser) and analyze links by expanding short URLs.
   - Integrate WHOIS, ASN lookup, and threat intelligence feeds (malicious domain lists) for IP and domain enrichment.
   - Add logging, error handling, and unit tests for robustness.

8) Forensic best practices:
   - Always keep the original raw email intact and store it in a secure evidence store.
   - Correlate header findings with server logs, SMTP transaction logs, and network captures for stronger attribution.
   - Record timestamps, analyst notes, and any enrichment queries (whois, geolocation) used during analysis.

Security, privacy and legal notes
-------------------------------
- The report may contain personal or sensitive data (email addresses, IPs). Treat reports securely.
- Follow your organization's policies and applicable laws for evidence handling and privacy when investigating emails.

Summary
-------
This script is intentionally lightweight and educational: it demonstrates core email-forensic techniques
(header parsing, Received/IP extraction, body keyword checks, simple scoring and reporting). The logic
has been kept minimal and clear so you can extend it with more advanced parsing, threat intelligence,
and validation features in future iterations.
"""
