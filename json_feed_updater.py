import requests
import re
import json
import uuid

# The global OSINT feed for active network exploits
ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata/rules/emerging-exploit.rules"
RULES_FILE = "rules.json"

def fetch_and_parse_rules():
    print(f"[*] Reaching out to OSINT Feed: {ET_OPEN_URL}")
    try:
        response = requests.get(ET_OPEN_URL, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to fetch intelligence: {e}")
        return

    lines = response.text.splitlines()
    new_signatures = []

    print("[*] Parsing Snort/Suricata syntax into Quantum_IDS JSON schema...")
    
    for line in lines:
        # We only want active alert rules, ignoring comments and config lines
        if not line.startswith("alert "):
            continue

        # 1. Extract the Threat Name (msg parameter)
        msg_match = re.search(r'msg:"([^"]+)"', line)
        if not msg_match:
            continue
        name = msg_match.group(1)

        # 2. Extract the malicious pattern
        # Snort uses 'pcre' for regex, and 'content' for exact strings. 
        # We check for a regex pattern first.
        pattern_match = re.search(r'pcre:"/([^/]+)/', line)
        if pattern_match:
            pattern = pattern_match.group(1)
        else:
            # Fallback: Extract exact string content and escape it for our regex engine
            content_match = re.search(r'content:"([^"]+)"', line)
            if content_match:
                raw_content = content_match.group(1)
                # Escape regex control characters so pure strings don't break the compiler
                pattern = re.escape(raw_content).replace('\\\\', '\\')
            else:
                continue # Skip rules that rely solely on packet headers, as we only scan payloads

        # 3. Dynamic Severity Assignment
        severity = "CRITICAL" if "CVE" in name.upper() else "HIGH"

        new_signatures.append({
            "id": f"OSINT-{str(uuid.uuid4())[:8].upper()}",
            "name": name,
            "severity": severity,
            "pattern": pattern
        })

        # Performance Cap: Prevent Python regex engine death
        if len(new_signatures) >= 99999999999:
            break

    # 4. Inject our local test payloads so we can still verify system health
    new_signatures.extend([
        {
            "id": "SIG-LOCAL-1",
            "name": "Test Payload (Mock Exploit)",
            "severity": "HIGH",
            "pattern": "EXPLOIT_PAYLOAD_V1"
        },
        {
            "id": "SIG-LOCAL-2",
            "name": "Log4j JNDI Lookup (CVE-2021-44228)",
            "severity": "CRITICAL",
            "pattern": "\\$\\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):"
        }
    ])

    # 5. Overwrite the rules.json matrix with the fresh intelligence
    with open(RULES_FILE, "w") as f:
        json.dump({"signatures": new_signatures}, f, indent=4)

    print(f"[+] Intelligence matrix updated successfully.")
    print(f"[+] Wrote {len(new_signatures)} active OSINT signatures to {RULES_FILE}.")

if __name__ == "__main__":
    fetch_and_parse_rules()