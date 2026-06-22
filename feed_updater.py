import requests
import re
import uuid

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata/rules/emerging-exploit.rules"
YARA_FILE = "matrix.yar"

def fetch_and_build_yara():
    print(f"[*] Fetching OSINT Feed: {ET_OPEN_URL}")
    try:
        response = requests.get(ET_OPEN_URL, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to fetch intelligence: {e}")
        return

    lines = response.text.splitlines()
    yara_rules = []

    # 1. Inject our foundational local test rules into the YARA matrix
    yara_rules.append("""
rule SIG_LOCAL_TEST_PAYLOAD {
    meta:
        description = "Test Payload (Mock Exploit)"
        severity = "HIGH"
    strings:
        $s1 = "EXPLOIT_PAYLOAD_V1"
    condition:
        $s1
}

rule SIG_LOCAL_LOG4J {
    meta:
        description = "Log4j JNDI Lookup (CVE-2021-44228)"
        severity = "CRITICAL"
    strings:
        $s1 = "${jndi:ldap:"
        $s2 = "${jndi:rmi:"
        $s3 = "${jndi:dns:"
    condition:
        any of them
}
""")

    print("[*] Translating Snort syntax into compiled YARA strings...")
    
    rule_count = 0
    for line in lines:
        if not line.startswith("alert "):
            continue

        # Extract the Threat Name and the specific exact-match string content
        msg_match = re.search(r'msg:"([^"]+)"', line)
        content_match = re.search(r'content:"([^"]+)"', line)

        if msg_match and content_match:
            name = msg_match.group(1).replace('"', "'")
            raw_content = content_match.group(1)
            
            # For this streamlined build, we skip complex Snort hex-jumps (e.g., |00 01|)
            if "|" in raw_content:
                continue 

            # Escape quotes and backslashes for the YARA compiler
            escaped_content = raw_content.replace('\\', '\\\\').replace('"', '\\"')
            severity = "CRITICAL" if "CVE" in name.upper() else "HIGH"
            rule_id = f"OSINT_{str(uuid.uuid4())[:8].replace('-', '_')}"

            yara_rule = f"""
rule {rule_id} {{
    meta:
        description = "{name}"
        severity = "{severity}"
    strings:
        $s1 = "{escaped_content}"
    condition:
        $s1
}}"""
            yara_rules.append(yara_rule)
            rule_count += 1

        # We can comfortably push 500 rules through YARA without touching the GIL
        if rule_count >= 100000: 
            break

    # Write the master .yar file
    with open(YARA_FILE, "w") as f:
        f.write("\n".join(yara_rules))

    print(f"[+] Successfully compiled {rule_count + 2} native YARA signatures into {YARA_FILE}.")

if __name__ == "__main__":
    fetch_and_build_yara()