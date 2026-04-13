import nmap
import requests
import json
import socket
from mitreattack.stix20 import MitreAttackData
from datetime import datetime
import os
import csv

class AdvancedSecurityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
        # Note: In a production environment, download this file locally 
        # to avoid slow network lookups during every initialization.
        self.stix_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        
        print("[*] Initializing Scanner...")
        try:
            # We fetch the data and save it locally if it doesn't exist
            if not os.path.exists("enterprise-attack.json"):
                print("[*] Downloading MITRE ATT&CK data (this may take a moment)...")
                r = requests.get(self.stix_url)
                with open("enterprise-attack.json", "wb") as f:
                    f.write(r.content)
            
            self.mitre_db = MitreAttackData("enterprise-attack.json")
            print("[*] MITRE ATT&CK Data Loaded.")
        except Exception as e:
            print(f"[!] Warning: Could not load MITRE data: {e}")
            self.mitre_db = None

        self.cve_data = self.load_cve_database()

    def load_cve_database(self):
        """Simplified CVE mapping for demonstration"""
        return {
            "CVE-2021-44228": {
                "title": "Log4Shell",
                "cvss": 10.0,
                "description": "Critical RCE in Apache Log4j 2.",
                "cwe": "CWE-502",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
            },
            "CVE-2021-34527": {
                "title": "PrintNightmare",
                "cvss": 8.1,
                "description": "RCE in Windows Print Spooler.",
                "cwe": "CWE-121",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"]
            },
            "CVE-2020-14882": {
                "title": "WebLogic RCE",
                "cvss": 9.8,
                "description": "RCE in Oracle WebLogic Server.",
                "cwe": "CWE-79",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"]
            }
        }

    def scan_network(self, target_range):
        """Performs an Nmap service scan."""
        print(f"[*] Scanning: {target_range}")
        # -sV enables service version detection
        self.nm.scan(target_range, arguments='-sV -T4 --top-ports 100')

        findings = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                for port in lport:
                    state = self.nm[host][proto][port]['state']
                    if state == 'open':
                        findings.append({
                            "host": host,
                            "port": port,
                            "service": self.nm[host][proto][port].get('name', 'unknown'),
                            "version": self.nm[host][proto][port].get('version', 'unknown'),
                            "product": self.nm[host][proto][port].get('product', 'unknown')
                        })
        return findings

    def get_mitre_patch(self, tech_id):
        """Fetches enterprise mitigations from MITRE library."""
        if not self.mitre_db:
            return ["MITRE data not available."]
        try:
            # Get technique by ID (e.g., T1190)
            technique = self.mitre_db.get_object_by_attack_id(tech_id, 'attack-pattern')
            if not technique:
                return ["No specific mitigation found."]
            
            mitigations = self.mitre_db.get_mitigations_mitigating_technique(technique.id)
            return [m.get('description', 'No description') for m in mitigations]
        except Exception as e:
            return [f"Error mapping MITRE: {str(e)}"]

    def get_cve_for_service(self, service, version):
        """Mapping logic for service to CVEs"""
        cve_map = {
            "http": ["CVE-2021-44228", "CVE-2020-14882"],
            "ms-wbt-server": ["CVE-2021-34527"],
            "smb": ["CVE-2021-34527"]
        }
        return cve_map.get(service.lower(), [])

    def generate_reports(self, findings):
        """Wrapper for generating both text and CSV reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"scan_{timestamp}.txt"
        csv_file = f"scan_{timestamp}.csv"

        # ATT&CK Technique Map
        tech_map = {
            80: "T1190", 443: "T1190", 3389: "T1021.001", 445: "T1021.002", 22: "T1021.004"
        }

        with open(txt_file, 'w') as f, open(csv_file, 'w', newline='') as cf:
            writer = csv.writer(cf)
            writer.writerow(['Host', 'Port', 'Service', 'ATT&CK ID', 'CVEs'])

            f.write(f"Security Report - {timestamp}\n" + "="*30 + "\n")
            
            for issue in findings:
                tid = tech_map.get(issue['port'], "T1046")
                cves = self.get_cve_for_service(issue['service'], issue['version'])
                
                f.write(f"\n[!] Host: {issue['host']} | Port: {issue['port']} ({issue['service']})\n")
                f.write(f"    ATT&CK ID: {tid}\n")
                f.write(f"    Possible CVEs: {', '.join(cves) if cves else 'None'}\n")
                
                writer.writerow([issue['host'], issue['port'], issue['service'], tid, "|".join(cves)])

        print(f"[+] Reports saved: {txt_file}, {csv_file}")

if __name__ == "__main__":
    scanner = AdvancedSecurityScanner()
    
    # Use real scan (Requires Sudo/Admin for some Nmap features)
    # target = "127.0.0.1" 
    # results = scanner.scan_network(target)
    # scanner.generate_reports(results)

    # Demo mode with sample data
    print("\n--- Running Demo Mode ---")
    sample_data = [{
        "host": "192.168.1.10", "port": 80, "service": "http", 
        "version": "2.4.49", "product": "Apache"
    }]
    scanner.generate_reports(sample_data)