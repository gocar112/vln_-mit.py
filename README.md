
2. Installation Guide
To run this tool, you need to install both the system-level scanner (Nmap) and the Python dependencies.

Step 1: Install Nmap
The Python library python-nmap is just a wrapper; you must have the actual Nmap engine installed on your OS.

Windows: Download and run the installer from nmap.org.

Linux (Ubuntu/Debian): sudo apt update && sudo apt install nmap -y

macOS: brew install nmap

Step 2: Install Python Libraries
Run the following command in your terminal/command prompt:

Bash
pip install python-nmap requests mitreattack-python stix2


3. How to Use
Run with Permissions: Nmap often requires root or administrator privileges to perform advanced service detection (-sV).

Linux/Mac: sudo python your_script_name.py

Windows: Run your Command Prompt or PowerShell as Administrator.

Set Your Target: In the if __name__ == "__main__": block, change the target variable.

Single IP: "192.168.1.1"

Range: "192.168.1.0/24"

The Output:

Console: Shows real-time progress and alerts.

enterprise-attack.json: Created on first run (stores MITRE data).

scan_TIMESTAMP.txt: A human-readable summary for your records.

scan_TIMESTAMP.csv: A spreadsheet-ready file for auditing.

⚠️ Disclaimer: Only scan networks and devices you own or have explicit permission to test. Unauthorized scanning can be illegal and easily detected
