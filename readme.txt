Automated Security Testing Tool
This repository contains an automated security testing tool designed to simplify the process of running various security tests on a target domain. The tool integrates multiple security tools and scripts to perform comprehensive security assessments, including subdomain enumeration, port scanning, vulnerability detection, and more.

Features
Subdomain Enumeration: Identify subdomains using subfinder and crt.sh.
Alive Subdomain Checking: Verify which subdomains are active using httpx-toolkit.
Port Scanning: Scan for open ports using naabu.
URL Collection: Collect URLs using katana, waybackurls, and gau.
Directory and File Enumeration: Discover sensitive files and directories using gobuster and dirsearch.
JavaScript Analysis: Identify and analyze JavaScript files for potential vulnerabilities using SecretFinder.
Subdomain Takeover Detection: Detect potential subdomain takeovers using subzy.
Vulnerability Scanning: Scan for various vulnerabilities using nuclei, dalfox, corsy, and other tools.
Open Redirection Detection: Identify open redirection vulnerabilities using openredirex.
Prerequisites
Before using this tool, ensure you have the following installed:

A Unix-like operating system (e.g., Linux, macOS)
Python 3
pip (Python package installer)
Installation
Clone the repository and navigate to the project directory:

bash
git clone https://github.com/arthacker619/automated-security-tool
cd automated-security-tool
Run the setup script to install all the necessary tools and dependencies:

bash
chmod +x setup.sh
./setup.sh
Usage
To run the automated security testing tool, execute the autosec.sh script with the target domain as an argument:

bash
chmod +x autosec.sh
./autosec.sh example.com
Output
The script will create a directory named target_example.com and log all outputs to output.log within that directory. Review the output.log file to see the results of the automated security tests.

Disclaimer
This tool is intended for educational purposes and authorized security testing only. Use it responsibly and ensure you have permission to test the target systems. The author is not responsible for any misuse or damage caused by this tool.

