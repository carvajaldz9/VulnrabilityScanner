#!/usr/bin/env python3
"""
Cross-Platform Automated Vulnerability Scanner
Author: Diego Carvajal
Date: 5/17/2025

This tool combines Nmap scanning with CVE lookup and exploit database matching.
Works on both Windows and Linux systems.
"""
import re
import os
import sys
import json
import subprocess
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict

# Cross-platform configuration
IS_WINDOWS = os.name == 'nt'
NMAP_WINDOWS_PATH = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
NMAP_LINUX_PATH = "/usr/bin/nmap"
EXPLOITDB_WINDOWS_PATH = "C:\\Program Files (x86)\\ExploitDB"
EXPLOITDB_LINUX_PATH = "/usr/share/exploitdb"
NVD_API_KEY = ""  # Get from NVD website
OUTPUT_DIR = "scan_results"

class VulnerabilityScanner:
    def __init__(self):
        self.create_output_dir()
        self.cpe_cache = {}
        self.service_cache = {}
        self.nmap_path = self.detect_nmap_path()
        self.exploitdb_path = self.detect_exploitdb_path()

    def detect_nmap_path(self):
        """Detect Nmap installation path based on OS"""
        if IS_WINDOWS:
            if os.path.exists(NMAP_WINDOWS_PATH):
                return NMAP_WINDOWS_PATH
            # Try common alternative Windows paths
            alt_paths = [
                os.path.expandvars("%ProgramFiles%\\Nmap\\nmap.exe"),
                os.path.expandvars("%ProgramFiles(x86)%\\Nmap\\nmap.exe")
            ]
            for path in alt_paths:
                if os.path.exists(path):
                    return path
        else:
            if os.path.exists(NMAP_LINUX_PATH):
                return NMAP_LINUX_PATH
            # Try to find nmap in PATH
            try:
                which_nmap = subprocess.check_output(["which", "nmap"], stderr=subprocess.PIPE).decode().strip()
                if which_nmap:
                    return which_nmap
            except:
                pass
        
        print("[-] Nmap not found in standard locations. Please ensure Nmap is installed.")
        return "nmap"  # Fall back to hoping it's in PATH

    def detect_exploitdb_path(self):
        """Detect ExploitDB installation path based on OS"""
        if IS_WINDOWS:
            if os.path.exists(EXPLOITDB_WINDOWS_PATH):
                return EXPLOITDB_WINDOWS_PATH
        else:
            if os.path.exists(EXPLOITDB_LINUX_PATH):
                return EXPLOITDB_LINUX_PATH
            # Try common Linux alternative paths
            alt_paths = [
                "/opt/exploitdb",
                os.path.expanduser("~/.local/share/exploitdb")
            ]
            for path in alt_paths:
                if os.path.exists(path):
                    return path
        print("[-] ExploitDB not found. Some features may be limited.")
        return None

    def create_output_dir(self):
        """Ensure output directory exists (cross-platform)"""
        try:
            if not os.path.exists(OUTPUT_DIR):
                os.makedirs(OUTPUT_DIR)
                print(f"[+] Created output directory: {OUTPUT_DIR}")
        except Exception as e:
            print(f"[-] Error creating output directory: {e}")
            sys.exit(1)

    def run_nmap_scan(self, target, scan_type="discovery"):
        """Run Nmap scan and return parsed results (cross-platform)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(OUTPUT_DIR, f"nmap_{target}_{timestamp}.xml")

        scan_profiles = {
            "discovery": "-sV -O --top-ports 100",
            "full": "-sV -O -p-",
            "vuln": "-sV --script vuln,vulners --script-args vulners.showall"
        }

        if scan_type not in scan_profiles:
            print(f"[-] Invalid scan type: {scan_type}. Using discovery scan.")
            scan_type = "discovery"

        # Cross-platform command building
        if IS_WINDOWS:
            command = f'"{self.nmap_path}" {scan_profiles[scan_type]} -oX "{output_file}" "{target}"'
        else:
            # On Linux, we don't need quotes around the command
            command = f'{self.nmap_path} {scan_profiles[scan_type]} -oX {output_file} {target}'

        print(f"[*] Running Nmap scan: {command}")

        try:
            # Use subprocess with proper shell setting
            subprocess.run(command, shell=IS_WINDOWS, check=True)
            print(f"[+] Nmap scan completed. Results saved to {output_file}")
            return self.parse_nmap_xml(output_file)
        except subprocess.CalledProcessError as e:
            print(f"[-] Nmap scan failed: {e}")
            return None
        except FileNotFoundError:
            print(f"[-] Nmap executable not found at {self.nmap_path}")
            print("Please install Nmap or specify the correct path in configuration.")
            return None

    def parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output (platform independent)"""
        try:
            # Handle potential encoding issues on Windows
            with open(xml_file, 'r', encoding='utf-8') as f:
                tree = ET.parse(f)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"[-] Error parsing Nmap XML: {e}")
            return None
        except UnicodeDecodeError:
            try:
                # Try different encoding if UTF-8 fails
                with open(xml_file, 'r', encoding='latin-1') as f:
                    tree = ET.parse(f)
                root = tree.getroot()
            except Exception as e:
                print(f"[-] Error parsing Nmap XML with alternative encoding: {e}")
                return None

        results = {
            "target": "",
            "host": "",
            "ports": [],
            "vulnerabilities": []
        }

        # Get host information
        host = root.find("host")
        if host is not None:
            address = host.find("address")
            if address is not None:
                results["target"] = address.get("addr")
                results["host"] = address.get("addr")

        # Parse ports and vulnerabilities
        for port in root.findall(".//port"):
            service = port.find("service")
            port_data = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": port.find("state").get("state"),
                "service": service.get("name") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "vulns": []
            }

            # Parse script output for vulnerabilities
            for script in port.findall("script"):
                script_id = script.get("id")
                output = script.get("output", "")
                
                if script_id in ["vuln", "vulners", "http-sql-injection", "http-xss"]:
                    vuln_data = {
                        "type": script_id,
                        "output": output,
                        "port": port_data["port"],
                        "service": port_data["service"],
                        "product": port_data["product"],
                        "version": port_data["version"]
                    }
                    
                    if script_id == "vulners":
                        cves = re.findall(r"(CVE-\d{4}-\d+)", output)
                        for cve in set(cves):
                            vuln_data["cve"] = cve
                            port_data["vulns"].append(vuln_data.copy())
                    else:
                        port_data["vulns"].append(vuln_data)

            results["ports"].append(port_data)
            results["vulnerabilities"].extend(port_data["vulns"])

        return results

    def generate_report(self, scan_results):
        """Generate report (platform independent)"""
        if not scan_results:
            return {
                "target": "Unknown",
                "status": "Scan failed",
                "vulnerabilities": []
            }

        report = {
            "target": scan_results.get("target", "Unknown"),
            "status": "Scan completed",
            "timestamp": datetime.now().isoformat(),
            "platform": "Windows" if IS_WINDOWS else "Linux",
            "vulnerabilities": []
        }

        for vuln in scan_results.get("vulnerabilities", []):
            vuln_entry = {
                "type": vuln.get("type", "Unknown"),
                "port": vuln.get("port", "N/A"),
                "service": vuln.get("service", "Unknown"),
                "product": vuln.get("product", ""),
                "version": vuln.get("version", ""),
                "details": vuln.get("output", "No details")
            }
            
            if "cve" in vuln:
                vuln_entry["cve"] = vuln["cve"]
                # Look up CVE details
                cve_details = self.lookup_cves(f"{vuln['product']} {vuln['version']}")
                for detail in cve_details:
                    if detail["id"] == vuln["cve"]:
                        vuln_entry["severity"] = detail.get("severity", "N/A")
                        vuln_entry["score"] = detail.get("score", "N/A")
                        break
            
            report["vulnerabilities"].append(vuln_entry)

        return report

    def lookup_cves(self, service_info):
        """Query NVD API for CVEs (platform independent)"""
        if not service_info:
            return []

        try:
            params = {
                "keyword": service_info,
                "resultsPerPage": 20
            }
            
            if NVD_API_KEY:
                params["apiKey"] = NVD_API_KEY

            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/1.0",
                params=params,
                timeout=15
            )
            response.raise_for_status()

            return self._parse_nvd_response(response.json())

        except Exception as e:
            print(f"[-] NVD API Error: {e}")
            return []

    def _parse_nvd_response(self, api_data):
        """Parse NVD response (platform independent)"""
        cves = []
        for item in api_data.get("result", {}).get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            description = item["cve"]["description"]["description_data"][0]["value"]
            
            cvss_data = item["impact"].get("baseMetricV3", {}).get("cvssV3", {})
            if not cvss_data:
                cvss_data = item["impact"].get("baseMetricV2", {}).get("cvssV2", {})
            
            cves.append({
                "id": cve_id,
                "description": description,
                "severity": cvss_data.get("baseSeverity", "N/A"),
                "score": cvss_data.get("baseScore", "N/A"),
                "references": [
                    ref["url"] for ref in item["cve"]["references"]["reference_data"]
                ]
            })
        return cves
    
    def save_report(self, report, format="text"):
        """Save report in specified format (cross-platform)"""
        if not report:
            print("[-] No report data to save")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vuln_report_{report.get('target', 'unknown')}_{timestamp}"

        try:
            if format == "json":
                filename += ".json"
                filepath = os.path.join(OUTPUT_DIR, filename)
                with open(filepath, "w", encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
                print(f"[+] JSON report saved to {filepath}")
            
            elif format == "text":
                filename += ".txt"
                filepath = os.path.join(OUTPUT_DIR, filename)
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(f"=== Vulnerability Report ===\n")
                    f.write(f"Target: {report.get('target', 'Unknown')}\n")
                    f.write(f"Scan Time: {timestamp}\n")
                    f.write(f"Platform: {'Windows' if IS_WINDOWS else 'Linux'}\n\n")
                    
                    if not report.get('vulnerabilities'):
                        f.write("No vulnerabilities found.\n")
                    else:
                        f.write("=== Vulnerabilities Found ===\n\n")
                        for vuln in report['vulnerabilities']:
                            service_info = f"{vuln.get('product', '')} {vuln.get('version', '')}".strip()
                            if service_info:
                                f.write(f"Service: {service_info}\n")
                            else:
                                f.write(f"Service: {vuln.get('service', 'Unknown')}\n")
                            
                            if vuln.get('type') == 'vulners' and 'cve' in vuln:
                                f.write(f"- {vuln['cve']} ")
                                if 'severity' in vuln:
                                    f.write(f"({vuln['severity']}, CVSS {vuln.get('score', 'N/A')})\n")
                                else:
                                    f.write("\n")
                                f.write(f"  Description: {vuln.get('details', 'No details')[:200]}\n")
                            
                            elif vuln.get('type') in ['http-sql-injection', 'http-xss']:
                                f.write(f"- {vuln['type'].upper()}\n")
                                f.write(f"  Evidence: {vuln.get('details', 'No details')[:200]}\n")
                            
                            f.write("\n")
                print(f"[+] Text report saved to {filepath}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def interactive_scan(self):
        """Run interactive scan (cross-platform)"""
        print("\n=== Cross-Platform Vulnerability Scanner ===")
        print(f"Running on {'Windows' if IS_WINDOWS else 'Linux'}\n")
        
        target = input("Enter target IP/hostname: ").strip()
        if not target:
            print("[-] Target is required")
            return

        print("\nSelect scan type:")
        print("1. Discovery Scan (Fast, top 100 ports)")
        print("2. Full Port Scan (All ports, takes longer)")
        print("3. Vulnerability Scan (Nmap vuln scripts)")
        
        scan_choice = input("Enter choice (1-3): ").strip()
        scan_types = {"1": "discovery", "2": "full", "3": "vuln"}
        scan_type = scan_types.get(scan_choice, "discovery")

        print(f"\n[*] Starting {scan_type} scan against {target}...")
        nmap_results = self.run_nmap_scan(target, scan_type)
        
        if nmap_results:
            print("\n[*] Analyzing results for vulnerabilities...")
            report = self.generate_report(nmap_results)
            
            if report:
                print("\nSelect output format:")
                print("1. JSON (Machine-readable)")
                print("2. Text (Human-readable)")
                format_choice = input("Enter choice (1-2): ").strip()
                output_format = "json" if format_choice == "1" else "text"
                
                self.save_report(report, output_format)
                
                # Show brief summary
                vuln_count = len(report.get("vulnerabilities", []))
                print(f"\n[+] Scan complete. Found {vuln_count} vulnerabilities.")
                if vuln_count > 0:
                    print("\n=== Critical Findings ===")
                    for vuln in report["vulnerabilities"]:
                        if vuln.get("type") == "vulners" and "cve" in vuln:
                            print(f"- {vuln['cve']} ({vuln.get('severity', 'N/A')}) on port {vuln['port']}")
                        elif vuln.get("type") in ["http-sql-injection", "http-xss"]:
                            print(f"- {vuln['type'].upper()} on port {vuln['port']}")

if __name__ == "__main__":
    try:
        scanner = VulnerabilityScanner()
        scanner.interactive_scan()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)