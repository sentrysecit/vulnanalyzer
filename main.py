#!/usr/bin/env python3

import argparse
import sys
import json
from datetime import datetime

from core.caldera_client import CalderaClient
from core.scanner import VulnerabilityScanner
from core.exploiter import Exploiter
from core.discover import HostDiscoverer

from config.settings import CALDERA_API_KEY, CALDERA_BASE_URL


def banner():
    print("""
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
    ██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
    ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
                                                                                       v1.0
    """)
    print("Vulnerability analysis and adversary emulation framework")
    print("=" * 80)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="VulnAnalyzer - Vulnerability Analysis Framework"
    )

    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command #1
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilites")
    scan_parser.add_argument("target", help="Target to scan IP, domain")
    scan_parser.add_argument(
        "--type",
        choices=["quick", "full", "stealth"],
        default="full",
        help="Scan type (default: full)",
    )
    scan_parser.add_argument("--output", "-o", help="Output file for results")
    scan_parser.add_argument(
        "--report", help="Generate an HTML report from the scan results (requires --output)"
    )

    # Discover command
    discover_parser = subparsers.add_parser(
        "discover", help="Discover active hosts on the network"
    )
    discover_parser.add_argument(
        "range", help="Network range to scan (e.g., 192.168.1.0/24)"
    )
    discover_parser.add_argument("--output", "-o", help="Output file for results")

    # Exploitation Command #2
    exploit_parser = subparsers.add_parser("exploit", help="Exploiting vulnerabilities")
    exploit_parser.add_argument("--scan-file", help="File with previous scan results")
    exploit_parser.add_argument("--target", help="Specific target to exploit")
    exploit_parser.add_argument("--exploit", help="Specific exploit to use")
    exploit_parser.add_argument(
        "--list", action="store_true", help="List available exploits"
    )

    # Comando de Caldera
    caldera_parser = subparsers.add_parser("caldera", help="Interact with MITRE Calder")
    caldera_parser.add_argument(
        "--deploy", action="store_true", help="Instruction to generate an agent"
    )
    caldera_parser.add_argument(
        "--platform",
        choices=["windows", "linux", "darwin"],
        default="windows",
        help="Platform for the agent (default: windows)",
    )
    caldera_parser.add_argument(
        "--run", action="store_true", help="Run evaluation with Caldera"
    )
    caldera_parser.add_argument("--adversary", help="Name of the opponent to use")

    # ###################################################################
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Handle Scan Command #1
    if args.command == "scan":
        print(f"[*] Starting vulnerability scan on {args.target}")
        scanner = VulnerabilityScanner(args.target, scan_type=args.type)
        results = scanner.run()

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            print(f"[+] Result saved in {args.output}")

            if args.report:
                print(f"[*] Generating HTML report to {args.report}...")
                try:
                    from reports.report_generator import ReportGenerator

                    report_generator = ReportGenerator({"scan_results": results})
                    report_generator.generate_html_report(args.report)
                    print(f"[+] Report generated successfully: {args.report}")
                except Exception as e:
                    print(f"[!] Error generating report: {e}")
        else:
            print(json.dumps(results, indent=4))

    # Handle Discover Command
    elif args.command == "discover":
        print(f"[*] Discovering hosts on {args.range}")
        discoverer = HostDiscoverer(args.range)
        hosts = discoverer.discover_hosts()

        if args.output:
            with open(args.output, "w") as f:
                json.dump({"active_hosts": hosts}, f, indent=4)
            print(f"[+] Results saved in {args.output}")
        else:
            print(json.dumps({"active_hosts": hosts}, indent=4))

    # Manage exploitation command #2
    elif args.command == "exploit":
        if args.list:
            # Create temporary instance to list exploits
            temp_exploiter = Exploiter({})
            exploits = temp_exploiter.list_exploits()
            print("\nAvailable exploits:")
            for category, category_exploits in exploits.items():
                print(f"\n[+] Category: {category}")
                for exploit in category_exploits:
                    print(
                        f"  - {exploit['name']}: {exploit['description']} (CVE: {exploit['cve']})"
                    )
            return

        if args.scan_file:
            with open(args.scan_file, "r") as f:
                scan_results = json.load(f)

            exploiter = Exploiter(scan_results)

            if args.exploit and args.target:
                print(f"[*] Running exploit {args.exploit} against {args.target}")
                result = exploiter.run_specific_exploit(args.exploit, args.target)
                print(json.dumps(result, indent=4))
            else:
                print("[*] Running exploits matching detected vulnerabilities")
                results = exploiter.run_all_matching_exploits()
                print(json.dumps(results, indent=4))
        else:
            print("Error: A pre-scan file is required (--scan-file)")

    # Handle Caldera Command
    elif args.command == "caldera":
        if not CALDERA_BASE_URL or not CALDERA_API_KEY:
            print(
                "Error: It is required to configure CALDERA_BASE_URL and CALDERA_API_KEY in config/settings.py"
            )
            return

        caldera = CalderaClient(CALDERA_BASE_URL, CALDERA_API_KEY)

        # Test conexion
        connection_ok, message = caldera.test_connection()
        if not connection_ok:
            print(f"Connection error with Caldera: {message}")
            return

        # Deploy a command to target
        if args.deploy:
            caldera.deploy_agent()

        elif args.run:
            print("[*] Running evaluation with MITRE Caldera")
            results = caldera.run_caldera_assessment(adversary_name=args.adversary)

            if "error" in results:
                print(f"Error: {results['error']}")
            else:
                print(f"[+] Operation completed: {results['operation_id']}")
                print(f"[+] Adversary: {results['adversary']}")
                print(json.dumps(results, indent=4))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation canceled by the user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)
