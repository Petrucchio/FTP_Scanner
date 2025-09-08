#!/usr/bin/env python3
"""
FTP Network Assessment Tool - Educational Portfolio Version
Version: 5.0 Educational

LEGAL DISCLAIMER:
================
This software is intended EXCLUSIVELY for:
- Educational and learning purposes
- Testing on your own systems and networks
- Authorized security assessments with written permission
- Laboratory environments and controlled testing

UNAUTHORIZED use on third-party systems is ILLEGAL and may violate:
- Computer Fraud and Abuse Act
- Similar laws in other jurisdictions
- Terms of service of network providers

The author assumes NO RESPONSIBILITY for misuse of this tool.
Users are solely responsible for compliance with all applicable laws.

EDUCATIONAL PURPOSE:
===================
This tool demonstrates:
- Network programming concepts
- Concurrent programming with threading
- Service detection methodologies
- Banner analysis techniques
- Clean code architecture and design patterns
"""

import socket
import sys
import argparse
import re
import json
import time
import hashlib
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextmanager import contextmanager
from typing import Tuple, Optional, Dict, List, Set
from dataclasses import dataclass
from enum import Enum


class ServiceInfo(Enum):
    """Service information levels for educational assessment"""
    UNKNOWN = "UNKNOWN"
    IDENTIFIED = "IDENTIFIED" 
    OUTDATED = "POTENTIALLY_OUTDATED"
    MODERN = "MODERN_VERSION"


@dataclass
class ServicePattern:
    """Educational service pattern for learning purposes"""
    name: str
    pattern: str
    info_level: ServiceInfo
    description: str
    learning_notes: str


# Educational service patterns (generic examples for learning)
EDUCATIONAL_PATTERNS = [
    ServicePattern(
        "Generic FTP Service", 
        r"220.*FTP", 
        ServiceInfo.IDENTIFIED,
        "Standard FTP service detected",
        "FTP services typically announce themselves with 220 response codes"
    ),
    ServicePattern(
        "Legacy FTP Implementation", 
        r"FTP.*Server.*1\.[0-2]", 
        ServiceInfo.OUTDATED,
        "Potentially outdated FTP implementation",
        "Version 1.x implementations may lack modern security features"
    ),
    ServicePattern(
        "Professional FTP Service", 
        r"ProFTPD.*1\.[3-9]|FileZilla.*Server.*[1-9]\.", 
        ServiceInfo.MODERN,
        "Modern FTP implementation detected",
        "Recent versions typically include security improvements"
    ),
    ServicePattern(
        "Secure FTP Service", 
        r"220.*FTPS|220.*SSL|220.*TLS", 
        ServiceInfo.MODERN,
        "Secure FTP service detected",
        "FTPS implementations provide encrypted connections"
    ),
]

# Common FTP ports for educational scanning
EDUCATIONAL_PORTS = [21, 2121, 8021, 10021, 21000]

# Honeypot detection patterns (educational)
HONEYPOT_PATTERNS = [
    r"Dionaea", r"Cowrie", r"Kippo", r"Honeypot", 
    r"Fake.*FTP", r"Decoy", r"Trap"
]


class Colors:
    """Terminal color codes for better output formatting"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    PURPLE = '\033[95m'
    END = '\033[0m'


class ServiceDatabase:
    """Educational service pattern database"""
    
    def __init__(self, pattern_file: str = None):
        self.patterns = []
        self.pattern_file = pattern_file
        self.load_patterns()
    
    def load_patterns(self):
        """Load service patterns from file or use defaults"""
        if self.pattern_file and os.path.exists(self.pattern_file):
            try:
                self._load_custom_patterns()
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error loading pattern file: {e}. Using defaults{Colors.END}")
                self.patterns = EDUCATIONAL_PATTERNS.copy()
        else:
            self.patterns = EDUCATIONAL_PATTERNS.copy()
        
        print(f"{Colors.GREEN}[+] Loaded {len(self.patterns)} educational patterns{Colors.END}")
    
    def _load_custom_patterns(self):
        """Load custom patterns from JSON file"""
        with open(self.pattern_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for item in data.get('patterns', []):
            info_level = ServiceInfo(item.get('info_level', 'UNKNOWN'))
            pattern = ServicePattern(
                name=item['name'],
                pattern=item['pattern'],
                info_level=info_level,
                description=item.get('description', 'No description'),
                learning_notes=item.get('learning_notes', 'Educational pattern')
            )
            self.patterns.append(pattern)
    
    def analyze_service(self, banner: str) -> Tuple[bool, Optional[ServicePattern]]:
        """Analyze service banner for educational purposes"""
        for pattern in self.patterns:
            if re.search(pattern.pattern, banner, re.IGNORECASE):
                return True, pattern
        return False, None


class NetworkAssessmentTool:
    """Educational network assessment tool for learning purposes"""
    
    def __init__(self, timeout=5, verbose=False, max_threads=10, pattern_file=None):
        self.timeout = timeout
        self.verbose = verbose
        self.max_threads = max_threads
        self.service_db = ServiceDatabase(pattern_file)
        self._show_legal_notice()
    
    def _show_legal_notice(self):
        """Display legal notice and get user confirmation"""
        print(f"{Colors.RED}{Colors.BOLD}")
        print("=" * 60)
        print("LEGAL NOTICE - READ CAREFULLY")
        print("=" * 60)
        print(f"{Colors.END}{Colors.YELLOW}")
        print("This tool is for EDUCATIONAL purposes only!")
        print("Only use on systems you own or have explicit permission to test.")
        print("Unauthorized network scanning may be illegal in your jurisdiction.")
        print(f"{Colors.END}")
        
        try:
            confirmation = input(f"{Colors.CYAN}Do you have authorization to scan the target? (yes/no): {Colors.END}")
            if confirmation.lower() not in ['yes', 'y']:
                print(f"{Colors.RED}[!] Operation cancelled for security compliance{Colors.END}")
                sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Operation cancelled{Colors.END}")
            sys.exit(0)
    
    @contextmanager
    def create_socket(self):
        """Context manager for socket creation and cleanup"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            yield sock
        finally:
            sock.close()
    
    def check_port_status(self, host: str, port: int) -> bool:
        """Check if a port is open (educational port scanning)"""
        try:
            with self.create_socket() as sock:
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Port check error {host}:{port} - {e}{Colors.END}")
            return False
    
    def discover_open_ports(self, host: str, ports: List[int] = None) -> Set[int]:
        """Educational port discovery using threading"""
        if ports is None:
            ports = EDUCATIONAL_PORTS
        
        print(f"{Colors.BLUE}[*] Discovering open ports (educational scan)...{Colors.END}")
        open_ports = set()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.check_port_status, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.add(port)
                        if self.verbose:
                            print(f"{Colors.GREEN}[+] Port {port} is open{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}[!] Error checking port {port}: {e}{Colors.END}")
        
        return open_ports
    
    def capture_service_banner(self, host: str, port: int) -> Tuple[str, float, bool]:
        """Educational banner grabbing technique"""
        try:
            start_time = time.time()
            with self.create_socket() as sock:
                sock.connect((host, port))
                
                # Capture initial banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                response_time = time.time() - start_time
                
                # Educational FTP service detection
                ftp_indicators = [
                    r"220.*FTP", r"220.*ftp", r"FTP\s+Server", 
                    r"ftpd", r"220.*ready", r"ProFTPD", r"vsftpd", 
                    r"Pure-FTPd", r"FileZilla"
                ]
                
                is_ftp_service = any(
                    re.search(indicator, banner, re.IGNORECASE) 
                    for indicator in ftp_indicators
                )
                
                # Additional FTP detection using HELP command
                if not is_ftp_service and banner:
                    try:
                        sock.send(b"HELP\r\n")
                        help_response = sock.recv(512).decode('utf-8', errors='ignore')
                        # FTP HELP responses typically use these codes
                        is_ftp_service = any(
                            code in help_response 
                            for code in ["214", "502", "500"]
                        )
                    except:
                        pass
                
                return banner, response_time, is_ftp_service
                
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Banner capture failed for {host}:{port} - {e}{Colors.END}")
            return "", 0.0, False
    
    def assess_single_port(self, host: str, port: int) -> Optional[Dict]:
        """Educational assessment of a single port"""
        if self.verbose:
            print(f"{Colors.BLUE}[*] Assessing {host}:{port}...{Colors.END}")
        
        banner, timing, is_ftp = self.capture_service_banner(host, port)
        
        if not banner or not is_ftp:
            return None
        
        # Educational service analysis
        has_match, service_pattern = self.service_db.analyze_service(banner)
        
        # Educational honeypot detection
        is_possible_honeypot = any(
            re.search(sig, banner, re.IGNORECASE) 
            for sig in HONEYPOT_PATTERNS
        )
        
        return {
            'host': host,
            'port': port,
            'banner': banner,
            'banner_hash': hashlib.md5(banner.encode()).hexdigest()[:8],
            'response_time': timing,
            'service_identified': has_match,
            'possible_honeypot': is_possible_honeypot,
            'service_info': service_pattern,
            'assessment_level': service_pattern.info_level.value if has_match else 'UNKNOWN'
        }
    
    def assess_host(self, host: str, ports: List[int] = None) -> List[Dict]:
        """Educational host assessment"""
        print(f"\n{Colors.CYAN}[*] Starting educational assessment of: {host}{Colors.END}")
        
        if ports:
            open_ports = set(ports)
            print(f"{Colors.BLUE}[*] Using specified ports: {sorted(ports)}{Colors.END}")
        else:
            open_ports = self.discover_open_ports(host)
        
        if not open_ports:
            print(f"{Colors.YELLOW}[-] No open ports discovered{Colors.END}")
            return []
        
        print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports for assessment{Colors.END}")
        
        assessment_results = []
        for port in sorted(open_ports):
            result = self.assess_single_port(host, port)
            if result:
                assessment_results.append(result)
                
                # Educational output
                if result['service_identified']:
                    status = "📚 Service Identified"
                    color = Colors.GREEN
                elif result['possible_honeypot']:
                    status = "🍯 Possible Honeypot"
                    color = Colors.YELLOW
                else:
                    status = "❓ Unknown Service"
                    color = Colors.CYAN
                
                print(f"    Port {port}: {color}{status}{Colors.END}")
        
        print(f"{Colors.CYAN}[+] Assessment complete: {len(assessment_results)} FTP services found{Colors.END}")
        return assessment_results
    
    def display_educational_results(self, results: List[Dict]):
        """Display results in educational format"""
        if not results:
            print(f"\n{Colors.YELLOW}No FTP services discovered in assessment{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}📊 EDUCATIONAL ASSESSMENT RESULTS{Colors.END}")
        print("=" * 60)
        
        for i, result in enumerate(results, 1):
            print(f"\n{Colors.CYAN}🎯 Service #{i}: {result['host']}:{result['port']}{Colors.END}")
            print(f"📋 Banner: {Colors.WHITE}{result['banner']}{Colors.END}")
            print(f"⏱️  Response Time: {result['response_time']:.3f}s")
            print(f"🔍 Banner Hash: {result['banner_hash']}")
            
            if result['possible_honeypot']:
                print(f"🍯 {Colors.YELLOW}Educational Note: Possible honeypot detected{Colors.END}")
                print(f"   Learning: Honeypots are decoy systems used for security research")
            
            if result['service_identified']:
                service = result['service_info']
                level_colors = {
                    ServiceInfo.MODERN: Colors.GREEN,
                    ServiceInfo.IDENTIFIED: Colors.BLUE,
                    ServiceInfo.OUTDATED: Colors.YELLOW,
                    ServiceInfo.UNKNOWN: Colors.CYAN
                }
                color = level_colors.get(service.info_level, Colors.WHITE)
                
                print(f"\n{Colors.BOLD}📚 Educational Analysis:{Colors.END}")
                print(f"Service: {color}{service.name}{Colors.END}")
                print(f"Assessment: {color}{service.info_level.value}{Colors.END}")
                print(f"Description: {service.description}")
                print(f"Learning Notes: {service.learning_notes}")
            else:
                print(f"\n{Colors.GREEN}📚 Learning Opportunity: Unknown service pattern{Colors.END}")
                print("   This demonstrates the importance of comprehensive service detection")
    
    def assess_multiple_hosts(self, filename: str) -> List[Dict]:
        """Educational assessment of multiple hosts from file"""
        try:
            with open(filename, 'r') as f:
                hosts = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
            
            all_results = []
            print(f"{Colors.BLUE}[*] Educational assessment of {len(hosts)} hosts{Colors.END}")
            
            for i, host in enumerate(hosts, 1):
                print(f"\n{Colors.PURPLE}[{i}/{len(hosts)}] Assessing: {host}{Colors.END}")
                host_results = self.assess_host(host)
                all_results.extend(host_results)
                
                # Educational rate limiting
                if i < len(hosts):
                    time.sleep(0.5)  # Be respectful to target systems
            
            return all_results
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading hosts file: {e}{Colors.END}")
            return []
    
    def save_educational_report(self, results: List[Dict], filename: str):
        """Save educational assessment report"""
        try:
            # Prepare serializable results
            report_data = []
            for result in results:
                r = result.copy()
                if r['service_info']:
                    r['service_info'] = {
                        'name': r['service_info'].name,
                        'info_level': r['service_info'].info_level.value,
                        'description': r['service_info'].description,
                        'learning_notes': r['service_info'].learning_notes
                    }
                report_data.append(r)
            
            # Create comprehensive educational report
            report = {
                'assessment_metadata': {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'tool_version': '5.0 Educational',
                    'purpose': 'Educational network assessment',
                    'disclaimer': 'For authorized educational use only'
                },
                'statistics': {
                    'total_services_found': len(results),
                    'identified_services': sum(1 for r in results if r['service_identified']),
                    'possible_honeypots': sum(1 for r in results if r['possible_honeypot']),
                    'unique_hosts_assessed': len(set(r['host'] for r in results)),
                    'assessment_levels': {
                        level.value: sum(1 for r in results 
                                       if r.get('assessment_level') == level.value)
                        for level in ServiceInfo
                    }
                },
                'educational_findings': report_data
            }
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"{Colors.GREEN}[+] Educational report saved: {filename}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Report save error: {e}{Colors.END}")


def main():
    """Main educational assessment function"""
    parser = argparse.ArgumentParser(
        description="FTP Network Assessment Tool - Educational Version 5.0",
        epilog="Remember: Only use on systems you own or have explicit permission to test!"
    )
    
    parser.add_argument(
        "target", 
        nargs='?', 
        help="Target IP/hostname or file containing targets"
    )
    parser.add_argument(
        "-p", "--ports", 
        help="Specific ports to assess (comma-separated)"
    )
    parser.add_argument(
        "-t", "--timeout", 
        type=int, 
        default=5, 
        help="Connection timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "-T", "--threads", 
        type=int, 
        default=10, 
        help="Maximum concurrent threads (default: 10)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose educational output"
    )
    parser.add_argument(
        "-f", "--file", 
        action="store_true", 
        help="Target parameter is a file containing multiple hosts"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Save educational report to JSON file"
    )
    parser.add_argument(
        "-P", "--patterns", 
        help="Custom service patterns file (JSON format)"
    )
    parser.add_argument(
        "--show-patterns", 
        action="store_true", 
        help="Display loaded educational patterns"
    )
    
    args = parser.parse_args()
    
    # Educational banner
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║      FTP Network Assessment Tool v5.0            ║
║           Educational Portfolio Version          ║
║                                                  ║
║  Purpose: Learning network assessment concepts   ║
║  Use: Educational and authorized testing only    ║
╚══════════════════════════════════════════════════╝{Colors.END}""")
    
    # Initialize assessment tool
    tool = NetworkAssessmentTool(
        timeout=args.timeout,
        verbose=args.verbose,
        max_threads=args.threads,
        pattern_file=args.patterns
    )
    
    # Show patterns if requested
    if args.show_patterns:
        print(f"\n{Colors.YELLOW}📚 Educational Service Patterns:{Colors.END}")
        for i, pattern in enumerate(tool.service_db.patterns, 1):
            level_colors = {
                ServiceInfo.MODERN: Colors.GREEN,
                ServiceInfo.IDENTIFIED: Colors.BLUE,
                ServiceInfo.OUTDATED: Colors.YELLOW,
                ServiceInfo.UNKNOWN: Colors.CYAN
            }
            color = level_colors.get(pattern.info_level, Colors.WHITE)
            
            print(f"\n{i:2d}. {color}{pattern.name}{Colors.END}")
            print(f"    Level: {pattern.info_level.value}")
            print(f"    Pattern: {pattern.pattern}")
            print(f"    Learning: {pattern.learning_notes}")
        return
    
    # Validate target
    if not args.target:
        print(f"{Colors.RED}[!] No target specified{Colors.END}")
        parser.print_help()
        return
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
            print(f"{Colors.BLUE}[*] Custom ports specified: {ports}{Colors.END}")
        except ValueError:
            print(f"{Colors.RED}[-] Invalid port format. Use comma-separated integers{Colors.END}")
            return
    
    # Start assessment
    start_time = time.time()
    results = []
    
    if args.file:
        print(f"{Colors.BLUE}[*] Educational multi-host assessment mode{Colors.END}")
        results = tool.assess_multiple_hosts(args.target)
    else:
        print(f"{Colors.BLUE}[*] Educational single-host assessment mode{Colors.END}")
        results = tool.assess_host(args.target, ports)
    
    # Display results
    tool.display_educational_results(results)
    
    # Educational statistics
    if results:
        total = len(results)
        identified = sum(1 for r in results if r['service_identified'])
        honeypots = sum(1 for r in results if r['possible_honeypot'])
        
        print(f"\n{Colors.BOLD}📈 Educational Statistics:{Colors.END}")
        print(f"Services Found: {total}")
        print(f"Identified: {Colors.GREEN}{identified}{Colors.END}")
        print(f"Possible Honeypots: {Colors.YELLOW}{honeypots}{Colors.END}")
        print(f"Unknown: {Colors.CYAN}{total - identified - honeypots}{Colors.END}")
    
    # Save report if requested
    if args.output and results:
        tool.save_educational_report(results, args.output)
    
    # Assessment completion
    elapsed_time = time.time() - start_time
    print(f"\n{Colors.CYAN}⏱️  Educational assessment completed in {elapsed_time:.2f} seconds{Colors.END}")
    print(f"{Colors.GREEN}🎓 Learning objective achieved: Network service assessment methodology{Colors.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Educational assessment interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-] Unexpected error in educational tool: {e}{Colors.END}")
        sys.exit(1)