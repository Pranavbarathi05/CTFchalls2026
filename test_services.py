#!/usr/bin/env python3
"""
CTF Services Health Check Script - Remote Server Support
Tests all Docker Compose services on local or remote hosts
"""

import requests
import socket
import sys
import argparse
from typing import Dict, List, Tuple
from colorama import init, Fore, Style
import time

# Initialize colorama for Windows color support
init(autoreset=True)


def get_services(host: str):
    """Return service definitions with the specified host"""
    return {
        "Infrastructure": [
            {"name": "Traefik Proxy", "host": host, "port": 9090, "type": "http", "path": "/"},
            {"name": "Traefik Dashboard", "host": host, "port": 8080, "type": "http", "path": "/dashboard/"},
            {"name": "CTFd Platform", "host": host, "port": 9090, "type": "http", "path": "/", "headers": {"Host": "ctf.dscjssstuniv.in"}},
            {"name": "MariaDB", "host": host, "port": 3306, "type": "tcp"},
            {"name": "Redis Cache", "host": host, "port": 6379, "type": "tcp"},
        ],
        "Binary Exploitation": [
            {"name": "Menu Pwner", "host": host, "port": 9999, "type": "tcp"},
            {"name": "Overflow Academy", "host": host, "port": 9001, "type": "tcp"},
        ],
        "Coding Challenges": [
            {"name": "Pathfinding Puzzle", "host": host, "port": 8004, "type": "http", "path": "/"},
            {"name": "Regex Master", "host": host, "port": 8006, "type": "http", "path": "/"},
            {"name": "Tree Traversal", "host": host, "port": 8005, "type": "http", "path": "/"},
            {"name": "Number of Ones", "host": host, "port": 54321, "type": "tcp"},
            {"name": "Math Challenge", "host": host, "port": 8018, "type": "http", "path": "/"},
        ],
        "Cryptography": [
            {"name": "Caesar's Pizza", "host": host, "port": 8001, "type": "http", "path": "/"},
        ],
        "Misc": [
            {"name": "Echo Chamber", "host": host, "port": 8017, "type": "http", "path": "/"},
            {"name": "Missing Tools (SSH)", "host": host, "port": 2222, "type": "tcp"},
            {"name": "Formality Breach", "host": host, "port": 8015, "type": "http", "path": "/"},
        ],
        "Pyjail": [
            {"name": "Cipher Prison", "host": host, "port": 1337, "type": "tcp"},
            {"name": "Prison Break", "host": host, "port": 9998, "type": "tcp"},
            {"name": "Blacklist Hell", "host": host, "port": 1338, "type": "tcp"},
        ],
        "Reverse Engineering": [
            {"name": "License Checker", "host": host, "port": 8002, "type": "http", "path": "/"},
            {"name": "Endgame Protocol", "host": host, "port": 8016, "type": "http", "path": "/"},
            {"name": "Upside Down", "host": host, "port": 1339, "type": "tcp"},
            {"name": "Has to Echo", "host": host, "port": 1340, "type": "tcp"},
            {"name": "Conditions", "host": host, "port": 42552, "type": "http", "path": "/"},
        ],
        "Web Exploitation": [
            {"name": "Wrong Password", "host": host, "port": 8014, "type": "http", "path": "/"},
            {"name": "Secure Portal", "host": host, "port": 8007, "type": "http", "path": "/"},
            {"name": "Stranger Things", "host": host, "port": 8013, "type": "http", "path": "/"},
            {"name": "Overthinker", "host": host, "port": 8011, "type": "http", "path": "/"},
            {"name": "Plain Sight", "host": host, "port": 8012, "type": "http", "path": "/"},
            {"name": "Flag in Cache", "host": host, "port": 8009, "type": "http", "path": "/"},
            {"name": "Auth Adventure", "host": host, "port": 8008, "type": "http", "path": "/"},
            {"name": "Nothing Works", "host": host, "port": 8010, "type": "http", "path": "/"},
            {"name": "Time Window", "host": host, "port": 8003, "type": "http", "path": "/"},
            {"name": "Cookie Recipe", "host": host, "port": 5002, "type": "http", "path": "/"},
            {"name": "Curl Unfurl", "host": host, "port": 5003, "type": "http", "path": "/"},
            {"name": "Robots Watching", "host": host, "port": 5001, "type": "http", "path": "/"},
        ],
    }


def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, str]:
    """Check if a TCP port is open and accepting connections"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return True, "Port is open"
        else:
            return False, f"Port is closed (error code: {result})"
    except socket.timeout:
        return False, "Connection timeout"
    except socket.gaierror:
        return False, "Cannot resolve hostname"
    except socket.error as e:
        return False, f"Socket error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def check_http_service(host: str, port: int, path: str = "/", timeout: float = 5.0, headers: Dict = None) -> Tuple[bool, str]:
    """Check if an HTTP service is responding"""
    url = f"http://{host}:{port}{path}"
    try:
        response = requests.get(url, timeout=timeout, headers=headers or {}, allow_redirects=True, verify=False)
        if response.status_code < 500:
            return True, f"HTTP {response.status_code}"
        else:
            return False, f"HTTP {response.status_code} (Server Error)"
    except requests.exceptions.Timeout:
        return False, "Request timeout"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def test_service(service: Dict) -> Tuple[bool, str]:
    """Test a single service based on its type"""
    if service["type"] == "tcp":
        return check_tcp_port(service["host"], service["port"])
    elif service["type"] == "http":
        path = service.get("path", "/")
        headers = service.get("headers", None)
        return check_http_service(service["host"], service["port"], path, headers=headers)
    else:
        return False, "Unknown service type"


def print_header(host: str):
    """Print script header"""
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{Fore.CYAN}CTF Services Health Check - Target: {host}")
    print(f"{Fore.CYAN}{'='*80}\n")


def print_category_header(category: str):
    """Print category header"""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[{category}]{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'-'*80}{Style.RESET_ALL}")


def print_result(service_name: str, success: bool, message: str, port: int):
    """Print test result with color formatting"""
    status_icon = f"{Fore.GREEN}✓" if success else f"{Fore.RED}✗"
    status_text = f"{Fore.GREEN}OK" if success else f"{Fore.RED}FAIL"
    
    # Pad service name for alignment
    service_display = f"{service_name:<30}"
    port_display = f":{port:<6}"
    
    print(f"{status_icon} {service_display} {port_display} [{status_text}{Style.RESET_ALL}] {message}")


def print_summary(total: int, passed: int, failed: int):
    """Print test summary"""
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{Fore.CYAN}Summary{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}")
    print(f"Total Services:  {total}")
    print(f"{Fore.GREEN}Passed:          {passed}")
    print(f"{Fore.RED}Failed:          {failed}")
    print(f"Success Rate:    {pass_rate:.1f}%")
    print(f"{Fore.CYAN}{'='*80}\n")


def main():
    """Main test execution"""
    parser = argparse.ArgumentParser(
        description='Test CTF Docker Compose services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Test localhost
  %(prog)s --host 192.168.1.100              # Test remote server
  %(prog)s --host ctf.example.com            # Test by hostname
  %(prog)s --host localhost --quick          # Quick test (faster timeouts)
        '''
    )
    parser.add_argument('--host', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--quick', action='store_true', help='Quick mode with shorter timeouts')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Get services for target host
    SERVICES = get_services(args.host)
    
    print_header(args.host)
    
    total_services = 0
    passed_services = 0
    failed_services = 0
    failed_list = []
    
    # Test all services by category
    for category, services in SERVICES.items():
        print_category_header(category)
        
        for service in services:
            total_services += 1
            success, message = test_service(service)
            
            if success:
                passed_services += 1
            else:
                failed_services += 1
                failed_list.append((category, service["name"], service["port"]))
            
            print_result(service["name"], success, message, service["port"])
        
        # Small delay between categories
        time.sleep(0.05 if args.quick else 0.1)
    
    # Print summary
    print_summary(total_services, passed_services, failed_services)
    
    # Print detailed failures if any
    if failed_list:
        print(f"\n{Fore.RED}{Style.BRIGHT}Failed Services:{Style.RESET_ALL}")
        print(f"{Fore.RED}{'-'*80}{Style.RESET_ALL}")
        for category, name, port in failed_list:
            print(f"{Fore.RED}  • [{category}] {name} (port {port}){Style.RESET_ALL}")
        print()
    
    # Exit with appropriate code
    sys.exit(0 if failed_services == 0 else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Test interrupted by user{Style.RESET_ALL}\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {str(e)}{Style.RESET_ALL}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
