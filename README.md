# WiFi Deauthentication Tool 🛡️

A professional command-line utility for Kali Linux designed for cybersecurity research and penetration testing. This tool features a modern, user-friendly interface with real-time feedback and progress monitoring.

![Tool Banner](https://raw.githubusercontent.com/yourusername/wifi-deauth-tool/main/screenshots/banner.png)

## ⚠️ Legal Disclaimer

**This tool is for EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY.**
- Only use on networks you own or have explicit permission to test
- Unauthorized use may be illegal in your jurisdiction
- The authors take no responsibility for misuse of this tool

## ✨ Features

### Modern Interface
- 🎨 Professional ASCII art banner
- 📊 Real-time progress bars and spinners
- 📋 Formatted tables for network and client information
- 🔄 Live attack statistics
- 🎯 Interactive menus with color coding

### Core Functionality
- 🔍 Automatic wireless interface detection
- 📡 Network scanning with signal strength
- 👥 Client detection with device type identification
- ⚡ Deauthentication attack capabilities
- 📝 Detailed logging system

### Smart Features
- 🔍 Automatic virtual environment management
- 📱 Device type detection (Apple, Android, Windows)
- 📊 Real-time packet statistics
- 🛡️ Automatic cleanup and restoration

## 🖼️ Screenshots

### Network Scanning
![Network Scan](https://raw.githubusercontent.com/yourusername/wifi-deauth-tool/main/screenshots/network_scan.png)

### Client Detection
![Client Detection](https://raw.githubusercontent.com/yourusername/wifi-deauth-tool/main/screenshots/client_detection.png)

### Attack Progress
![Attack Progress](https://raw.githubusercontent.com/yourusername/wifi-deauth-tool/main/screenshots/attack_progress.png)

## 🔧 Prerequisites

- Kali Linux (latest version recommended)
- Python 3.x
- Wireless card supporting monitor mode and packet injection
- Root privileges

## 📦 Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd wifi-deauth-tool
```

2. Run the tool:
```bash
sudo python3 deauth_tool.py
```

The tool will automatically:
- Create a virtual environment if needed
- Install required dependencies
- Launch in the virtual environment

## 🚀 Usage

The tool features an intuitive, interactive interface. Simply follow the on-screen prompts:

1. **Interface Selection**
   - View available wireless interfaces
   - Select interface by number
   - Automatic monitor mode configuration

2. **Network Scanning**
   - Real-time network discovery
   - View signal strength and channels
   - Select target network from list

3. **Client Detection**
   - Automatic client discovery
   - Device type identification
   - Select specific client or target all

4. **Attack Execution**
   - Real-time packet statistics
   - Live rate calculation
   - Progress monitoring

## 📊 Interface Features

### Network List Display
```
┌─ Discovered Networks ──────────────────────────────────────┐
│ No. │ BSSID             │ Channel │ Signal │ SSID         │
├─────┼──────────────────┼─────────┼────────┼──────────────┤
│  1  │ XX:XX:XX:XX:XX:XX│   1     │  -67   │ Network1     │
│  2  │ YY:YY:YY:YY:YY:YY│   6     │  -72   │ Network2     │
└─────┴──────────────────┴─────────┴────────┴──────────────┘
```

### Client List Display
```
┌─ Connected Clients ───────────────────────────────────────┐
│ No. │ Client MAC         │ Device Type                    │
├─────┼──────────────────┼────────────────────────────────┤
│  1  │ AA:AA:AA:AA:AA:AA│ 📱 Apple Device                │
│  2  │ BB:BB:BB:BB:BB:BB│ 🤖 Android Device              │
└─────┴──────────────────┴────────────────────────────────┘
```

### Attack Progress Display
```
┌─ Attack Information ───────────────────────────────────────┐
│ Packets Sent: 1337                                         │
│ Time Elapsed: 42.5s                                        │
│ Rate: 31.5 packets/s                                       │
└──────────────────────────────────────────────────────────┘
```

## 🛡️ Defense Against Deauth Attacks

To protect against deauthentication attacks:
1. Use WPA3 when possible
2. Implement 802.11w (Protected Management Frames)
3. Monitor network for suspicious deauthentication frames
4. Use IDS/IPS systems
5. Keep firmware and drivers updated

## 🐛 Troubleshooting

Common issues and solutions:

1. **Monitor Mode Failed**
   ```bash
   sudo airmon-ng check kill
   sudo airmon-ng start wlan0
   ```

2. **Permission Denied**
   - Ensure running with sudo
   - Check wireless card permissions

3. **No Networks Found**
   - Verify card supports monitor mode
   - Check antenna connection
   - Try different channel ranges

4. **Virtual Environment Issues**
   - Delete the `venv` directory
   - Rerun the tool to create a new environment

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License
Copyright (c) 2024 WiFi Deauthentication Tool
```

## 📚 Resources

- [Kali Linux Tools](https://www.kali.org/tools/)
- [802.11 Security](https://www.wi-fi.org/discover-wi-fi/security)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Rich Documentation](https://rich.readthedocs.io/)

## 🙏 Acknowledgments

- Scapy project for packet manipulation
- Aircrack-ng suite for wireless tools
- Rich library for the beautiful interface
- Kali Linux team
- Open source community

## 📧 Contact

For bugs, features, or questions, please [open an issue](https://github.com/yourusername/wifi-deauth-tool/issues). 