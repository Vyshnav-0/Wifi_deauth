# WiFi Deauthentication Tool 🛡️

A command-line utility for Kali Linux designed for cybersecurity research and penetration testing. This tool allows security professionals to test network security by simulating WiFi deauthentication attacks.

## ⚠️ Legal Disclaimer

**This tool is for EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY.**
- Only use on networks you own or have explicit permission to test
- Unauthorized use may be illegal in your jurisdiction
- The authors take no responsibility for misuse of this tool

## ✨ Features

- 🔍 Interactive mode with guided interface selection
- 📡 Automatic wireless interface detection
- 🌐 Network scanning with signal strength
- 👥 Client detection with device type identification
- 📊 Real-time attack monitoring
- 📝 Detailed logging system
- 🎨 Colorized output for better readability

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

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure your wireless card supports monitor mode:
```bash
sudo airmon-ng
```

## 🚀 Usage

### Interactive Mode (Recommended)

Run the tool in interactive mode for a guided experience:
```bash
sudo python3 deauth_tool.py --interactive
```

The interactive mode will:
1. Show available wireless interfaces
2. Enable monitor mode automatically
3. Scan and display nearby networks
4. Scan for clients on selected network
5. Allow targeting specific client or all clients
6. Provide real-time attack feedback

### Command-Line Mode

Basic network scanning:
```bash
sudo python3 deauth_tool.py --interface wlan0 --scan
```

Attack specific client:
```bash
sudo python3 deauth_tool.py --interface wlan0 --bssid XX:XX:XX:XX:XX:XX --client YY:YY:YY:YY:YY:YY --packets 100
```

### Command Line Options

- `--interactive`, `-i`: Start interactive mode
- `--interface`: Wireless interface to use (e.g., wlan0)
- `--scan`, `-s`: Scan for networks
- `--bssid`, `-b`: Target access point MAC address
- `--client`, `-c`: Target client MAC address (optional)
- `--packets`, `-p`: Number of deauth packets to send (default: 50)
- `--interval`: Interval between packets in seconds (default: 0.1)

## 📝 Features in Detail

### Network Scanning
- Lists all nearby WiFi networks
- Shows BSSID (MAC address)
- Displays channel number
- Shows signal strength
- Identifies hidden SSIDs

### Client Detection
- Scans for connected clients
- Attempts to identify device types:
  - Apple devices
  - Android devices
  - Windows devices
  - Other/Unknown devices
- Shows real-time client discovery

### Attack Modes
- Target specific client
- Target all clients on network
- Customizable packet count
- Adjustable packet interval
- Automatic cleanup after attack

### Monitoring
- Real-time attack progress
- Packet sending confirmation
- Signal strength monitoring
- Detailed logging to file
- Color-coded status messages

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

## 🙏 Acknowledgments

- Scapy project for packet manipulation
- Aircrack-ng suite for wireless tools
- Kali Linux team
- Open source community

## 📧 Contact

For bugs, features, or questions, please [open an issue](https://github.com/yourusername/wifi-deauth-tool/issues). 