# WiFi Deauthentication Tool

A command-line utility for Kali Linux designed for cybersecurity research and penetration testing. This tool allows security professionals to test network security by simulating WiFi deauthentication attacks.

## ⚠️ Legal Disclaimer

**This tool is for EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY.**
- Only use on networks you own or have explicit permission to test
- Unauthorized use may be illegal in your jurisdiction
- The authors take no responsibility for misuse of this tool

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

Basic usage:
```bash
sudo python3 deauth_tool.py --interface wlan0 --scan
```

Attack specific client:
```bash
sudo python3 deauth_tool.py --interface wlan0 --bssid XX:XX:XX:XX:XX:XX --client YY:YY:YY:YY:YY:YY --packets 100
```

### Command Line Options

- `--interface`: Wireless interface to use (e.g., wlan0)
- `--scan`: Scan for nearby access points
- `--bssid`: Target access point MAC address
- `--client`: Target client MAC address (optional)
- `--packets`: Number of deauth packets to send (default: 50)
- `--interval`: Interval between packets in seconds (default: 0.1)
- `--log`: Enable logging to file

## 📝 Features

- Scan nearby WiFi networks
- List connected clients
- Send deauthentication packets to specific clients or all clients
- Real-time attack monitoring
- Detailed logging
- Colorized output

## 🛡️ Defense Against Deauth Attacks

To protect against deauthentication attacks:
1. Use WPA3 when possible
2. Implement 802.11w (Protected Management Frames)
3. Monitor network for suspicious deauthentication frames
4. Use IDS/IPS systems

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 