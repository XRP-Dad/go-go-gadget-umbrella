# GoGoGadget 🕵️‍♂️

[![Version](https://img.shields.io/badge/version-1.1-blue.svg)](https://github.com/XRP-Dad/go-go-gadget-umbrella)
[![Codename](https://img.shields.io/badge/codename-Umbrella-orange.svg)](https://github.com/XRP-Dad/go-go-gadget-umbrella)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/XRP-Dad/go-go-gadget-umbrella/LICENSE)

> A distributed network monitoring and management tool inspired by Inspector Gadget! 🚀

## 📖 Overview

GoGoGadget is a powerful, distributed network monitoring system that helps you monitor and manage your network devices through multiple proxies. It currently supports PING and SNMP checks, with SSH and traceroute capabilities coming in future releases.

```mermaid
graph TD
    A[GoGoGadget Server] --> B[Proxy 1]
    A --> C[Proxy 2]
    A --> D[Proxy N]
    B --> E[Network Devices]
    C --> E
    D --> E
    style A fill:#f9f,stroke:#333,stroke-width:4px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style C fill:#bbf,stroke:#333,stroke-width:2px
    style D fill:#bbf,stroke:#333,stroke-width:2px
    style E fill:#bfb,stroke:#333,stroke-width:2px
```

## ✨ Features

- 🌐 Distributed monitoring through multiple proxies
- 📊 Smart proxy selection based on performance
- 🔍 Current monitoring methods:
  - PING (latency measurement)
  - SNMP (v1 and v2c support)
- 🚀 Coming soon:
  - SSH (port availability)
  - Traceroute (path analysis)
- 🚦 Real-time status monitoring
- 📈 Performance scoring system
- 🔄 Automatic failover
- 🛡️ Error resilience

## 🚀 Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/XRP-Dad/go-go-gadget-umbrella.git
cd go-go-gadget-umbrella
```

2. Run the installer:
```bash
chmod +x install_gogogadget.sh
./install_gogogadget.sh
```

3. Choose your installation type:
```
Please select installation type:
1) Server
2) Proxy
3) Uninstall
4) Cancel
```

### Configuration

The configuration files are located in `/opt/gogogadget/`:

- `constants.json`: Global configuration settings
- `server_config.json`: Server-specific configuration (for server installations)

Example `constants.json`:
```json
{
  "default_community": "public",
  "original_ping_weight": 0.6,
  "original_snmp_weight": 0.4,
  "max_ping_ms": 1000
}
```

## 📡 Usage Examples

### Basic Device Check
```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "checks": ["ping", "snmp"],
    "community": "public"
  }'
```

### SNMP Monitoring with Custom OIDs
```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "checks": ["ping", "snmp"],
    "community": "public",
    "snmp_oids": [
      ".1.3.6.1.2.1.1.1.0",
      ".1.3.6.1.2.1.1.5.0"
    ]
  }'
```

### Status Check
```bash
curl http://localhost:8080/status
```

## 🔄 Architecture

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Proxy
    participant Device
    
    Client->>Server: Request device check
    Server->>Server: Calculate best proxy
    Server->>Proxy: Forward check request
    Proxy->>Device: Perform checks (PING/SNMP)
    Device-->>Proxy: Response
    Proxy-->>Server: Results
    Server-->>Client: Aggregated response
```

## 🎯 Performance Scoring

GoGoGadget uses a scoring system to determine the best proxy for each check:

```mermaid
pie
    title "Current Check Weights"
    "PING" : 60
    "SNMP" : 40
```

## 🔧 Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check service status
   systemctl status gogogadget-server
   
   # Check logs
   journalctl -u gogogadget-server -n 50
   ```

2. **SNMP Checks Failing**
   - Verify SNMP community string
   - Check if SNMP is enabled on the target device
   - Ensure UDP port 161 is accessible

3. **Proxy Connection Issues**
   ```bash
   # Check proxy status
   curl http://localhost:8080/status
   
   # Test proxy connectivity
   telnet proxy_ip 8081
   ```

### Debug Mode

Enable debug logging by setting the environment variable:
```bash
export GOGOGADGET_DEBUG=1
systemctl restart gogogadget-server
```

## 🔍 Monitoring Dashboard

Access the monitoring dashboard at `http://localhost:8080/status` for a comprehensive view of your network:

```mermaid
graph LR
    A[Dashboard] --> B[Proxy Status]
    A --> C[Device Status]
    B --> E[Health]
    B --> F[Performance]
    C --> G[Connectivity]
    C --> H[Response Time]
```

## 📊 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/check` | POST | Perform device checks |
| `/status` | GET | Get system status |
| `/version` | GET | Get version info |
| `/simplecheck` | GET | Simple device check |

## 🗺️ Roadmap

- [ ] SSH connectivity checks
- [ ] Traceroute analysis
- [ ] Enhanced performance metrics
- [ ] Web-based dashboard
- [ ] SNMP v3 support
- [ ] Custom check plugins

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by Inspector Gadget
- Built with Go
- Special thanks to all contributors

---

Made with ❤️ by the GoGoGadget Team 