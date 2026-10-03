# ⚡ DHCP Spoofer

[![GitHub](https://img.shields.io/badge/github-repo-3776AB?style=for-the-badge&logo=github&logoColor=white)](https://github.com/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Network%20Packets-red?style=for-the-badge)](https://scapy.net/)

> A lightweight DHCP spoofing demonstration tool built with Python and Scapy for authorized security research and isolated network labs.

---

## 📖 Overview

**DHCP Spoofer** is a Python-based networking tool that demonstrates how DHCP traffic can be monitored and how DHCP `OFFER` and `ACK` packets can be constructed using [Scapy](https://scapy.net/).

The program listens for DHCP traffic, identifies `DHCPDISCOVER` and `DHCPREQUEST` messages, and responds with crafted DHCP packets.

> [!WARNING]
> **For educational and authorized testing only.**
>
> DHCP spoofing can interfere with legitimate network infrastructure and may cause clients to receive incorrect network configuration.
>
> Only use this project on networks you own or have explicit permission to test. An isolated virtual or physical lab environment is strongly recommended.

---

## ✨ Features

- 📡 DHCP packet sniffing
- 🔍 DHCP `DISCOVER` detection
- 📦 DHCP `OFFER` packet construction
- 📨 DHCP `REQUEST` detection
- ✅ DHCP `ACK` packet construction
- 🌐 CIDR-based network calculation
- 🎲 Random usable IP selection
- 🛠️ Configurable network interface
- 🌍 Configurable gateway and DNS
- 🎨 Colorized terminal output
- 🪶 Memory-efficient packet sniffing with `store=False`

---

## 🫯 DHCP Spoofing

**FROM [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/003/)**

```text
Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network.
By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols.
This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.

DHCP is based on a client-server model and has two functionalities:
1. a protocol for providing network configuration settings from a DHCP server to a client.
2. a mechanism for allocating network addresses to clients.

The typical server-client interaction is as follows:
    - The client broadcasts a DISCOVER message.
    - The server responds with an OFFER message, which includes an available network address.
    - The client broadcasts a REQUEST message, which includes the network address offered.
    - The server acknowledges with an ACK message and the client receives the network configuration parameters.

Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers.
Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network.
```
---

## 🧠 How It Works

The application follows a simplified DHCP exchange:

```text
                     DHCP CLIENT
                          │
                          │ DHCPDISCOVER
                          ▼
                  ┌───────────────┐
                  │ DHCP Spoofer  │
                  └───────┬───────┘
                          │
                          │ DHCPOFFER
                          ▼
                     DHCP CLIENT
                          │
                          │ DHCPREQUEST
                          ▼
                  ┌───────────────┐
                  │ DHCP Spoofer  │
                  └───────┬───────┘
                          │
                          │ DHCPACK
                          ▼
                     DHCP CLIENT
```
The program
1. Captures DHCP packets on the selected interface.
2. Extracts the DHCP message type and transaction ID.
3. Responds to DHCP `DISCOVER` messages with an `OFFER`.
4. Processes DHCP `REQUEST` messages.
5. Sends an `ACK` when the request is addressed to the program's configured server identity.
6. Uses a randomly selected host address from the supplied CIDR network.

---

## 📋 Requirements

- Python 3
- Scapy
- A network interface capable of seeing DHCP broadcast traffic
- Appropriate privileges for packet capture/transmission

Install Scapy with:

```text
python3 -m pip install scapy
sudo apt-get install python3-scapy
```

For safer experimentation, use an isolated virtual network rather than a production or shared LAN.

---

## 🚀 Running the Project

Clone the repository and enter the project directory:

```text
git clone <your-repository-url>
cd <your-repository-directory>
```

Then run:

```text
sudo python3 dhcp_spoofer.py
```

The program accepts the following command-line options:


| Option | Description | Default |
|---|---|---|
| -i, --iface | Network interface | eth0 |
| -g, --gateway | Gateway advertised in DHCP responses | 192.168.1.1 |
| -n, --dns | DNS server advertised in DHCP responses |192.168.1.1 |
| -r, --range | IPv4 network in CIDR notation | 192.168.1.0/24 |

For example, in an isolated test network, you can configure the program with values appropriate to that lab:

```text
sudo python3 dhcp_spoofer.py --iface eth0 --gateway 192.168.50.1 --dns 192.168.50.1 --range 192.168.50.0/24
```

---

## 🖥️ Example Output

```text
A typical startup sequence looks similar to:

╭──────────────────────────────────────────╮
│            DHCP Spoofer v1.0             │
╰──────────────────────────────────────────╯

[*] DHCP Configuration
[+] Network: 192.168.50.0/24
[+] Subnet mask: 255.255.255.0
[+] Gateway: 192.168.50.1
[+] DNS: 192.168.50.1
[+] Random IP address: 192.168.50.137

[•] Sniffing DHCP packets...
```
When DHCP traffic is observed:

```text
[+] DHCP DISCOVER received from aa:bb:cc:dd:ee:ff
[+] DHCP OFFER: 192.168.50.137 -> aa:bb:cc:dd:ee:ff

[+] DHCP REQUEST received from aa:bb:cc:dd:ee:ff
[+] DHCP ACK: 192.168.50.137 -> aa:bb:cc:dd:ee:ff
```

---

🧩 Project Structure
```text
.
├── dhcp_spoofer.py
└── README.md
```

## Main components

`banner()`

Displays the application banner.

`network_calculation()`

Converts the supplied CIDR network into an IPv4 network, determines its subnet mask, and selects a usable host address.

`packet_sniffer()`

Starts Scapy's packet capture process and filters for DHCP-related UDP traffic.

`packet_handler()`

Examines captured DHCP packets and determines whether they represent a DISCOVER or REQUEST.

`build_dhcp_offer()`

Constructs a DHCP OFFER packet.

`build_dhcp_ack()`

Constructs a DHCP ACK packet.

`main()`

Parses command-line arguments, calculates network parameters, displays configuration information, and starts packet capture.

---

## 🔬 Security-Lab Use Cases

This project can be useful for studying:

- DHCP packet structure
- BOOTP/DHCP relationships
- DHCP message types
- Scapy packet construction
- Layer-2 broadcast traffic
- Network-security monitoring
- DHCP spoofing detection
- Rogue DHCP server behavior

A good lab setup is an isolated virtual network containing:

```text
┌──────────────────────┐
│   Isolated Network   │
│                      │
│  ┌───────┐           │
│  │Client │──────┐    │
│  └───────┘      │    │
│                 │    │
│  ┌────────────┐ │    │
│  │ Lab DHCP   │ │    │
│  │ Spoofer    │─┘    │
│  └────────────┘      │
│                      │
└──────────────────────┘
```

This keeps experiments away from real users and production DHCP infrastructure.

---

## ⚠️ Limitations

This is a demonstration tool, not a production DHCP implementation.

Some important limitations include:

- The selected IP address is randomly chosen rather than allocated through a persistent lease database.
- There is no lease management.
- There is no conflict detection before offering an address.
- DHCP state is not persisted.
- The implementation handles only a subset of DHCP message types.
- DHCP options are intentionally minimal.
- IPv6 DHCP is not supported.
- Network configuration must be supplied correctly by the operator.
- Multiple legitimate or rogue DHCP servers may respond simultaneously.

---

## 🛡️ Defensive Perspective

The same concepts demonstrated by this project can be used defensively to understand and detect rogue DHCP activity.

Organizations can investigate unexpected DHCP behavior by monitoring for:

- Multiple DHCP servers appearing on the same network segment
- Unexpected DHCP OFFER packets
- DHCP server identifiers that don't belong to authorized infrastructure
- Unexpected gateway or DNS-server advertisements
- DHCP traffic originating from unauthorized switch ports

Network controls such as DHCP snooping, appropriate switch configuration, segmentation, and monitoring can help reduce the impact of rogue DHCP servers.

---

## 📚 Protocol References

Useful resources for understanding the underlying protocols:

**RFC 2131 — Dynamic Host Configuration Protocol**

**RFC 2132 — DHCP Options and BOOTP Vendor Extensions**

**Scapy documentation** — packet crafting and network protocol manipulation

---

## ⚖️ Disclaimer

This software is provided for educational and authorized security-testing purposes.

Do not deploy it on networks without explicit authorization. Improper use can cause DHCP conflicts, loss of network connectivity, incorrect client configuration, or unintended traffic redirection.

The author is not responsible for damage or disruption resulting from unauthorized use.
