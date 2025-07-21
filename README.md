# Network Packet Sniffer

A powerful and lightweight command-line packet sniffing tool built with Python. It captures and analyzes network traffic in real-time, decoding various protocols to provide detailed insights into your network communications.

---

## Key Features

-   **Cross-Platform Support**: Works on Linux, macOS, and Windows.
-   **Multi-Protocol Analysis**: Decodes multiple layers of the network stack:
    -   Ethernet Frames (MAC Addresses, Protocol)
    -   IPv4 Packets (Version, TTL, Source/Destination IP)
    -   TCP Segments (Ports, Sequence/Acknowledgement Numbers, Flags)
    -   UDP Segments (Ports, Size)
    -   ICMP Packets (Type, Code, Checksum)
-   **Real-Time Capture**: Captures and displays packet data as it arrives on the network interface.
-   **Detailed Output**: Provides clearly formatted and indented output for easy readability of packet information.
-   **No External Dependencies**: Runs using only standard Python libraries.

---

## Badges

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

---

## Table of Contents

-   [Installation](#installation)
-   [Usage](#usage)
-   [Architecture Overview](#architecture-overview)
-   [Code Documentation](#code-documentation)
-   [Development](#development)
-   [Testing](#testing)
-   [Contributing](#contributing)
-   [License](#license)
-   [Contact](#contact)

---

## Installation

### Prerequisites

-   **Python 3.x**: Ensure you have Python 3 installed on your system.
-   **Administrator/Root Privileges**: The tool requires elevated privileges to create raw sockets for packet capture.

### Step-by-Step Guide

1.  **Clone the Repository**:
    ```bash
    git clone [https://github.com/your-username/packet-sniffer.git](https://github.com/your-username/packet-sniffer.git)
    cd packet-sniffer
    ```

2.  **No Dependencies to Install**:
    The script uses only Python's standard libraries, so no `pip install` commands are necessary.

---

## Usage

Run the script from your terminal with the appropriate privileges for your operating system.

-   **On Linux or macOS**:
    Use `sudo` to provide root privileges.
    ```bash
    sudo python3 sniffer.py
    ```

-   **On Windows**:
    Open Command Prompt or PowerShell **as an Administrator** and run the script.
    ```powershell
    python sniffer.py
    ```

### Expected Output

The script will start capturing packets immediately and display them in the console. The output will be formatted to show the breakdown of each captured packet, from the Ethernet frame down to the transport layer protocol.

To stop the capture, press `Ctrl+C`. The script will clean up and close the socket before exiting.

---

## Architecture Overview

The packet sniffer operates on a simple yet effective architecture:

1.  **Socket Creation**: The application first detects the host operating system (Linux/macOS or Windows) to create an appropriate raw network socket.
    -   On **Linux/macOS**, it uses `socket.AF_PACKET` to capture at the link layer (Ethernet).
    -   On **Windows**, it uses `socket.AF_INET` with `IPPROTO_IP` and enables promiscuous mode (`SIO_RCVALL`) to capture IP packets.

2.  **Packet Capture Loop**: The script enters an infinite loop, continuously listening for and receiving raw data from the socket using `connection.recvfrom()`.

3.  **Layered Parsing**: Each captured raw packet (a byte string) is passed through a series of parsing functions that decode it layer by layer:
    -   `ethernet_frame()`: The entry point for parsing. It unpacks the destination MAC, source MAC, and protocol type from the first 14 bytes.
    -   `ipv4packet()`: If the Ethernet protocol is identified as IPv4 (protocol 8), this function is called to unpack the IP header.
    -   `icmp_packet()`, `tcp_segment()`, `udp_segment()`: Based on the protocol field in the IP header, the appropriate function is called to unpack the transport layer segment.

4.  **Formatted Output**: The data extracted at each layer is printed to the console with clear labels and indentation for readability. Any remaining payload data is printed in a formatted, multi-line hex representation.

---

## Code Documentation

The script is built around a set of specialized functions, each responsible for unpacking a specific protocol layer.

| Function                     | Description                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| `main()`                     | Orchestrates the entire process: detects the OS, creates the socket, runs the capture loop, and handles cleanup. |
| `ethernet_frame(data)`       | Unpacks the destination and source MAC addresses and protocol from a raw Ethernet frame.                |
| `get_mac_addressess(bytes)`  | A helper function to format a 6-byte sequence into a standard MAC address string (e.g., `AA:BB:CC:DD:EE:FF`). |
| `ipv4packet(data)`           | Unpacks the IPv4 header, including version, TTL, protocol, and source/target IP addresses.              |
| `ipv4(address)`              | A helper function to format a 4-byte sequence into a standard IPv4 address string (e.g., `192.168.1.1`). |
| `tcp_segment(data)`          | Unpacks a TCP segment to get ports, sequence/acknowledgement numbers, and flags (SYN, ACK, FIN, etc.).    |
| `udp_segment(data)`          | Unpacks a UDP segment to get source/destination ports and segment size.                                 |
| `icmp_packet(data)`          | Unpacks an ICMP packet to get the type, code, and checksum.                                             |
| `format_multi_line(prefix, string)` | A utility function to format the raw payload data for clean, indented display in the terminal.    |

---

## Development

### Local Setup

1.  Clone the repository as shown in the [Installation](#installation) section.
2.  It is recommended to use a virtual environment to manage dependencies for any future development.
    ```bash
    # Create a virtual environment
    python3 -m venv .venv

    # Activate it
    # On Linux/macOS
    source .venv/bin/activate
    # On Windows
    .\.venv\Scripts\activate
    ```
3.  The `.gitignore` file is already configured to exclude the `.venv` directory.

### Code Style

There is no formal linter or code style guide enforced in this project yet, but contributions should aim to follow the general style of the existing codebase and adhere to [PEP 8](https://www.python.org/dev/peps/pep-0008/) standards.

---

## Testing

This project does not currently include an automated test suite. Future contributions to add unit or integration tests would be welcome.

---

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Please fork the repository and submit a pull request with your changes.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## License

This project is distributed under the MIT License. See the `LICENSE` file for more information.

---

## Contact

Abhinav O - [abhinavrajesh2002@gmail.com](mailto:abhinavrajesh2002@gmail.com)

Project Link: [https://github.com/your-username/packet-sniffer](https://github.com/your-username/packet-sniffer)
