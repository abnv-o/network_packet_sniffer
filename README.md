# Packet Sniffer

A Python-based packet sniffer that captures and analyzes network packets. This tool can decode and display Ethernet, IPv4, ICMP, TCP, and UDP packets.

## Features

- **Ethernet Frame Analysis**: Displays source and destination MAC addresses along with the Ethernet protocol.
- **IPv4 Packet Analysis**: Extracts and shows details of IPv4 packets including version, header length, TTL, and protocol.
- **ICMP Packet Analysis**: Decodes ICMP packets to display type, code, and checksum.
- **TCP Segment Analysis**: Analyzes TCP segments including source and destination ports, sequence numbers, acknowledgment numbers, and flags.
- **UDP Segment Analysis**: Extracts source and destination ports and the size of UDP segments.

## Prerequisites

- Python 3.x
- Appropriate privileges (root or administrator) to create raw sockets.

## Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/your-username/packet-sniffer.git
    cd packet-sniffer
    ```

2. **Run the Script**:

    Ensure you have the necessary permissions to run raw sockets. On Unix-like systems, you might need to use `sudo`:

    ```bash
    sudo python packet_sniffer.py
    ```

    On Windows, you may need to run the script as an administrator.

## Usage

1. Run the script using Python:

    ```bash
    python packet_sniffer.py
    ```

2. The script will detect the operating system and create an appropriate socket for capturing packets.

3. Packets will be analyzed and displayed in the terminal. The output will include details about Ethernet frames, IPv4 packets, ICMP, TCP, and UDP segments as applicable.

4. To stop the packet capture, interrupt the script with `Ctrl+C`.

## Code Overview

- **ethernet_frame(data)**: Parses Ethernet frames to extract MAC addresses and protocol.
- **get_mac_addressess(addressess_bytes)**: Formats MAC addresses.
- **ipv4packet(data)**: Parses IPv4 packets to extract relevant details.
- **ipv4(address)**: Formats IPv4 addresses.
- **icmp_packet(data)**: Parses ICMP packets.
- **tcp_segment(data)**: Parses TCP segments.
- **udp_segment(data)**: Parses UDP segments.
- **format_multi_line(prefix, string, size=80)**: Formats byte data for readable output.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Push to the feature branch.
5. Submit a pull request.

## Contact

For any questions or suggestions, please contact [abhinavrajesh2002@gmail.com](mailto:abhinavrajesh2002@gmail.com).

