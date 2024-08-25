import socket
import struct
import sys
import textwrap

TAB_1 = '    - '
TAB_2 = '        - '
TAB_3 = '            - '
TAB_4 = '                - '

DATA_TAB_1 = '    '
DATA_TAB_2 = '        '
DATA_TAB_3 = '            '
DATA_TAB_4 = '                '

# Unpack ethernet
def ethernet_frame(data):
    # Capturing the first 14 bytes to get source and destination addresses
    dest_addressess, src_addressess, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addressess(dest_addressess), get_mac_addressess(src_addressess), socket.htons(protocol), data[14:]

def get_mac_addressess(addressess_bytes):
    # This function formats the address as a proper MAC address format
    bytes_str = map('{:02x}'.format, addressess_bytes)
    mac = ':'.join(bytes_str).upper()
    return mac

# Unpack IPv4 packet
def ipv4packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('!8x B B 2x 4s 4s ', data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]

# Format IPv4 address
def ipv4(address):
    return '.'.join(map(str, address))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H ', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    # Detecting OS for appropriate socket
    if sys.platform in ["linux", "linux2", "darwin"]:
        print("OS detected as Linux or macOS")
        try:
            connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except Exception as e:
            print(f"Failed to create socket: {e}")
            return
    elif sys.platform == "win32":
        print("OS detected as Windows")
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            connection.bind((socket.gethostname(), 0))
            # Enable promiscuous mode
            connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except Exception as e:
            print(f"Failed to create socket: {e}")
            return
    else:
        print("Unsupported OS")
        return

    try:
        while True:
            raw_data, address = connection.recvfrom(65565)
            dest_mac, src_mac, protocol, data = ethernet_frame(raw_data)
            print("\nEthernet Frame:")
            print(TAB_1 + f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {protocol}")

            # Ethernet protocol 8 for IPv4
            if protocol == 8:
                (version, header_length, ttl, protocol, src, target, data) = ipv4packet(data)
                print(TAB_1 + 'IPV4 Packet:')
                print(TAB_2 + 'Version:{}, Header Length:{}, TTL:{}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol:{}, Source:{}, Target:{}'.format(protocol, src, target))

                # ICMP
                if protocol == 1:
                    (icmp_type, code, checksum, data) = icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type:{}, Code:{}, Checksum:{}'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                # TCP
                elif protocol == 6:
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                    print(TAB_1 + 'TCP Packet:')
                    print(TAB_2 + 'Source Port:{}, Destination Port:{}'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence:{}, Acknowledgement:{}'.format(sequence, acknowledgement))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG:{}, ACK:{}, PSH:{}, RST:{}, SYN:{}, FIN:{}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(format_multi_line(DATA_TAB_3, data))
                # UDP
                elif protocol == 17:
                    (src_port, dest_port, size, data) = udp_segment(data)
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port:{}, Destination Port:{}, Size:{}'.format(src_port, dest_port, size))
                # Others
                else:
                    print(TAB_1 + 'Data:')
                    print(format_multi_line(DATA_TAB_2, data))
            else:
                print('Data:')
                print(format_multi_line(DATA_TAB_1, data))

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Disable promiscuous mode and close socket if on Windows
        if sys.platform == "win32":
            connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        connection.close()


main()
