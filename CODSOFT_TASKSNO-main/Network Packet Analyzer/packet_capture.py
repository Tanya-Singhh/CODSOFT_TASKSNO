from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime


# ---------------------------------------------------------
# Packet Capture and Network Protocol Analyzer
# Task 1 - Cybersecurity Internship Project
# ---------------------------------------------------------

packet_count = 0


def get_protocol(packet):
    """Identify the protocol used by the packet."""

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    elif packet.haslayer(ICMP):
        return "ICMP"

    elif packet.haslayer(ARP):
        return "ARP"

    elif packet.haslayer(IP):
        return "IP"

    return "Other"


def get_packet_data(packet):
    """
    Return a short, safe representation of packet payload.
    This avoids printing potentially huge or binary payloads.
    """

    if packet.haslayer(TCP):
        payload = bytes(packet[TCP].payload)

    elif packet.haslayer(UDP):
        payload = bytes(packet[UDP].payload)

    else:
        payload = b""

    if not payload:
        return "No application data"

    # Convert printable bytes to readable text.
    # Non-printable bytes are represented as dots.
    preview = ""

    for byte in payload[:50]:

        if 32 <= byte <= 126:
            preview += chr(byte)

        else:
            preview += "."

    if len(payload) > 50:
        preview += "..."

    return preview


def analyze_packet(packet):
    """Analyze and display information about one captured packet."""

    global packet_count

    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    print("\n" + "=" * 70)

    print(f"Packet Number : {packet_count}")
    print(f"Time          : {timestamp}")

    # -----------------------------------------------------
    # IP PACKET
    # -----------------------------------------------------

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = get_protocol(packet)

        packet_length = len(packet)

        print(f"Source IP     : {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol      : {protocol}")
        print(f"Packet Length : {packet_length} bytes")

        # TCP information
        if packet.haslayer(TCP):

            print(f"Source Port   : {packet[TCP].sport}")
            print(f"Dest. Port    : {packet[TCP].dport}")
            print(f"TCP Flags     : {packet[TCP].flags}")

        # UDP information
        elif packet.haslayer(UDP):

            print(f"Source Port   : {packet[UDP].sport}")
            print(f"Dest. Port    : {packet[UDP].dport}")

        # ICMP information
        elif packet.haslayer(ICMP):

            print(f"ICMP Type     : {packet[ICMP].type}")
            print(f"ICMP Code     : {packet[ICMP].code}")

        print(f"Packet Data   : {get_packet_data(packet)}")

    # -----------------------------------------------------
    # ARP PACKET
    # -----------------------------------------------------

    elif packet.haslayer(ARP):

        print("Protocol      : ARP")
        print(f"Source MAC    : {packet[ARP].hwsrc}")
        print(f"Source IP     : {packet[ARP].psrc}")
        print(f"Destination MAC: {packet[ARP].hwdst}")
        print(f"Destination IP : {packet[ARP].pdst}")

    else:

        print("Protocol      : Other")
        print(f"Packet Length : {len(packet)} bytes")

    print("=" * 70)


def main():

    print("=" * 70)
    print("        PYTHON NETWORK PACKET CAPTURE TOOL")
    print("=" * 70)

    print("\nStarting packet capture...")
    print("Press CTRL + C to stop the program.\n")

    try:

        # Capture packets.
        #
        # count=0 means capture continuously.
        # store=False prevents Scapy from keeping every packet
        # in memory after processing it.

        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n\n" + "=" * 70)
        print("PACKET CAPTURE STOPPED")
        print("=" * 70)

        print(f"Total packets captured: {packet_count}")

        print("\nProgram completed successfully.")


if __name__ == "__main__":
    main()