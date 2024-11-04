import pyshark
import argparse

# CLI
parser = argparse.ArgumentParser(description="This script finds spesific events in a minecraft PCAP/PCAPNG recording. \nGo to wiki.vg/Protocol to find the event you want to find")
parser.add_argument("-i", "--input", type=str, help="Input file path of PCAP/PCAPNG file")
parser.add_argument("-P", "--packetId", type=str, help="Packet ID of the desired packet")
args = parser.parse_args()

inputFile = args.input

# Main
cap = pyshark.FileCapture(inputFile, display_filter=f'tcp.payload[2] == {args.packetId}')

for packet in cap:
    packetId = "".join(packet['tcp'].segment_data.split(":")[2])
    packet = " ".join(packet['tcp'].segment_data.split(":")[3:])
    print(f'Packet ID: 0x{packetId}\nPacket: {packet}\n')

cap.close()
