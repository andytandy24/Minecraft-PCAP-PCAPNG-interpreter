import pyshark
import argparse

# Converts 64 bit to coordinates 
'''
def split_coordinates(value):
    x = (value >> 38) & 0x3FFFFFF 
    z = (value >> 12) & 0x3FFFFFF 
    y = value & 0xFFF 

    if x & (1 << 25):
        x -= (1 << 26)
    
    if z & (1 << 25):
        z -= (1 << 26)

    if y & (1 << 11): 
        y -= (1 << 12)

    return [x, z, y]
'''

# CLI
parser = argparse.ArgumentParser(description="This script finds spesific events in a minecraft PCAP/PCAPNG recording. \nGo to wiki.vg/Protocol to find the event you want to find")
parser.add_argument("-i", "--input", type=str, help="Input file path of PCAP/PCAPNG file")
parser.add_argument("-P", "--packetId", type=str, help="Packet ID of the desired packet")
parser.add_argument("-o", "--output", type=str, default="output.txt", help="Path of output file")
args = parser.parse_args()

inputFile = args.input

# Main
cap = pyshark.FileCapture(inputFile, display_filter=f'tcp.payload[2] == {args.packetId}')

for packet in cap:
    packetId = "".join(packet['tcp'].segment_data.split(":")[2])
    packet = " ".join(packet['tcp'].segment_data.split(":")[3:])
    print(f'Packet ID: 0x{packetId}\nPacket: {packet}\n')

cap.close()
