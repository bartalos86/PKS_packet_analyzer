from scapy.all import rdpcap
from scapy.compat import raw 
from yaml import dump

packets = rdpcap('Captures/eth-1.pcap')
length  = len(packets)

etherTypesF = open('Protocols/EtherTypes.txt', 'r')
etherTypes = {}

for line in etherTypesF:
    splitLine = line.split(':')
    if len(splitLine) > 1:
        etherTypes[splitLine[0]] = splitLine[1]
        
source_constant = 8;
protocol_constant = 24;
length_constant = 28;

for i in range(length):
    packet = raw(packets[i]).hex()
    packet_data_length = packet[length_constant:length_constant+2];
    packet_length=packet[protocol_constant:protocol_constant+4];
    dest_mac = f"{packet[0:2]}:{packet[2:4]}:{packet[4:6]}:{packet[6:8]}"
    dest_src = f"{packet[source_constant:source_constant+2]}:{packet[source_constant+2:source_constant+4]}:{packet[source_constant+4:source_constant+6]}:{packet[source_constant+6:source_constant+8]}"
    
    if int(packet_length, base=16) >= 1500:
        frame_type = "Ethernet II"
    elif packet_length == 'aaaa':
        frame_type = "IEEE 802.3 SNAP"
    elif packet_length == 'ffff':
        frame_type = "IEEE 802.3 RAW"
    else:
        frame_type = "IEEE 802.3 LLC"

    ether_type = ""


    if frame_type == "Ethernet II":
        ether_type = f"{etherTypes[str(packet_length)]}".strip();
    # else:
    #     ether_type = ""
    packet_cap = packet.capitalize().strip()
    frame_dump = ""
    for i in range(len(packet_cap)):
        if (i % 32) == 0:
            frame_dump += '\n'
        elif i % 2 == 0 and i != 0:
            frame_dump += " "
        
        frame_dump += str(packet_cap[i].capitalize());

    yaml = dump({
        "frame_number": i,
        "frame_type": frame_type,
        "dest_mac": dest_mac,
        "dest_src": dest_src,
        "ether_type": ether_type,
        "len_frame": packet_data_length,
        "frame_dump": frame_dump
    },line_break='\n')
    print(yaml)




