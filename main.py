from scapy.all import rdpcap
from scapy.compat import raw 

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
    packet_ipv_type=packet[protocol_constant:protocol_constant+4];
    print("destination: " + packet[0:2] + ":" + packet[2:4] + ":" + packet[4:6] + ":" + packet[6:8])
    print("source: " + packet[source_constant:source_constant+2] + ":" + packet[source_constant+2:source_constant+4] + ":" + packet[source_constant+4:source_constant+6] + ":" + packet[source_constant+6:source_constant+8])
    print("protocol:" + etherTypes[str(packet_ipv_type)])
    print("length: " + packet_data_length)




