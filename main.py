from scapy.all import rdpcap

packets = rdpcap('Captures/trace-27.pcap')
length  = len(packets)

for i in range(length):
    packet = str(packets[i])
    #print(packet[4:6] + " - " + packet[8:10])
    print(packet[26:30].replace("x","").replace("\\",""))
    #print(int("0" + packet[4:6],base=16))




