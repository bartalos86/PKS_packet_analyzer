import os
import main

pacaps = os.listdir("Captures")
schema = "schema-all.yaml"

test_protocols = ["FTP-DATA","UDP","HTTP","ICMP","ARP"]

for i in range(len(pacaps)):
    pcap = pacaps[i]
    output_yaml = pcap.strip(".pcap")
    print(pcap)
    #main.analyze_frames(pcap)
    for j in range(len(test_protocols)):
        filter = test_protocols[j]
        os.system(f"python main.py -p {filter} {pcap}")
        os.system(f"python validator.py -d outputs/{output_yaml}-{filter}.yaml -s schemas/{schema}")  