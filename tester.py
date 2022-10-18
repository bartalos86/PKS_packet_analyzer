import os
import main

pacaps = os.listdir("Captures")
schema = "schema-all.yaml"

test_protocols = ["TCP"]

for i in range(len(pacaps)):
    pcap = pacaps[i]
    output_yaml = pcap.strip(".pcap")
    print(pcap)
    # main.analyze_frames(pcap)
    for j in range(len(test_protocols)):
        os.system(f"python main.py -p {test_protocols[j]} {pcap}")
        os.system(f"python validator.py -d outputs/{output_yaml}.yaml -s schemas/{schema}")  