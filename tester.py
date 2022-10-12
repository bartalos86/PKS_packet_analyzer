import os
import main

pacaps = os.listdir("Captures")
schema = "schema-task-1.yaml"

for i in range(len(pacaps)):
    pcap = pacaps[i]
    output_yaml = pcap.strip(".pcap")
    print(pcap)
    main.analyze_frames(pcap)
    os.system(f"python validator.py -d outputs/{output_yaml}.yaml -s schemas/{schema}")  