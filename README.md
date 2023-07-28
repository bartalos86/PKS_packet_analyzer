# Wireshark pcap packet analyzer
An application built in python which analyzes wireshark packet captures with the file extensions of .pcap and .xpcap.
It can dynamically detect protocol types in all layers and can be easily extended by appending new protocols to its database which is stored in .txt files. It analyzes and groups the protocols and their properties on each layer.
It is able to detect ad group continuous TCP and UDP communications. It is also able to detect and group ICMP packet fragments.

## Features
- Analyze .pcap and .xpcap files
- Detect all kinds of protocols on each layer
- Detect all information on the Transfer layer
- Analyze and gather further informations on other layers
- TCP and UDP communication grouping
- ICMP fragment grouping
- YAML file export

## Documentation
More in-depth documentation of the program can be found in the Documentation folder.

## Output
Output of the program is a yaml file with all the grouped and identified protocols and communications with also including the raw communication data.

```yaml
---
name: PKS2022/23
pcap_name: trace-26.pcap
packets:
  - frame_number: 1
    frame_type: Ethernet II
    len_frame_pcap: 352
    len_frame_medium: 356
    dst_mac: 01:80:C2:00:00:0E
    src_mac: 00:16:47:02:24:1A
    ether_type: LLDP
    hexa_frame: |
      01 80 C2 00 00 0E 00 16 47 02 24 1A 88 CC 02 07
      04 00 16 47 02 24 00 04 07 05 46 61 30 2F 32 34
      06 02 00 78 0A 06 53 77 69 74 63 68 0C F7 43 69
      73 63 6F 20 49 4F 53 20 53 6F 66 74 77 61 72 65
      2C 20 43 33 35 36 30 20 53 6F 66 74 77 61 72 65
      20 28 43 33 35 36 30 2D 49 50 53 45 52 56 49 43
      45 53 4B 39 2D 4D 29 2C 20 56 65 72 73 69 6F 6E
      20 31 32 2E 32 28 35 35 29 53 45 37 2C 20 52 45
      4C 45 41 53 45 20 53 4F 46 54 57 41 52 45 20 28
      66 63 31 29 0A 54 65 63 68 6E 69 63 61 6C 20 53
      75 70 70 6F 72 74 3A 20 68 74 74 70 3A 2F 2F 77
      77 77 2E 63 69 73 63 6F 2E 63 6F 6D 2F 74 65 63
      68 73 75 70 70 6F 72 74 0A 43 6F 70 79 72 69 67
      68 74 20 28 63 29 20 31 39 38 36 2D 32 30 31 33
      20 62 79 20 43 69 73 63 6F 20 53 79 73 74 65 6D
      73 2C 20 49 6E 63 2E 0A 43 6F 6D 70 69 6C 65 64
      20 4D 6F 6E 20 32 38 2D 4A 61 6E 2D 31 33 20 31
      30 3A 31 30 20 62 79 20 70 72 6F 64 5F 72 65 6C
      5F 74 65 61 6D 08 10 46 61 73 74 45 74 68 65 72
      6E 65 74 30 2F 32 34 0E 04 00 14 00 04 10 0C 05
      01 0A 14 1E FE 03 00 00 00 01 00 FE 06 00 80 C2
      01 00 01 FE 09 00 12 0F 01 03 6C 00 00 10 00 00
  - frame_number: 2
    frame_type: IEEE 802.3 LLC
    len_frame_pcap: 60
    len_frame_medium: 64
    dst_mac: 01:80:C2:00:00:00
    src_mac: 00:16:47:02:24:1A
    sap: STP
    hexa_frame: |
      01 80 C2 00 00 00 00 16 47 02 24 1A 00 26 42 42
      03 00 00 00 00 00 80 01 00 16 47 02 24 00 00 00
      00 00 80 01 00 16 47 02 24 00 80 1A 00 00 14 00
      02 00 0F 00 00 00 00 00 00 00 00 00
  - frame_number: 3
    frame_type: Ethernet II
    len_frame_pcap: 60
    len_frame_medium: 64
    dst_mac: 00:16:47:02:24:1A
    src_mac: 00:16:47:02:24:1A
    ether_type: ECTP
    hexa_frame: |
      00 16 47 02 24 1A 00 16 47 02 24 1A 90 00 00 00
      01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00
  - frame_number: 4
    frame_type: IEEE 802.3 LLC
    len_frame_pcap: 60
    len_frame_medium: 64
    dst_mac: 01:80:C2:00:00:00
    src_mac: 00:16:47:02:24:1A
    sap: STP
    hexa_frame: |
      01 80 C2 00 00 00 00 16 47 02 24 1A 00 26 42 42
      03 00 00 00 00 00 80 01 00 16 47 02 24 00 00 00
      00 00 80 01 00 16 47 02 24 00 80 1A 00 00 14 00
      02 00 0F 00 00 00 00 00 00 00 00 00
```

## Still needs fixing
- TCP communication grouping sometimes works incorrectly in edge cases
- ICMP packet grouping fragment also in some cases doesnt work correctly