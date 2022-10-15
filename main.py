from scapy.all import rdpcap
from scapy.compat import raw
import ruamel.yaml.scalarstring

pcap_name = "trace-26.pcap"
etherTypes = {}
SapTypes = {}
pidTypes = {}

source_constant = 12
protocol_constant = 24
length_constant = 28

frames_database = {"name": "PKS2022/23", "pcap_name": pcap_name, "packets": []}


def load_dictionaries():
    etherTypesF = open("Protocols/EtherTypes.txt", "r")
    sapTypesF = open("Protocols/SAP.txt", "r")
    pidTypesF = open("Protocols/PID.txt", "r")
    for line in etherTypesF:
        splitLine = line.split(":")
        if len(splitLine) > 1:
            etherTypes[splitLine[0]] = splitLine[1]
    for line in sapTypesF:
        splitLine = line.split(":")
        if len(splitLine) > 1:
            SapTypes[splitLine[0]] = splitLine[1]
    for line in pidTypesF:
        splitLine = line.split(":")
        if len(splitLine) > 1:
            pidTypes[splitLine[0]] = splitLine[1]


def prettify_hex_data(hex_packet):
    frame_dump = ""
    for i in range(len(hex_packet)):
        if (i % 32) == 0 and i != 0:
            frame_dump += "\n"
        elif i % 2 == 0 and i != 0:
            frame_dump += " "
        frame_dump += str(hex_packet[i].capitalize())

    frame_dump += "\n"
    return frame_dump


def modify_ethernet_object(packet_length, packet_object):
    try:
        ether_type = f"{etherTypes[str(packet_length)]}".strip()
    except:
        ether_type = "Unknown"
    # packet_object["ether_type"] = ether_type
    return packet_object


def modify_iee_llc(packet, packet_object, offset = 0):
    dsap_offset = 28 + offset
    # dsap_num = packet[dsap_offset : dsap_offset + 2]
    ssap_num = packet[dsap_offset + 2 : dsap_offset + 4]

    try:
        ssap = f"{SapTypes[ssap_num]}".strip()
    except:
        ssap = ssap_num
    packet_object["sap"] = ssap

    return packet_object

def modify_iee_llc_snap(packet, packet_object, offset = 0):
    pid_offset = 40 + offset
    pid_num = packet[pid_offset:pid_offset+4]
    try:
        pid = f"{pidTypes[pid_num]}".strip()
    except:
        pid = pid_num;
        
    packet_object["pid"] = pid;

    return packet_object;


load_dictionaries()

def analyze_frames(pcap_file = pcap_name):
    pcap_name = pcap_file
    packets = rdpcap(f"Captures/{pcap_name}")
    length = len(packets)
    frames_database = {"name": "PKS2022/23", "pcap_name": pcap_name, "packets": []}


    for i in range(length):
        packet = raw(packets[i]).hex()

        #check if is ISL present
        isl_mac_test = f"{packet[0:2]}:{packet[2:4]}:{packet[4:6]}:{packet[6:8]}:{packet[8:10]}:{packet[10:12]}"
        if isl_mac_test == "01:00:0c:00:00:00" or isl_mac_test == "03:00:0c:00:00:00":
            frame_jump = 52
        else:
            frame_jump = 0

        packet_length = packet[24 + frame_jump: 24 + 4 + frame_jump]
        packet_type_length = packet[length_constant + frame_jump : length_constant + 4 + frame_jump]

        dest_mac = f"{packet[0+frame_jump:2+frame_jump]}:{packet[2+frame_jump:4+frame_jump]}:{packet[4+frame_jump:6+frame_jump]}:{packet[6+frame_jump:8+frame_jump]}:{packet[8+frame_jump:10+frame_jump]}:{packet[10+frame_jump:12+frame_jump]}".upper()
        source_position = source_constant + frame_jump;
        src_mac = f"{packet[source_position:source_position+2]}:{packet[source_position+2:source_position+4]}:{packet[source_position+4:source_position+6]}:{packet[source_position+6:source_position+8]}:{packet[source_position+8:source_position+10]}:{packet[source_position+10:source_position+12]}".upper()

        real_frame_length = int(len(packet) / 2)
        if real_frame_length < 60:
            len_frame_medium = 64
        else:
            len_frame_medium = real_frame_length + 4

        if int(packet_length, base=16) >= 1500:
            frame_type = "Ethernet II"
        elif packet_type_length == "aaaa":
            frame_type = "IEEE 802.3 LLC & SNAP"
        elif packet_type_length == "ffff":
            frame_type = "IEEE 802.3 RAW"
        else:
            frame_type = "IEEE 802.3 LLC"

        packet_object = {
            "frame_number": i+1,
            "frame_type": frame_type,
            "len_frame_pcap": real_frame_length,
            "len_frame_medium": len_frame_medium,
            "dst_mac": dest_mac,
            "src_mac": src_mac,
        }

        if frame_type == "Ethernet II":
            packet_object = modify_ethernet_object(
                packet_length=packet_length, packet_object=packet_object
            )
        elif frame_type == "IEEE 802.3 LLC":
            packet_object = modify_iee_llc(packet=packet, packet_object=packet_object, offset = frame_jump)
        elif frame_type == "IEEE 802.3 LLC & SNAP":
           packet_object = modify_iee_llc_snap(packet=packet, packet_object=packet_object, offset = frame_jump)

        packet_object["hexa_frame"] = ruamel.yaml.scalarstring.LiteralScalarString(
            prettify_hex_data(packet)
        )

        frames_database["packets"].append(packet_object)

    # YAML formatting and print
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.sort_keys = False
    yaml_file_name = pcap_name.strip(".pcap");
    with open(f"outputs/{yaml_file_name}.yaml", "w") as f:
        file = yaml.dump(frames_database, f)

analyze_frames()
