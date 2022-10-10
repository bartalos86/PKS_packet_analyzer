from scapy.all import rdpcap
from scapy.compat import raw 
# from yaml import dump
import ruamel.yaml.scalarstring


pcap_name = "trace-27.pcap"
packets = rdpcap(f'Captures/{pcap_name}')
length  = len(packets)

etherTypes = {}
SapTypes = {}

source_constant = 12;
protocol_constant = 24;
length_constant = 28;

frames_database = {
    'name': "PKS2022/23",
    'pcap_name': pcap_name,
    'packets': []
}

def load_dictionaries():
    etherTypesF = open('Protocols/EtherTypes.txt', 'r')
    sapTypesF = open('Protocols/SAP.txt', 'r')
    for line in etherTypesF:
        splitLine = line.split(':')
        if len(splitLine) > 1:
            etherTypes[splitLine[0]] = splitLine[1]
    for line in sapTypesF:
        splitLine = line.split(':')
        if len(splitLine) > 1:
            SapTypes[splitLine[0]] = splitLine[1]


def prettify_hex_data(hex_packet):
    frame_dump = ""
    for i in range(len(hex_packet)):
        if (i % 32) == 0 and i != 0:
            frame_dump += '\n'
        elif i % 2 == 0 and i != 0:
            frame_dump += " "
        frame_dump += str(hex_packet[i].capitalize());
    
    frame_dump += '\n'
    return frame_dump;

def modify_ethernet_object(packet_length,packet_object):
    try:
        ether_type = f"{etherTypes[str(packet_length)]}".strip();
    except:
        ether_type = "Unknown"
    packet_object["ether_type"] = ether_type
    # addatt(packet_object, "ether_type",ether_type);

    return packet_object;
   
def modify_iee_llc(packet,packet_object):
    dsap_offset = 24;
    dsap_num = packet[dsap_offset:dsap_offset+2]
    ssap_num = packet[dsap_offset+2:dsap_offset+4]

    try:
        dsap = f"{SapTypes[dsap_num]}".strip()
    except:
        dsap = dsap_num

    try:
        ssap = f"{SapTypes[ssap_num]}".strip()
    except:
        ssap = ssap_num
    # packet_object["dsap"] = dsap
    # packet_object["sap"] = ssap

    return packet_object

load_dictionaries();


for i in range(length):
    packet = raw(packets[i]).hex()
    packet_data_length = packet[length_constant:length_constant+2];
    packet_length=packet[protocol_constant:protocol_constant+4];
    dest_mac = f"{packet[0:2]}:{packet[2:4]}:{packet[4:6]}:{packet[6:8]}:{packet[8:10]}:{packet[10:12]}"
    dest_src = f"{packet[source_constant:source_constant+2]}:{packet[source_constant+2:source_constant+4]}:{packet[source_constant+4:source_constant+6]}:{packet[source_constant+6:source_constant+8]}:{packet[source_constant+8:source_constant+10]}:{packet[source_constant+10:source_constant+12]}"
    
    if int(packet_length, base=16) >= 1500:
        frame_type = "Ethernet II"
    elif packet_length == 'aaaa':
        frame_type = "IEEE 802.3 SNAP"
    elif packet_length == 'ffff':
        frame_type = "IEEE 802.3 RAW"
    else:
        frame_type = "IEEE 802.3 LLC"

    real_frame_length = len(packet)
    if real_frame_length < 60:
        len_frame_medium = 64
    else:
        len_frame_medium = real_frame_length +4
    packet_object = {
        "frame_number": i,
        "frame_type": frame_type,
        "len_frame_pcap": real_frame_length,
        "len_frame_medium": len_frame_medium,
        "src_mac": dest_mac,
        "dst_mac": dest_src,
    }

    if frame_type == "Ethernet II":
       packet_object = modify_ethernet_object(packet_length=packet_length,packet_object=packet_object)
    elif frame_type == "IEEE 802.3 SNAP" or frame_type == "IEEE 802.3 LLC":
        packet_object = modify_iee_llc(packet=packet,packet_object=packet_object)

    packet_object["hexa_frame"] = ruamel.yaml.scalarstring.LiteralScalarString(prettify_hex_data(packet))
    if frame_type != "Ethernet II":
        frames_database["packets"].append(packet_object)
        
        
#YAML formatting and print
yaml = ruamel.yaml.YAML()
yaml.default_flow_style = False
yaml.sort_keys = False
with open("output.yaml", "w") as f:
    file = yaml.dump(frames_database,f)

