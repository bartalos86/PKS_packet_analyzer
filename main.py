from scapy.all import rdpcap
from scapy.compat import raw 
from yaml import dump

pcap_name = "trace-27.pcap"
packets = rdpcap(f'Captures/{pcap_name}')
length  = len(packets)

etherTypes = {}
SapTypes = {}

source_constant = 8;
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
        if (i % 32) == 0:
            frame_dump += '\n'
        elif i % 2 == 0 and i != 0:
            frame_dump += " "
        frame_dump += str(hex_packet[i].capitalize());
    return frame_dump;

def modify_ethernet_object(packet_length,packet_object):
    try:
        ether_type = f"{etherTypes[str(packet_length)]}".strip();
    except:
        ether_type = "Unknown"
    packet_object["ether_type"] = ether_type
    # addatt(packet_object, "ether_type",ether_type);

    return packet_object;
   
def modify_iee_snap(packet,packet_object):
    dsap_offset = 24;
    dsap_num = packet[dsap_offset:dsap_offset+2]
    ssap_num = packet[dsap_offset+2:dsap_offset+4]

    try:
        dsap = f"{SapTypes[dsap_num]}".strip()
    except:
        dsap = "Unknown"

    try:
        ssap = f"{SapTypes[ssap_num]}".strip()
    except:
        ssap = "Unknown"
    packet_object["dsap"] = dsap
    packet_object["ssap"] = ssap

    return packet_object

load_dictionaries();


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

    packet_object = {
        "frame_number": i,
        "frame_type": frame_type,
        "len_frame": packet_data_length,
        "dest_mac": dest_mac,
        "dest_src": dest_src,
    }

    if frame_type == "Ethernet II":
       packet_object = modify_ethernet_object(packet_length=packet_length,packet_object=packet_object)
    elif frame_type == "IEEE 802.3 SNAP":
        packet_object = modify_iee_snap(packet=packet,packet_object=packet_object)

    packet_object["frame_dump"] = prettify_hex_data(packet)
    frames_database["packets"].append(packet_object)
        
        

yaml = dump(frames_database,line_break='\n',indent=1,sort_keys=False)
print(yaml)
