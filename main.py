from copy import deepcopy
from scapy.all import rdpcap
from scapy.compat import raw
import ruamel.yaml.scalarstring
import sys

pcap_name = "trace-26.pcap"

dictionaries = {
    "etherTypes": {},
    "sapTypes": {},
    "pidTypes": {},
    "ipProtocolTypes": {},
    "udpPortTypes": {},
    "tcpPortTypes": {},
}

source_constant = 12
protocol_constant = 24
length_constant = 28

frames_database = {"name": "PKS2022/23", "pcap_name": pcap_name, "packets": []}


def check_protocol_exists(protocol):
    if (
        protocol not in dictionaries["etherTypes"].values()
        and protocol not in dictionaries["ipProtocolTypes"].values()
        and protocol not in dictionaries["udpPortTypes"].values()
        and protocol not in dictionaries["tcpPortTypes"].values()
    ):
        return False
    else:
        return True


def load_dictionary(file_path, dictionary):
    file = open(file_path, "r")
    for line in file:
        splitLine = line.split(":")
        if len(splitLine) > 1:
            dictionary[splitLine[0]] = splitLine[1].strip()
    file.close()


def load_dictionaries():
    load_dictionary("Protocols/EtherTypes.txt", dictionaries["etherTypes"])
    load_dictionary("Protocols/SAP.txt", dictionaries["sapTypes"])
    load_dictionary("Protocols/PID.txt", dictionaries["pidTypes"])
    load_dictionary("Protocols/Protocols.txt", dictionaries["ipProtocolTypes"])
    load_dictionary("Protocols/UDPports.txt", dictionaries["udpPortTypes"])
    load_dictionary("Protocols/TCPports.txt", dictionaries["tcpPortTypes"])


load_dictionaries()


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


def find_max_sent_packets(ipv4_history):
    max = 0
    for node in ipv4_history:
        if ipv4_history[node]["number_of_sent_packets"] > max:
            max = ipv4_history[node]["number_of_sent_packets"]
    max_send_packets = []
    for node in ipv4_history:
        if ipv4_history[node]["number_of_sent_packets"] == max:
            max_send_packets.append(node)

    return max_send_packets


def modify_ethernet_object(
    packet,
    packet_length,
    packet_object,
    ipv4_history,
    filter="",
    filter_type="",
    offset=0,
):
    ip_offset = 52 + offset
    protocol_offset = 46 + offset
    port_offset = 68 + offset
    packet_object = packet_object
    is_filtering = filter != ""

    try:
        ether_type = f"{dictionaries['etherTypes'][str(packet_length)]}".strip()
        packet_object["ether_type"] = ether_type
    except:
        ether_type = packet_length
        print("Unknown ethertype")

    if ether_type == "IPv4":
        src_ip = f"{int(packet[ip_offset:ip_offset+2],base=16)}.{int(packet[ip_offset+2:ip_offset+4],base=16)}.{int(packet[ip_offset+4:ip_offset+6],base=16)}.{int(packet[ip_offset+6:ip_offset+8],base=16)}"
        dst_ip = f"{int(packet[ip_offset+8:ip_offset+10],base=16)}.{int(packet[ip_offset+10:ip_offset+12],base=16)}.{int(packet[ip_offset+12:ip_offset+14],base=16)}.{int(packet[ip_offset+14:ip_offset+16],base=16)}"
        protocol = f"{dictionaries['ipProtocolTypes'][str(packet[protocol_offset:protocol_offset+2])]}".strip()
        src_port = int(packet[port_offset : port_offset + 4], base=16)
        dst_port = int(packet[port_offset + 4 : port_offset + 8], base=16)

        if src_ip in ipv4_history:
            ipv4_history[src_ip]["number_of_sent_packets"] = (
                ipv4_history[src_ip]["number_of_sent_packets"] + 1
            )
        else:
            ipv4_history[src_ip] = {"number_of_sent_packets": 1}

        packet_object["protocol"] = protocol

        packet_object["src_ip"] = src_ip
        packet_object["dst_ip"] = dst_ip
        if src_port > 0 and dst_port > 0:
            packet_object["src_port"] = src_port
            packet_object["dst_port"] = dst_port

        if protocol == "TCP":
            dictType = "tcpPortTypes"
        elif protocol == "UDP":
            dictType = "udpPortTypes"

        try:
            app_protocol = f"{dictionaries[dictType][str(src_port)]}".strip()
            packet_object["app_protocol"] = app_protocol
        except:
            try:
                app_protocol = f"{dictionaries[dictType][str(dst_port)]}".strip()
                packet_object["app_protocol"] = app_protocol
            except:
                app_protocol = ""
    
    if ether_type == "ARP":
        arp_ip_offset = 56 + offset
        arp_dst_ip_offset = 76 + offset
        arpcode_offset = 40 + offset
        src_ip = f"{int(packet[arp_ip_offset:arp_ip_offset+2],base=16)}.{int(packet[arp_ip_offset+2:arp_ip_offset+4],base=16)}.{int(packet[arp_ip_offset+4:arp_ip_offset+6],base=16)}.{int(packet[arp_ip_offset+6:arp_ip_offset+8],base=16)}"
        dst_ip = f"{int(packet[arp_dst_ip_offset:arp_dst_ip_offset+2],base=16)}.{int(packet[arp_dst_ip_offset+2:arp_dst_ip_offset+4],base=16)}.{int(packet[arp_dst_ip_offset+4:arp_dst_ip_offset+6],base=16)}.{int(packet[arp_dst_ip_offset+6:arp_dst_ip_offset+8],base=16)}"
        arpcode = int(packet[arpcode_offset:arpcode_offset+4],base=16)
        packet_object["src_ip"] = src_ip
        packet_object["dst_ip"] = dst_ip
        if arpcode == 1:
            packet_object["arp_opcode"] = "REQUEST"
        else:
            packet_object["arp_opcode"] = "REPLY"



    if is_filtering and (filter_type == "TCP" or filter_type == "UDP"):
        property_to_filter = "app_protocol";
    elif is_filtering and filter_type == "Ether":
        property_to_filter = "ether_type"
    else:
        property_to_filter = "protocol"
    
    if is_filtering:
        try:
            if packet_object[property_to_filter] != filter:
                return None
        except:
            return None

    return packet_object


def modify_iee_llc(packet, packet_object, offset=0):
    dsap_offset = 28 + offset
    # dsap_num = packet[dsap_offset : dsap_offset + 2]
    ssap_num = packet[dsap_offset + 2 : dsap_offset + 4]

    try:
        ssap = f"{dictionaries['sapTypes'][ssap_num]}".strip()
    except:
        ssap = ssap_num
    packet_object["sap"] = ssap

    return packet_object


def modify_iee_llc_snap(packet, packet_object, offset=0):
    pid_offset = 40 + offset
    pid_num = packet[pid_offset : pid_offset + 4]
    try:
        pid = f"{dictionaries['pidTypes'][pid_num]}".strip()
    except:
        pid = pid_num

    packet_object["pid"] = pid

    return packet_object

def export_data_to_yaml(data, file_name):
    # YAML formatting and print
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.sort_keys = False
    yaml.explicit_start = True
    yaml.indent(sequence=4, offset=2)
    yaml_file_name = file_name
    with open(f"outputs/{yaml_file_name}.yaml", "w") as f:
        file = yaml.dump(data, f)


def filter_frames_arp(frames_database):
    return_frames = {
        "name": frames_database["name"],
        "pcap_name": frames_database["pcap_name"],
        "filter_name": "ARP",
        "complete_comms": [],
        "partial_comms": []
    }
    packet_range = range(len(frames_database["packets"]))
    i = 0
    not_added_packets = []
    while i < len(frames_database["packets"]):
        packet = frames_database["packets"][i]
        dst_ip = packet["dst_ip"]
        src_ip = packet["src_ip"]
        if packet["arp_opcode"] == "REQUEST":
            response_found = False
            for j in range(i,len(frames_database["packets"])):
                sub_packet = frames_database["packets"][j]
                if sub_packet["arp_opcode"] == "REPLY" and sub_packet["src_ip"] == dst_ip and sub_packet["dst_ip"] == src_ip:
                    
                    if sub_packet in not_added_packets:
                        not_added_packets.remove(sub_packet)

                    return_frames["complete_comms"].append({
                        "number_comm": len(return_frames["complete_comms"]) +1,
                        "src_comm": src_ip,
                        "dst_comm": dst_ip,
                        "packets": [deepcopy(packet),deepcopy(sub_packet)]
                    })
                    response_found = True
                    frames_database["packets"].remove(sub_packet)
                    break;
                elif sub_packet["arp_opcode"] == "REPLY":
                    if sub_packet not in not_added_packets:
                        not_added_packets.append(sub_packet)

            if not response_found:
                return_frames["partial_comms"].append({
                    "number_comm": len(return_frames["partial_comms"]) +1,
                    "packets": [deepcopy(packet)]
                })

        i = i+1


    for packet in not_added_packets:
            return_frames["partial_comms"].append({
                    "number_comm": len(return_frames["partial_comms"]) +1,
                    "packets": [deepcopy(packet)]
                })  
    
    #Corecct the ordering
    def sorting_func(comm):
        return comm["packets"][0]["frame_number"]
    #Correct only if reply packet has been appended to the end           
    if len(not_added_packets) > 0:                
        return_frames["partial_comms"].sort(key=sorting_func)
        for i in range(len(return_frames["partial_comms"])):
            return_frames["partial_comms"][i]["number_comm"] = i+1


    if len( return_frames["partial_comms"]) == 0:
        return_frames["partial_comms"] = None

    if len( return_frames["complete_comms"]) == 0:
        return_frames["complete_comms"] = None
   

    return return_frames



def analyze_frames(pcap_file=pcap_name, filter="", filter_type=""):
    pcap_name = pcap_file
    packets = rdpcap(f"Captures/{pcap_name}")
    ipv4_history = {}
    length = len(packets)
    frames_database = {"name": "PKS2022/23", "pcap_name": pcap_name, "packets": []}
    is_filtering = filter != ""

    for i in range(length):
        packet = raw(packets[i]).hex()

        # check if is ISL present
        isl_mac_test = f"{packet[0:2]}:{packet[2:4]}:{packet[4:6]}:{packet[6:8]}:{packet[8:10]}:{packet[10:12]}"
        if isl_mac_test == "01:00:0c:00:00:00" or isl_mac_test == "03:00:0c:00:00:00":
            frame_jump = 52
        else:
            frame_jump = 0

        packet_length = packet[24 + frame_jump : 24 + 4 + frame_jump]
        packet_type_length = packet[
            length_constant + frame_jump : length_constant + 4 + frame_jump
        ]

        dest_mac = f"{packet[0+frame_jump:2+frame_jump]}:{packet[2+frame_jump:4+frame_jump]}:{packet[4+frame_jump:6+frame_jump]}:{packet[6+frame_jump:8+frame_jump]}:{packet[8+frame_jump:10+frame_jump]}:{packet[10+frame_jump:12+frame_jump]}".upper()
        source_position = source_constant + frame_jump
        src_mac = f"{packet[source_position:source_position+2]}:{packet[source_position+2:source_position+4]}:{packet[source_position+4:source_position+6]}:{packet[source_position+6:source_position+8]}:{packet[source_position+8:source_position+10]}:{packet[source_position+10:source_position+12]}".upper()

        real_frame_length = int(len(packet) / 2)
        if real_frame_length < 60:
            len_frame_medium = 64
        else:
            len_frame_medium = real_frame_length + 4

        #Classify packet type
        if int(packet_length, base=16) > 1500:
            frame_type = "Ethernet II"
        elif packet_type_length == "aaaa":
            frame_type = "IEEE 802.3 LLC & SNAP"
        elif packet_type_length == "ffff":
            frame_type = "IEEE 802.3 RAW"
        else:
            frame_type = "IEEE 802.3 LLC"

        packet_object = {
            "frame_number": i + 1,
            "frame_type": frame_type,
            "len_frame_pcap": real_frame_length,
            "len_frame_medium": len_frame_medium,
            "dst_mac": dest_mac,
            "src_mac": src_mac,
        }

        if frame_type == "Ethernet II":
            packet_object = modify_ethernet_object(
                packet=packet,
                packet_length=packet_length,
                packet_object=packet_object,
                ipv4_history=ipv4_history,
                filter=filter,
                filter_type=filter_type,
                offset=frame_jump,
            )
        elif frame_type == "IEEE 802.3 LLC" and filter == "":
            packet_object = modify_iee_llc(
                packet=packet, packet_object=packet_object, offset=frame_jump
            )
        elif frame_type == "IEEE 802.3 LLC & SNAP" and filter == "":
            packet_object = modify_iee_llc_snap(
                packet=packet, packet_object=packet_object, offset=frame_jump
            )
        elif filter != "":
            packet_object = None

        #Only add packet if not null
        if packet_object != None:
            packet_object["hexa_frame"] = ruamel.yaml.scalarstring.LiteralScalarString(
                prettify_hex_data(packet)
            )
            frames_database["packets"].append(packet_object)


    #If filtering is present do not add statistics
    if not is_filtering:
        frames_database["ipv4_senders"] = []
        for node in ipv4_history:
            frames_database["ipv4_senders"].append(
                {
                    "node": node,
                    "number_of_sent_packets": ipv4_history[node]["number_of_sent_packets"],
                }
        )
        frames_database["max_send_packets_by"] = find_max_sent_packets(
            ipv4_history=ipv4_history
        )

    if not is_filtering:
        export_data_to_yaml(frames_database, pcap_name.strip(".pcap"))
    elif filter == "ARP":
        frames_database["filter_name"] = "ARP"
        frames_database = filter_frames_arp(frames_database)
        export_data_to_yaml(frames_database, pcap_name.strip(".pcap"))



# Argument start
if len(sys.argv) >= 3:
    filter = sys.argv[2]
    try:
        pcap = sys.argv[3]
    except:
        pcap = None
    print(filter)
    filter_type = "IP"
    if sys.argv[1] != "-p":
        print("Incorrect argument. Try -p")
        exit()

    if not check_protocol_exists(filter):
        print("Protocol doesnt exists")
        exit()

    for key in dictionaries:
        if filter in dictionaries[key].values():
            if key == "tcpPortTypes":
                filter_type = "TCP"
            elif key == "udpPortTypes":
                filter_type = "UDP"
            elif key == "etherTypes":
                filter_type = "Ether"
            break
    if pcap != None:
        print(pcap)
        analyze_frames(pcap_file=pcap,filter=filter, filter_type=filter_type)
    else:
        analyze_frames(filter=filter, filter_type=filter_type)
else:
    analyze_frames()
