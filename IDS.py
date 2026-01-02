

# Import required libraries
import pyshark
from pyshark.capture.capture import TSharkCrashException

'''
TSharkCrashException  is a specific exception from the PyShark library, which is used for packet capturing and 
network traffic analysis in Python.This exception is raised when TShark, the underlying tool PyShark relies on 
for packet processing, crashes or fails during its execution.
'''

class IDS():

    def __init__(self,  config):
        self.config = config


    def _read_pcap(self, interface, IoCs):

        interface = interface
        packets = pyshark.LiveCapture(interface=interface)

        packets.sniff(timeout=0.01)

        # To read the Packets from the pcap stream
        packet_counter = 0

        for pcap in packets:
            print("Packet_Number: ", packet_counter)
            print(pcap)

            if packet_counter == 10:
                break

            packet_counter += 1
            has_transport = pcap.transport_layer is not None
            packet_time = float(pcap.sniff_timestamp)
            packet_dict = dict()
            highest_layer = pcap.highest_layer.upper()
            packet_dict["highest_layer"] = highest_layer
            if has_transport:
                packet_dict["transport_layer"] = pcap.transport_layer.upper()

            else:
                packet_dict["transport_layer"] = "NONE"
                packet_dict["src_port"] = -1
                packet_dict["dst_port"] = -1
                packet_dict["transport_flag"] = -1

            packet_dict["timestamp"] = int(packet_time)
            packet_dict["time"] = str(pcap.sniff_time)
            packet_dict["frame_len"] = int(pcap.length)
            packet_dict["data"] = ""

            for layer in pcap.layers:
                layer_name = layer.layer_name.upper()
                if 'ETH' == layer_name:
                    # print(layer.type)
                    packet_dict['mac_src'] = str(layer.dst)
                    packet_dict['mac_dst'] = str(layer.src)
                    packet_dict['eth_type'] = str(layer.type)

                if "IP" == layer_name or "IPV6" == layer_name:
                    # print(layer._all_fields)
                    packet_dict["src_ip"] = str(layer.src)
                    packet_dict["dst_ip"] = str(layer.dst)


                    if hasattr(layer, "geocountry"):
                        packet_dict["geo_country"] = str(layer.geocountry)
                    else:
                        packet_dict["geo_country"] = "Unknown"


                elif has_transport and layer_name == pcap.transport_layer:
                    packet_dict["src_port"] = int(layer.dstport)
                    packet_dict["dst_port"] = int(layer.srcport)
                    # To save the data in a database

            if "src_ip" not in packet_dict:
                continue


