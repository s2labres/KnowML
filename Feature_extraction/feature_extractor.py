from fe_constants import FEConstants, PacketFEIdx
from typing import List, Tuple, Union, Optional, Dict
import os
import logging
import pandas as pd
from pcap_reader import PcapReader
from tqdm import tqdm
from netstats import NetStats
from enums import TCPState
import argparse

import sys
sys.path.append('../')

from util import Util, DataBuffer

class FeatureExtractorChrollo: 
    _LOG_PATH = os.getcwd() + "/" + "feature_extractor.log"
    # LAMBDA = 1 # DECAY FACTOR
    IDLE_TIMEOUT = 5 # Timeout for connection less protocols
    ACTIVE_TIMEOUT = 60
    TIME_WINDOW = 300
    SPLIT_CHAR = chr(127) # 0x7F

    #  # Force time out for TCP connection.
    # Note this has higher precdence than RST and FIN flags.
    # If set to None then the timeout is not forced and connections length is UNBOUNDED until terminated through: 
    # * Graceful termination 
    # * Abrupt termination

    TCP_TIMEOUT = 3600

    def __init__(self, pcap_file_path: str, store_file_path: Dict=None)->None:

        if not self._file_exists(pcap_file_path):
            raise Exception(f"The pcap file: {pcap_file_path} does not exist.")
         
        self.pcap_file_path = pcap_file_path

        self.store_file_path = store_file_path

        Util.init_logging(self._LOG_PATH)

        self.packet_features = [attr.lower() for attr in PacketFEIdx.__dict__ if not callable(getattr(PacketFEIdx, attr)) and not attr.startswith("__")]
        self.tshark_cmd = self._init_extraction_cmd(pcap_file_path) # Initialize the extraction command for tshar

        self._pcap_reader = PcapReader(self.tshark_cmd, split_char=FeatureExtractorChrollo.SPLIT_CHAR)

        # Connection features are extracted by the following aggreagations
        # Src IP| SrcMAC| Src Port| Dst IP| Dst MAC| Dst Port| Protocol 
        # Dst IP| Dst MAC| Dst Port | Protocol
        self.channel_conversations = dict() # Store the channel conversations - Source MAC, Destination MAC, Source Port, Destination Port
        self.dst_mac_conversations = dict() # Store the conversations based on destination mac address and destination port
        self.packet_count = 0 # TODO for debugging purposes only
        logging.info(f"Intialization completed. Extracting features from the pcap file: {pcap_file_path}.")

        # Kitsune adoptation - Terminate connection AFTER return in the NEXT iteration
        self.terminate_last = None


# Initialization functions
    def _init_extraction_cmd(self, pcap_file_path: str)->List[str]:
        """
        Initialize the extraction command for tshark based on the packet features to be extracted.
        """
        fields = self._get_fields_cmd()
        return ["tshark", "-r", pcap_file_path,
                    "-T", "fields"] + fields + ["-E", f"separator={FeatureExtractorChrollo.SPLIT_CHAR}"] 
# Public functions, getters and setters
    @property
    def pcap_reader(self) -> PcapReader:
        if self._pcap_reader is None:
            self._pcap_reader = PcapReader(self.tshark_cmd)
        return self._pcap_reader
    
    def _get_fields_cmd(self)->str:
        """
        Get the tshark fields command for the features to be extracted.
        """
        fields = []

        for feature in self.packet_features:
            if isinstance(FEConstants.THARK_CMD_MAP[feature], list):
                for sub_feature in FEConstants.THARK_CMD_MAP[feature]:
                    fields.append("-e")
                    fields.append(sub_feature)
            else:
                fields.append("-e")
                fields.append(FEConstants.THARK_CMD_MAP[feature])

        return fields
        
    
    def extract(self, return_df: bool = False) -> Optional[pd.DataFrame]:
        """
        Extract features from the packet capture file(s) and store the features efficiently.
        
        :param return_df: Return the extracted features as a DataFrame. Default is False.
        """
        logging.info(f"Extracting features from the pcap file(s) using command: {self.tshark_cmd}")
        packets = self.pcap_reader
        logging.info("Starting to process the packets")
        
        processed_count = 0
        
        data_buffer = DataBuffer(self.store_file_path)
        
        column_names = FEConstants.EXRACTION_FE

        with open(self.store_file_path, 'w') as f:
            f.write(','.join(column_names) + '\n')
        
        try:
            for packet in tqdm(iter(packets), desc="Processing packets"):
                self.packet_count += 1
                
                if not packet:
                    raise Exception(f"Empty packet encountered at position {self.packet_count}.")
                    
                try:
                    packet = self._process_packet(packet)
                    channel_id, dst_id, terminated = self._register(packet)
                    
                    # Add both rows to buffer
                    data_buffer.add_row(self.channel_conversations[channel_id].info())
                    data_buffer.add_row(self.dst_mac_conversations[dst_id].info(True))
                    
                    if terminated:
                        self.dst_mac_conversations[dst_id].reduce(self.channel_conversations[channel_id])
                        self.channel_conversations.pop(channel_id)
                    
                    processed_count += 1
                        
                except Exception as e:
                    raise Exception(f"Error processing packet {self.packet_count}: {str(e)}")
                    
        except StopIteration:
            logging.info("Finished processing all packets.")
        except Exception as e:
            raise Exception(f"Unexpected error during packet processing: {str(e)}")
        finally:
            # Ensure all remaining data is written
            data_buffer.close()
        
        logging.info(f"Total packets read: {self.packet_count}")
        logging.info(f"Packets successfully processed: {processed_count}")
        
        if return_df:
            return pd.read_csv(self.store_file_path)
        
        return None


# Private functions, getters and setters

    def _register(self, packet: List[str])->Tuple[int, int, bool]: 
        """
        Helper function to register the new packet information.

        :param packet: The packet to register.
        :param to_bool: Convert the numerical set values such as number of source_mac in the dst_mac_conversation to num (size). Default is True.
        :param return_all: Return all the extraction features. Default is True.
        """
        channel_id, dst_id= self._get_conversations(packet)

        terminated, channel_id, dst_id = self._update(packet, channel_id, dst_id)

        return channel_id, dst_id, terminated
    

    def _update(self, packet: List[str], channel_id: str, dst_id: str)->Tuple[bool, int, int]:
        terminated = False

        if "tcp" in packet[PacketFEIdx.PROTOCOL_HIERARCHY]:
            terminated, channel_id, dst_id = self._update_state(packet, channel_id, dst_id)

        else: 
            last_ts = self.channel_conversations[channel_id].last_ts
            start_ts = self.channel_conversations[channel_id].start_ts
            if last_ts != NetStats.UNITIALIZED:
                # Check whether the Inter-arrival time has exceeded the timeout
                if packet[PacketFEIdx.TIMESTAMP] - last_ts > FeatureExtractorChrollo.IDLE_TIMEOUT or \
                    packet[PacketFEIdx.TIMESTAMP] - start_ts > FeatureExtractorChrollo.ACTIVE_TIMEOUT: 
                    channel_conversation = self.channel_conversations[channel_id]
                    self.dst_mac_conversations[dst_id].reduce(channel_conversation)
                    channel_conversation.clear(packet[PacketFEIdx.TIMESTAMP])
                    channel_conversation.last_ts = packet[PacketFEIdx.TIMESTAMP]

        self._update_statistics(packet, channel_id, dst_id)
        return terminated, channel_id, dst_id
    
    def _update_statistics(self, packet: List[str], channel_id: str, dst_id: str)->None:
        
        last_ts = self.channel_conversations[channel_id].last_ts
        current_ts = packet[PacketFEIdx.TIMESTAMP]
        increment = 0 if last_ts == NetStats.UNITIALIZED else current_ts - last_ts
        
        inbound_packet = self.channel_conversations[channel_id].inbound_packet_count
        outbound_packet = self.channel_conversations[channel_id].outbound_packet_count
        conn_ps = self.channel_conversations[channel_id].ssh_connection_ps
        self.channel_conversations[channel_id].update(packet)

        inbound_packet = self.channel_conversations[channel_id].inbound_packet_count - inbound_packet
        outbound_packet = self.channel_conversations[channel_id].outbound_packet_count - outbound_packet
        conn_ps = self.channel_conversations[channel_id].ssh_connection_ps - conn_ps
        self.dst_mac_conversations[dst_id].update(packet, increment, increment, inbound_packet, outbound_packet, conn_ps)
        
    def _get_connection_info(self, channel_id: str)->Tuple[str, str, str, str, str, str]:
        """
        Get the connection information from the channel id.

        :param channel_id: The channel id to get the connection information from.
        """
        channel_info = channel_id.split("-")
        src_ip = channel_info[0]
        src_mac = channel_info[1]
        src_port = channel_info[2]
        dst_ip = channel_info[3]
        dst_mac = channel_info[4]
        dst_port = channel_info[5]

        return src_mac, dst_mac, src_port, dst_port, src_ip, dst_ip


    def _update_state(self, packet: List[str], channel_id: str, dst_id: str)->Tuple[bool, int, int]:
        chanel_netstats = self.channel_conversations[channel_id]
        dst_netstats = self.dst_mac_conversations[dst_id]
    
        terminated = False

        if packet[PacketFEIdx.ACK_FLAG] == "True":
            if chanel_netstats.tcp_state == TCPState.NONE: 
                chanel_netstats.init_out_of_order = 1
            if chanel_netstats.tcp_state == TCPState.SYN_RECEIVED: 
                if packet[PacketFEIdx.ACK_NUMBER] == chanel_netstats.ex_ack_number:
                    init_out_of_order = chanel_netstats.init_out_of_order if chanel_netstats.init_out_of_order != NetStats.UNITIALIZED else 0
                    self._update_init_state(chanel_netstats, dst_netstats, init_out_of_order)
            elif chanel_netstats.tcp_state == TCPState.SYN_SENT and packet[PacketFEIdx.SEQUENCE_NUMBER] == chanel_netstats.ex_seq_num:
                self._update_init_state(chanel_netstats, dst_netstats, 1)
                
            elif packet[PacketFEIdx.SYN_FLAG] == "True" and (chanel_netstats.tcp_state ==  TCPState.NONE):
                
                channel_id, dst_id = self._get_forward_converstaion(packet)
                self.channel_conversations[channel_id].init_out_of_order = 1
                # Remove previous state value before adding new state

                if self.channel_conversations[channel_id].tcp_state != TCPState.NONE:
                    self.dst_mac_conversations[dst_id].tcp_state[self.channel_conversations[channel_id].tcp_state] -= 1

                self.channel_conversations[channel_id].tcp_state = TCPState.SYN_RECEIVED # Overwrite the previous state
                self.dst_mac_conversations[dst_id].tcp_state[TCPState.SYN_RECEIVED] += 1
                self.channel_conversations[channel_id].ex_ack_number = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1

                return terminated, channel_id, dst_id
            elif chanel_netstats.tcp_state == TCPState.TIME_WAIT and \
                chanel_netstats.ex_ack_number == packet[PacketFEIdx.ACK_NUMBER]: # Acknowledging the final ack

                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1

                chanel_netstats.tcp_state = TCPState.CLOSED

                dst_netstats.tcp_state[TCPState.CLOSED] += 1
                chanel_netstats.close_out_of_order = 0
                terminated = True

            elif (chanel_netstats.tcp_state == TCPState.FIN_WAIT_1 and  packet[PacketFEIdx.SEQUENCE_NUMBER] == chanel_netstats.ex_seq_num) or \
                (chanel_netstats.receiver == packet[PacketFEIdx.SOURCE_IP] and  chanel_netstats.ex_ack_number == packet[PacketFEIdx.SEQUENCE_NUMBER] and packet[PacketFEIdx.FIN_FLAG] != "True"): 

                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1
                chanel_netstats.tcp_state = TCPState.CLOSED

                dst_netstats.tcp_state[TCPState.CLOSED] += 1
                chanel_netstats.close_out_of_order = 1
                terminated = True
            elif packet[PacketFEIdx.FIN_FLAG] == "True" and chanel_netstats.fin_flag_count == 0 or chanel_netstats.total_packet_count == 0:
                chanel_netstats.close_out_of_order = 1
            
        if packet[PacketFEIdx.RST_FLAG] == "True" and packet[PacketFEIdx.FIN_FLAG] != "True":
            if chanel_netstats.tcp_state != TCPState.NONE:
                dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1
            dst_netstats.tcp_state[TCPState.CLOSED] += 1
            terminated = True
            chanel_netstats.tcp_state = TCPState.CLOSED
        elif packet[PacketFEIdx.SYN_FLAG] == "True":
            if chanel_netstats.tcp_state == TCPState.NONE or \
            (chanel_netstats.tcp_state == TCPState.SYN_RECEIVED and packet[PacketFEIdx.ACK_NUMBER] =="") or \
            chanel_netstats.ex_seq_num == NetStats.UNITIALIZED:

                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1

                chanel_netstats.tcp_state = TCPState.SYN_SENT

                dst_netstats.tcp_state[TCPState.SYN_SENT] += 1
                chanel_netstats.ex_seq_num = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1
            else: 

                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1
                
                chanel_netstats.tcp_state = TCPState.SYN_RECEIVED

                dst_netstats.tcp_state[TCPState.SYN_RECEIVED] += 1

                chanel_netstats.ex_ack_number = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1
        elif packet[PacketFEIdx.FIN_FLAG] == "True" and packet[PacketFEIdx.RST_FLAG] != "True":
                # Fin was send from the receiver
            if chanel_netstats.receiver != NetStats.UNITIALIZED and \
                packet[PacketFEIdx.SOURCE_IP] == chanel_netstats.receiver and packet[PacketFEIdx.SEQUENCE_NUMBER] < chanel_netstats.ex_ack_number:
                # FIN-ACK arrived before the FIN from the initiator i.e. FIN 


                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1

                chanel_netstats.tcp_state = TCPState.FIN_WAIT_1

                dst_netstats.tcp_state[TCPState.FIN_WAIT_1] += 1
                chanel_netstats.ex_seq_num = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1
                chanel_netstats.close_out_of_order = 1
            elif chanel_netstats.receiver == NetStats.UNITIALIZED: # Initialize start of the termination if FIN is received first , enter FIN_WAIT_1
                chanel_netstats.receiver = packet[PacketFEIdx.DESTINATION_IP]

                if chanel_netstats.tcp_state != TCPState.NONE: # If TCP is in other state then remove it
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1

                chanel_netstats.tcp_state = TCPState.FIN_WAIT_1

                dst_netstats.tcp_state[TCPState.FIN_WAIT_1] += 1
                chanel_netstats.ex_seq_num = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1 # This should be acknowledged by the receiver (next sender)
                chanel_netstats.ex_ack_number = packet[PacketFEIdx.ACK_NUMBER] # This next seequence number of receiver (next sender)
            elif chanel_netstats.tcp_state == TCPState.FIN_WAIT_1 and chanel_netstats.receiver == packet[PacketFEIdx.SOURCE_IP]: 

                if chanel_netstats.tcp_state != TCPState.NONE:
                    dst_netstats.tcp_state[chanel_netstats.tcp_state] -= 1

                dst_netstats.tcp_state[TCPState.TIME_WAIT] += 1
                chanel_netstats.ex_ack_number = packet[PacketFEIdx.SEQUENCE_NUMBER] + 1 # Expecting the final ack from non reciver 
                chanel_netstats.tcp_state = TCPState.TIME_WAIT


        # Check for repeated FIN flags, ack for FIN might be lost due to network congestion
        flag_count = chanel_netstats.fin_flag_count
        
        # Note: statistics are not updated yet
        flag_count += 1 if packet[PacketFEIdx.FIN_FLAG] == "True" else 0

        # Force clear immedietely BEFORE update if: 
        # - TCP_TIMEOUT is reached 
        # - Fin flags more than 4
        # After TCP State is stats are updates, force terminate if TCP_TIMEOUT is set 
        time_elapsed = packet[PacketFEIdx.TIMESTAMP] - chanel_netstats.start_ts
        if (self.TCP_TIMEOUT is not None and time_elapsed > self.TCP_TIMEOUT) or flag_count > 4: 
            terminated = True
            chanel_netstats.clear(packet[PacketFEIdx.TIMESTAMP])
            chanel_netstats.last_ts = packet[PacketFEIdx.TIMESTAMP]

        # # After TCP State is stats are updates, force terminate if TCP_TIMEOUT is set 
        # time_elapsed = packet[PacketFEIdx.TIMESTAMP] - chanel_netstats.start_ts
        # if self.TCP_TIMEOUT is not None and time_elapsed > self.TCP_TIMEOUT:
        #     terminated = True
        #     chanel_netstats.clear(packet[PacketFEIdx.TIMESTAMP])
        #     chanel_netstats.last_ts = packet[PacketFEIdx.TIMESTAMP]
        
        # # Check for repeated FIN flags, ack for FIN might be lost due to network congestion
        # flag_count = chanel_netstats.fin_flag_count
        
        # # Note: statistics are not updated yet
        # flag_count += 1 if packet[PacketFEIdx.FIN_FLAG] == "True" else 0

        # # Force termininate if more than 4 FIN flags are received
        # if flag_count > 4:
        #     terminated = True

        return terminated, channel_id, dst_id


    def _get_forward_converstaion(self, packet): 
        src_ip, dst_ip, dst_mac, src_mac, dst_port, src_port = packet[PacketFEIdx.SOURCE_IP], packet[PacketFEIdx.DESTINATION_IP], packet[PacketFEIdx.DESTINATION_MAC], packet[PacketFEIdx.SOURCE_MAC], packet[PacketFEIdx.DESTINATION_PORT], packet[PacketFEIdx.SOURCE_PORT]
        channel_id = self._get_reverse_id(src_mac, src_port, dst_mac, dst_port, src_ip, dst_ip)
        dst_id = self._get_dst_id_reverse(src_mac, src_port, src_ip)

        if not channel_id in self.channel_conversations:
            channel_conversation = NetStats(src_mac, src_port, dst_mac, dst_port, src_ip, dst_ip, packet[PacketFEIdx.TIMESTAMP], packet[PacketFEIdx.PROTOCOL])
            self.channel_conversations[channel_id] = channel_conversation
    
        if not dst_id in self.dst_mac_conversations:
            tcp_state = self._get_status_values()
            dst_mac_conversation = NetStats("", "", dst_mac, dst_port, "", dst_ip, "", "")
            dst_mac_conversation.tcp_state = tcp_state
            self.dst_mac_conversations[dst_id] = dst_mac_conversation

        return channel_id, dst_id

    def _update_init_state(self, channel_netstats: NetStats,dst_netstats: NetStats,  out_of_order: int)->None:
        """
        out_of_order: 0: In order, 1: Out of order, -1: Unknown/Uninitialized
        """
        channel_netstats.init_out_of_order = out_of_order
        if channel_netstats.tcp_state != NetStats.UNITIALIZED:
             dst_netstats.tcp_state[channel_netstats.tcp_state] -=1 # Remove the previous state and add the new state

        channel_netstats.tcp_state = TCPState.ESTABLISHED
        dst_netstats.tcp_state[TCPState.ESTABLISHED] += 1
    
    def _process_protocol(self, protocol: str)->str:
        """
        Remove the version number from the protocol name. e.g. TLSv1.2 -> TLS and change SSL to TLS
        Assuming that protocol is in the lower case
        """
    
        if protocol.startswith(('tls', 'ssl')):
            return "tls" 
        if protocol == "0x0007" or protocol == "0x0006":
            return "ecatf"
        elif protocol == "http/json" or protocol == "http/xml": 
            return "http"
        elif protocol == "classic-stun":
            return "classicstun"
        elif protocol == "tc-nv":
            return "tc_nv"
        elif protocol == "? knxnet/ip": 
            return "kip"
        elif protocol == "sshv2":
            return "ssh"
        else:
            return protocol


    def _get_id(self, src_mac: str, src_port: str, dst_mac: str, dst_port: str, src_ip: str, dst_ip: str)->str:
        return f"{src_ip}-{src_mac}-{src_port}-{dst_ip}-{dst_mac}-{dst_port}"
    
    def _get_reverse_id(self, src_mac: str, src_port: str, dst_mac: str, dst_port: str, src_ip: str, dst_ip: str)->str:
        return f"{dst_ip}-{dst_mac}-{dst_port}-{src_ip}-{src_mac}-{src_port}"
    
    def _get_dst_id(self, dst_mac: str, dst_port: str, dst_ip: str)->str:
        return f"{dst_ip}-{dst_mac}-{dst_port}"
    
    def _get_dst_id_reverse(self, src_mac: str, src_port: str, src_ip: str)->str:
        return f"{src_ip}-{src_mac}-{src_port}"
    
    def _get_status_values(self): 
        # return {member.value: 0 for member in TCPState}
        values = [value for value in vars(TCPState).values() if isinstance(value, int)]
        max_value = max(values)
        return {i: 0 for i in range(max_value + 1)}
    
    def _get_conversations(self, packet: List[str])->Tuple[str, str]:
        """
        Get conversations based on the packet information.

        :param packet: The packet to get the conversations from.
        :return: The channel id and the destination mac id.
        """
        src_mac = packet[PacketFEIdx.SOURCE_MAC]
        src_port = packet[PacketFEIdx.SOURCE_PORT]
        dst_mac = packet[PacketFEIdx.DESTINATION_MAC]
        dst_port = packet[PacketFEIdx.DESTINATION_PORT]
        timestamp = packet[PacketFEIdx.TIMESTAMP]
        protocol = packet[PacketFEIdx.PROTOCOL] 
        src_ip = packet[PacketFEIdx.SOURCE_IP]
        dst_ip = packet[PacketFEIdx.DESTINATION_IP]

        channel_id = self._get_id(src_mac, src_port, dst_mac, dst_port, src_ip, dst_ip)
        channel_id_reverse = self._get_reverse_id(src_mac, src_port, dst_mac, dst_port, src_ip, dst_ip)
        dst_mac_proto_id = self._get_dst_id(dst_mac, dst_port, dst_ip)
        dst_mac_proto_id_reverse = self._get_dst_id_reverse(src_mac, src_port, src_ip)
        duplex = False

        # Create new conversation if it does not exist
        if channel_id in self.channel_conversations:
            channel_conversation = self.channel_conversations[channel_id]
        elif channel_id_reverse in self.channel_conversations:
            channel_conversation = self.channel_conversations[channel_id_reverse]
            channel_id = channel_id_reverse
            dst_mac_proto_id = dst_mac_proto_id_reverse
            duplex = True
        else:
            channel_conversation = NetStats(src_mac, src_port, dst_mac, dst_port, src_ip, dst_ip, timestamp, protocol)
            self.channel_conversations[channel_id] = channel_conversation
        
        if dst_mac_proto_id in self.dst_mac_conversations:
            dst_mac_conversation = self.dst_mac_conversations[dst_mac_proto_id]
        else: 
            
            tcp_state = self._get_status_values()
            
            dst_mac_conversation = NetStats("", "", dst_mac, dst_port, "", dst_ip, "", "")
            dst_mac_conversation.tcp_state = tcp_state

            self.dst_mac_conversations[dst_mac_proto_id] = dst_mac_conversation

        # Added for debugging purposes only!
        if  duplex and not dst_mac_proto_id in self.dst_mac_conversations: 
            raise Exception(f"Error: Duplex conversation found, but no dst_mac_proto_id found for {dst_mac_proto_id}. Bug in the code.")
        
        return channel_id, dst_mac_proto_id
    

    def _process_packet(self, packet: List[str])->List[str]:
        """
        Merge the protocol values for the packets and convert the numerical values to float.
        
        Example:
        tcp.srcport = "8080", udp.srcport = "" -> srcport = "8080"
        """
        # Merge source port
        packet[PacketFEIdx.SOURCE_PORT] += packet.pop(PacketFEIdx.SOURCE_PORT + 1)

        # Merge destination port
        packet[PacketFEIdx.SOURCE_PORT + 1] += packet.pop(PacketFEIdx.SOURCE_PORT + 2)

        try: 
            packet[PacketFEIdx.TIMESTAMP]= float(packet[PacketFEIdx.TIMESTAMP])
        except ValueError:
            # packet size  miight contain a string e.g, '1665163138.(1000000000 nanosec'
            packet[PacketFEIdx.TIMESTAMP] = float(packet[PacketFEIdx.TIMESTAMP].split(".")[0])
        packet[PacketFEIdx.FRAME_LEN] = float(packet[PacketFEIdx.FRAME_LEN])
        packet[PacketFEIdx.TCP_WINDOW_SIZE] = int(packet[PacketFEIdx.TCP_WINDOW_SIZE]) if packet[PacketFEIdx.TCP_WINDOW_SIZE] != "" else 0

        if "," in packet[PacketFEIdx.ICMP_TYPE]:
            packet[PacketFEIdx.ICMP_TYPE] = packet[PacketFEIdx.ICMP_TYPE][0]
        packet[PacketFEIdx.ICMP_TYPE] = int(packet[PacketFEIdx.ICMP_TYPE]) if packet[PacketFEIdx.ICMP_TYPE] != "" else 0
        packet[PacketFEIdx.HTTP_FRAME_TYPE] = int(packet[PacketFEIdx.HTTP_FRAME_TYPE]) if packet[PacketFEIdx.HTTP_FRAME_TYPE] != "" else -1 # Note: frame type cannot be 0, 0 stands for DATA frame
        packet[PacketFEIdx.SSH_ENCRYPTED] = int(packet[PacketFEIdx.SSH_ENCRYPTED], 16) if packet[PacketFEIdx.SSH_ENCRYPTED] != "" else 0 # Convert to int from hex
        packet[PacketFEIdx.SEQUENCE_NUMBER] = int(packet[PacketFEIdx.SEQUENCE_NUMBER]) if packet[PacketFEIdx.SEQUENCE_NUMBER] != "" else -1
        packet[PacketFEIdx.ACK_NUMBER] = int(packet[PacketFEIdx.ACK_NUMBER]) if packet[PacketFEIdx.ACK_NUMBER] != "" else -1
        packet[PacketFEIdx.TCP_PAYLOAD] = int(packet[PacketFEIdx.TCP_PAYLOAD]) if packet[PacketFEIdx.TCP_PAYLOAD] != "" else 0

        # Note: it is possible that multiple HTTP messages are present in a single TCP segment hence we sum the values
        if "," in packet[PacketFEIdx.HTTP_HEADER_SIZE]:
            strin_val = packet[PacketFEIdx.HTTP_HEADER_SIZE]
            packet[PacketFEIdx.HTTP_HEADER_SIZE] = sum(int(val.strip()) for val in strin_val.split(','))
        elif packet[PacketFEIdx.HTTP_HEADER_SIZE] != "":
            packet[PacketFEIdx.HTTP_HEADER_SIZE] = int(packet[PacketFEIdx.HTTP_HEADER_SIZE])
        else:
            packet[PacketFEIdx.HTTP_HEADER_SIZE] = 0

        if "," in packet[PacketFEIdx.HTTP_PAYLOAD]: 
            strin_val = packet[PacketFEIdx.HTTP_PAYLOAD]
            packet[PacketFEIdx.HTTP_PAYLOAD] = sum(float(val.strip()) for val in strin_val.split(','))
        elif packet[PacketFEIdx.HTTP_PAYLOAD] != "":
            packet[PacketFEIdx.HTTP_PAYLOAD] = float(packet[PacketFEIdx.HTTP_PAYLOAD])
        else:
            packet[PacketFEIdx.HTTP_PAYLOAD] = 0

        packet[PacketFEIdx.HTTP2_FRAME_SIZE] = int(packet[PacketFEIdx.HTTP2_FRAME_SIZE]) if packet[PacketFEIdx.HTTP2_FRAME_SIZE] != "" else 0

        if "," in packet[PacketFEIdx.ICMP_CODE]:
            packet[PacketFEIdx.ICMP_CODE] = packet[PacketFEIdx.ICMP_CODE][0]

        packet[PacketFEIdx.ICMP_CODE] = int(packet[PacketFEIdx.ICMP_CODE]) if packet[PacketFEIdx.ICMP_CODE] != "" else -1

        # Process encapulated packets, assuming the last value the original encapsulated packet e.g. ICMP - Time-to-live exceeded," encapsulates the UDP packet whose ttl is 1
        if ","  in packet[PacketFEIdx.TTL]: 
            packet[PacketFEIdx.TTL] = int(packet[PacketFEIdx.TTL].split(",")[-1])
        else:
            packet[PacketFEIdx.TTL] = int(packet[PacketFEIdx.TTL]) if packet[PacketFEIdx.TTL] != "" else 0

        self._normalize_flags(packet)

        packet[PacketFEIdx.TCP_PAYLOAD_SIZE] = int(packet[PacketFEIdx.TCP_PAYLOAD_SIZE]) if packet[PacketFEIdx.TCP_PAYLOAD_SIZE] != "" else 0

        if ","  in  packet[PacketFEIdx.SSH_MESSAGE_CODE]:
            # Multiple messages are sent in the same packet
            packet[PacketFEIdx.SSH_MESSAGE_CODE] = [int(value) for value in packet[PacketFEIdx.SSH_MESSAGE_CODE].split(",")]
        elif packet[PacketFEIdx.SSH_MESSAGE_CODE] != "":
            packet[PacketFEIdx.SSH_MESSAGE_CODE] = int(packet[PacketFEIdx.SSH_MESSAGE_CODE])

        return packet
    
    def _normalize_flags(self, packet: List[str])->None:
        """
        Normalize the flag values to boolean values.

        Note: This is necessary as different operation systems might represent the flags differently.
        """

        packet[PacketFEIdx.FIN_FLAG] = self._normalize_value(packet[PacketFEIdx.FIN_FLAG])
        packet[PacketFEIdx.SYN_FLAG] = self._normalize_value(packet[PacketFEIdx.SYN_FLAG])
        packet[PacketFEIdx.RST_FLAG] = self._normalize_value(packet[PacketFEIdx.RST_FLAG])
        packet[PacketFEIdx.PUSH_FLAG] = self._normalize_value(packet[PacketFEIdx.PUSH_FLAG])
        packet[PacketFEIdx.ACK_FLAG] = self._normalize_value(packet[PacketFEIdx.ACK_FLAG])
    
    def _normalize_value(self, value)->str:
        """
        Normalize the value to boolean values.
        """
        return  "True" if value in ['True', '1'] else "False"

    def _file_exists(self, file_path: str)->bool:
        """
        Check if the file exists.
        """
        return os.path.exists(file_path)
   

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="PCAP file path")
    parser.add_argument("--store", required=True, help="Store path")
    args = parser.parse_args()
    
    fe = FeatureExtractorChrollo(args.input, args.store)
    fe.extract()

if __name__ == "__main__":
    main()