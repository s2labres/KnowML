
from typing import List, Union, Set, Dict
from fe_constants import PacketFEIdx, FEConstants
from collections import defaultdict
import numpy as np
from enums import TCPState
import re

class NetStats:     
    UNITIALIZED = -np.inf
    IDLE_THRESHOLD = 120 
    def __init__(self, src_mac: Union[str, Set[str]], src_port : str, 
               dst_mac : str, dst_port :str, src_ip: Union[str, Set[str]], dst_ip: str,
               timestamp: float, protocol: Union[str, Set[str]]) ->None:
        """
        Initialize the NetStats class.

        :param src_mac: The source mac address.
        :param src_port: The source port.
        :param dst_mac: The destination mac address.
        :param dst_port: The destination port.
        :param timestamp: The timestamp of first packet.
        """
        self.attributes = FEConstants.EXRACTION_FE

        # Initialize identifier features
        self._init_values()
        self.src_mac = src_mac
        self.src_port = src_port
        self.dst_mac = dst_mac
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.start_ts = timestamp
        self.last_ts = timestamp
        self.protocol = protocol 
        self.last_ts = NetStats.UNITIALIZED
        self.receiver = NetStats.UNITIALIZED
        self.tcp_state = TCPState.NONE

        self.min_ttl = NetStats.UNITIALIZED
        self.max_ttl = NetStats.UNITIALIZED

        self.max_tcp_payload_size = NetStats.UNITIALIZED
        self.min_tcp_payload_size = NetStats.UNITIALIZED


    def _init_iat_values(self)->None:
        """
        Initialize the IAT values.
        """
        self.iat_time = 0
        self.iat_time_mean = 0
        self.iat_time_std = 0
        self.iat_time_ssr = 0

    def info(self, is_dst:bool=False)->List:
        """
        Return the netstats information in a list by value.
        """

        # Pre-allocate the list
        values = [None] * len(self.attributes)
        
        # Use direct indexing instead of append
        for i, attr in enumerate(self.attributes):
            if is_dst and attr == "tcp_state":
                values[i] = self.tcp_state.copy() # Copy the tcp_state to return copy
            else: 
                values[i] = getattr(self, attr)
        
        return values

    def info_kitsune(self, dst_conversation: bool=False)->List: 
        """
        Return the netstats information in a list by value for Kitsune.

        Note: Non numerical and NONE evaluation features are omitted.
        """

        drop_columns = ['src_mac', 'protocol', 
                        'num_connection_per_domain', 'http_resource_request_count',
                        "src_port","dst_mac", "src_ip", "dst_ip", "dst_port", "protocol",  
                        "ex_ack_number", "ex_seq_num",  "last_ts", "start_ts", "receiver",  'last_request_ts','last_response_ts']
        
        dst_nestat_drop_cols = ["init_out_of_order", "close_out_of_order","min_ttl", "max_ttl",  "max_window_size", "min_window_size"
                        "request_interaval", "request_interal_mean", "response_interval", "response_interval_mean", "tcp_state", "max_tcp_payload_size", "min_tcp_payload_size"
                        ]
        
        
        values = []
        attribute_names = [] # TODO: REmove for debuggine only

        for attr in self.attributes:
            if attr in drop_columns or (dst_conversation and attr in dst_nestat_drop_cols and attr != "tcp_state"):
                continue
            if attr not in FEConstants.TCP_ATTCACK_FE: # TODO: Hard coded fix remove for generalization
                continue
            value = getattr(self, attr)

            if not dst_conversation and attr == "concurrent_connections": # Drop the concurrent connections for channel conversation
                continue

            if dst_conversation and attr == "tcp_state":
                values += value.values()
                attribute_names.extend(list(value.keys()))
            else:
                values.append(value)
                attribute_names.append(attr)
        return values
    
    def preprocess_values(self, values: List)->List:
        """
        Preprocess the values for the Kitsune model.
        """
        return values

    def update(self, packet: List[str], duration: float=None, 
               iat_time: float=None, inbound_packet_count: int=None, output_packet_count: int=None, conn_ps :int=None)->None:
        """
        Update the netstats with the new packet information.

        :param packet: The packet information.
        :param duration: The duration of the connection. Default is None. Used for calculating aggregated dst conversations.
        :param iat_time: The inter arrival time. Default is None. Used for calculating aggregated dst conversations.
        """
        current_ts = packet[PacketFEIdx.TIMESTAMP]
        packet_size = packet[PacketFEIdx.FRAME_LEN]
        packet[PacketFEIdx.PROTOCOL] = packet[PacketFEIdx.PROTOCOL].lower()

        self.total_packet_count  = self.total_packet_count + 1

        old_duration = self.duration
        self.duration = current_ts - self.start_ts if duration is None else self.duration + duration

        self._update_2D_stats(packet, inbound_packet_count, output_packet_count)
        self._update_size_features(packet_size)
        protocol = packet[PacketFEIdx.PROTOCOL].lower()
        # Note: No ICMP here is added because ICMP packet might responded as part of attempt to estabilish TCP connction
        # A packet such as ICMP Type 3 Destination Unreachable might be replied with TCP in protocol hierarchy
        if "tcp" in packet[PacketFEIdx.PROTOCOL_HIERARCHY] and protocol != "icmp": 
            self._update_flags(packet)
        self._update_ttl_values(packet[PacketFEIdx.TTL])  
        self._update_window_size(packet[PacketFEIdx.TCP_WINDOW_SIZE])
        self._update_http_frame_count(packet[PacketFEIdx.HTTP_FRAME_TYPE])

        if  packet[PacketFEIdx.PROTOCOL] in ["ssh","sshv2"]:
            self.ssh_packet_count += 1
            self._update_ssh_payload(packet[PacketFEIdx.TCP_PAYLOAD_SIZE])

        if packet[PacketFEIdx.IP_PROTOCOL] == "6": # IP conveys TCP data
        
            more_fragment = 1 if packet[PacketFEIdx.IP_MORE_FRAGMENT] == "True" else 0
            offset = int(packet[PacketFEIdx.IP_FRAG_OFFSET])
            if more_fragment == 1 or offset > 0:
                self.tcp_fragmented_packet_count += 1
           
        self._update_ssh_values(packet[PacketFEIdx.SSH_MESSAGE_CODE], packet[PacketFEIdx.TIMESTAMP], conn_ps, packet[PacketFEIdx.SOURCE_IP])
        
        self._update_retransmission_values(packet[PacketFEIdx.RETRANSMISSION])
        self._update_performance_stats(packet[PacketFEIdx.LOST_SEGMENT])
        self._update_tcp_payload(packet[PacketFEIdx.TCP_PAYLOAD])
        self._update_malfoded_vals(packet)

        self.icmp_packet_count += 1 if packet[PacketFEIdx.PROTOCOL] == "icmp" else 0


        self.http_packet_count += 1  if "http" in packet[PacketFEIdx.PROTOCOL] or "http" in packet[PacketFEIdx.PROTOCOL_HIERARCHY] else 0


        if packet[PacketFEIdx.HTTP1_AUTH] != "" or packet[PacketFEIdx.HTTP2_AUTH] != "":
            self.http_auth_count += 1

        self._update_cookie_features(len(packet[PacketFEIdx.HTTP_COOKIE]))  
        self._update_http_status_code(packet[PacketFEIdx.HTTP_STATUS_CODE])
        self._update_http_request_count(packet[PacketFEIdx.HTTP_REQUEST_METHOD])
        self._update_http2_stats(packet[PacketFEIdx.HTTP2_FRAME_TYPE], packet[PacketFEIdx.HTTP2_FRAME_SIZE])
        if packet[PacketFEIdx.HTTP_PAYLOAD] > 0:
            self._update_http_payload(packet[PacketFEIdx.HTTP_PAYLOAD])
            
            self._update_http_header_size(packet[PacketFEIdx.HTTP_HEADER_SIZE])
        
        if self.win_start_ts != 0 and current_ts - self.win_start_ts >= 5:
            self.win_http_pks = 0
            self.win_start_ts = current_ts

        if "http" in packet[PacketFEIdx.PROTOCOL] or "http" in packet[PacketFEIdx.PROTOCOL_HIERARCHY]: 
            if self.win_start_ts == 0: 
                self.win_start_ts = current_ts

            self.win_http_pks += 1 

        if self.win_http_pks > 0 and  self.win_start_ts != current_ts: 
            self.http_connection_p5s = self.win_http_pks / (current_ts - self.win_start_ts)

        
        if self.duration > 0: 
            if old_duration != self.duration: # Avoid aggregating time values for single packet connection
                self._update_time_features(current_ts, iat_time)
        else:
            self._init_iat_values()
        
        
        self.keep_alive_count += 1 if packet[PacketFEIdx.TCP_KEEP_ALIVE] != "" else 0
        self.invalid_checksums_count += (1 if packet[PacketFEIdx.PROTOCOL_HIERARCHY] == "tcp,malformed" else 0)
        self.ping_request_count += 1 if packet[PacketFEIdx.ICMP_TYPE] == 8 else 0

        self.icmp_error_count += 1 if packet[PacketFEIdx.ICMP_CODE] >=0 and packet[PacketFEIdx.ICMP_CODE] <= 15 else 0 # Ref: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

  

        self.connection_count += 1 if packet[PacketFEIdx.SYN_FLAG] == "True" and self.dst_mac == packet[PacketFEIdx.DESTINATION_MAC] else 0 # Number of attemptes to open a new connection
        self.http_auth_count += 1 if packet[PacketFEIdx.HTTP_AUTHORIZATION] != "" else 0
        
        if self.last_ts != NetStats.UNITIALIZED and packet[PacketFEIdx.TIMESTAMP] - self.last_ts > NetStats.IDLE_THRESHOLD:
            self.idle_connections += 1
        self.last_ts = current_ts

    def _update_malfoded_vals(self, packet: List[str]):
            if "http" in packet[PacketFEIdx.PROTOCOL_HIERARCHY]:

                if self._contains_crlf(packet[PacketFEIdx.HTTP_USER_AGENT]):
                    self.malfolded_user_agent_count += 1
                if self._contains_crlf(packet[PacketFEIdx.HTTP_ACCEPT_ENCODING]) or self._is_invalid_accept_encoding(packet[PacketFEIdx.HTTP_ACCEPT_ENCODING]):
                    self.malfolded_accept_encoding_count += 1
                if self._contains_crlf(packet[PacketFEIdx.HTTP_ACCEPT_LANGUAGE]) or (packet[PacketFEIdx.HTTP_ACCEPT_LANGUAGE] != "" and self._is_invalid_accept_language(packet[PacketFEIdx.HTTP_ACCEPT_LANGUAGE])):
                    self.malfolded_accept_language_count += 1
                if packet[PacketFEIdx.HTTP_BAD_HEADER] != "":
                    self.bad_http_header_count += 1

    def _is_invalid_accept_language(self, value: str) -> bool:

        single_lang_pattern = r'^[a-zA-Z]{2,3}(-[a-zA-Z]{2,4})?(?:;q=(?:1|0(?:\.[0-9])?))?\Z'

        if ',' in value:
            lang_tags = [tag.strip() for tag in value.split(',')]
            return not all(re.match(single_lang_pattern, tag) for tag in lang_tags)
        
        return not re.match(single_lang_pattern, value)
    

    def _is_invalid_accept_encoding(self, accept_encoding: str)->bool:
        """
        Validates Accept-Encoding header value. Handles q-values and multiple encodings.
        :return False if valid, True otherwise.
        """
        if accept_encoding == "":
            return False

        valid_encodings = {'gzip', 'deflate', 'br', 'identity', '*', 'sdch', 'xpress'}
        encodings = [enc.strip() for enc in accept_encoding.split(',')]
        
        for encoding in encodings:

            parts = [p.strip() for p in encoding.split(';')]
            

            base_encoding = parts[0].lower()
            if base_encoding not in valid_encodings:
                return True

            if len(parts) > 1:
                qvalue_part = parts[1]
                if not qvalue_part.startswith('q='):
                    return True
                try:
                    q_value = float(qvalue_part[2:])
                    if q_value < 0 or q_value > 1:
                        return True
                except ValueError:
                    return True
        
        return False

    def _update_http2_stats(self, frame_type: str, frame_size: int)->None:
        # Ref: https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml
        if frame_type == "0": 
            self.http_data_frame_count += 1
        elif frame_type == "3":
            self.http_rst_stream_count += 1
        elif frame_type == "7":
            self.http_goaway_count += 1

        if frame_size > 0:
            self.http_frame_size += frame_size
            self.http_frame_size_mean = self.http_frame_size / self.http_packet_count
            self.http_frame_size_ssr += (frame_size - self.http_frame_size_mean) ** 2
            self.http_frame_size_std = (self.http_frame_size_ssr / self.total_packet_count) ** 0.5

    def reduce(self, netstats: "NetStats", remove_src_mac: bool=True)->None:
        """
        Remove netstat values from the current netstats for aggregated dst conversations

        Note: ! Assumes that only connection-orineted connection are reduced.
        """
        
        self.total_packet_count -= netstats.total_packet_count
        self.duration -= netstats.duration
         
        self._reduce_2D_stats(netstats.inbound_packet_count, netstats.outbound_packet_count)
        self._reduce_packet_size(netstats.packet_size, netstats.packet_size_ssr)
        self._reduce_flags(netstats)
        self._reduce_ttl_values(netstats.ttl, netstats.ttl_packets, netstats.ttl_ssr)
        self._reduce_time_features(netstats.iat_time, netstats.iat_time_ssr)
        self._reduce_cookie_features(netstats.http_cookie_size, netstats.http_cookie_ssr)
        self._reduce_http_status_code(netstats)
        self._reduce_http_request_count(netstats)
        self._reduce_http_payload(netstats.http_payload_size, netstats.http_payload_ssr)
        self._reduce_http_header_size(netstats.http_header_size, netstats.http_header_ssr)
        self._reduce_window_size(netstats.tcp_window_size, netstats.tcp_window_size_ssr, netstats.zero_window_count)
        # self._reduce_ssh_values(netstats.ssh_packet_size, netstats.ssh_packet_size_ssr, netstats.ssh_packet_count)
        self._reduce_ssh_values(netstats)

        self.icmp_packet_count -= netstats.icmp_packet_count
        self.tcp_fragmented_packet_count -= netstats.tcp_fragmented_packet_count

        self.keep_alive_count -= netstats.keep_alive_count
        self.invalid_checksums_count -= netstats.invalid_checksums_count
        self.ping_request_count -= netstats.ping_request_count
        self.http_header_count -= netstats.http_header_count
        self.http_rst_stream_count -= netstats.http_rst_stream_count
        self.http_auth_count -= netstats.http_auth_count
        self._reduce_http_2_stats(netstats)
        self._reduce_malfoded_vals(netstats)

        self.connection_count -= netstats.connection_count
        self.http_auth_count -= netstats.http_auth_count

        # Reduce netstat values
        if netstats.tcp_state != NetStats.UNITIALIZED and netstats.tcp_state != TCPState.NONE:
            self.tcp_state[netstats.tcp_state] -= 1

        self._reduce_reteransmission_values(netstats.retransmission_packets)
        self._reduce_performance_stats(netstats.packet_loss_count)
        self.idle_connections -= netstats.idle_connections

    def _reduce_malfoded_vals(self, netstats: "NetStats"):
        self.malfolded_user_agent_count -= netstats.malfolded_user_agent_count
        self.malfolded_accept_encoding_count -= netstats.malfolded_accept_encoding_count
        self.malfolded_accept_language_count -= netstats.malfolded_accept_language_count
        self.bad_http_header_count -= netstats.bad_http_header_count
        
    def _reduce_http_2_stats(self, netstats: "NetStats")->None:
        self.http_data_frame_count -= netstats.http_data_frame_count
        self.http_rst_stream_count -= netstats.http_rst_stream_count

        if netstats.http_frame_size > 0:
            old_mean = self.http_frame_size_mean

            self.http_frame_size -= netstats.http_frame_size
            self.http_frame_size_mean = self.http_frame_size / self.http
            self.http_frame_size_ssr -= ((self.http_frame_size_mean - old_mean) ** 2 + netstats.http_frame_size_ssr)
            self.http_frame_size_ssr = abs(self.http_frame_size_ssr) # Avoid negative values
            self.http_frame_size_std = (self.http_frame_size_ssr / self.total_packet_count) ** 0.5

    def clear(self, timestamp: float)->None:
        """
        Clear the netstats values and reinitialize.
        """
        self._init_values()

        self.start_ts = timestamp
        self.last_ts = timestamp

        self.ex_ack_number = NetStats.UNITIALIZED
        self.ex_seq_num = NetStats.UNITIALIZED
        self.init_out_of_order =  NetStats.UNITIALIZED
        self.close_out_of_order = NetStats.UNITIALIZED
        self.receiver = NetStats.UNITIALIZED
        self.tcp_state = TCPState.NONE

        self.min_ttl = NetStats.UNITIALIZED
        self.max_ttl = NetStats.UNITIALIZED



# PRIVATE METHODS and PROPERTIES
    def _init_values(self)->None:
        for attr in self.attributes:
            if attr not in ["src_mac", "src_ip", "dst_ip", 
                            "protocol", "src_port", "dst_port", "dst_mac"]:
                setattr(self, attr, 0.0)
        
        self.ex_ack_number = NetStats.UNITIALIZED
        self.ex_seq_num = NetStats.UNITIALIZED

        self.init_out_of_order =  NetStats.UNITIALIZED
        self.close_out_of_order = NetStats.UNITIALIZED
        

    def _update_2D_stats(self, packet: List[str], inbound_packet_count: int, output_packet_count: int)->None:
        last_request_ts = self.last_request_ts
        last_response_ts = self.last_response_ts

        if inbound_packet_count == None and output_packet_count == None:
            if packet[PacketFEIdx.DESTINATION_MAC] == self.dst_mac:
                self.inbound_packet_count += 1
                self.last_request_ts = packet[PacketFEIdx.TIMESTAMP]
            else:
                self.outbound_packet_count += 1
                self.last_response_ts = packet[PacketFEIdx.TIMESTAMP]
        else:
            self.inbound_packet_count += inbound_packet_count
            self.outbound_packet_count += output_packet_count
        
        if self.duration > 0:
            self.inbound_packet_rate = self.inbound_packet_count / self.duration
            self.outbound_packet_rate = self.outbound_packet_count / self.duration
            self.transmission_rate = self.total_packet_count / self.duration
        else:
            self.inbound_packet_rate = 0
            self.outbound_packet_rate = 0
            self.transmission_rate = 0

        if self.inbound_packet_count > 1:
            self.request_interaval += (packet[PacketFEIdx.TIMESTAMP] - last_request_ts) 
            self.request_interval = self.request_interaval / (self.inbound_packet_count - 1)
        if self.outbound_packet_count >1:
            self.response_interval += (packet[PacketFEIdx.TIMESTAMP] - last_response_ts) 
            self.response_interval_mean = self.response_interval / self.outbound_packet_count
    
    def _update_size_features(self, packet_size: float):
        self.packet_size += packet_size
        self.packet_size_mean = self.packet_size / self.total_packet_count
        self.packet_size_ssr += (packet_size - self.packet_size_mean) ** 2
        self.packet_size_std = (self.packet_size_ssr / self.total_packet_count) ** 0.5

    def _update_cookie_features(self, cookie_size: float):
        self.http_cookie_size += cookie_size
        if self.http_cookie_size > 0:
            self.http_cookie_mean = self.http_cookie_size / (self.http_packet_count if self.http_packet_count > 0 else self.http_cookie_size )
            self.http_cookie_ssr += (cookie_size - self.http_cookie_mean) ** 2
            self.http_cookie_std = (self.http_cookie_ssr / self.total_packet_count) ** 0.5
    
    def _update_ttl_values(self, ttl: float)->None:
        self.ttl += ttl # Cummulative sum of ttl values
        self.ttl_packets += 1
        self.ttl_mean = self.ttl / self.ttl_packets
        self.ttl_ssr += (ttl - self.ttl_mean) ** 2
        self.ttl_std = (self.ttl_ssr / self.ttl_packets) ** 0.5

        if self.min_ttl == NetStats.UNITIALIZED or ttl < self.min_ttl:
            self.min_ttl = ttl
        
        if self.max_ttl == NetStats.UNITIALIZED or ttl > self.max_ttl:
            self.max_ttl = ttl
    
    def _reduce_ttl_values(self, ttl: float, ttl_packets: int,
                            ttl_ssr: float)->None:
        self.ttl_packets -= ttl_packets

        if self.ttl_packets > 0:
            old_mean = self.ttl_mean

            self.ttl -= ttl
            self.ttl_mean = self.ttl / self.ttl_packets
            self.ttl_ssr -= ((self.ttl_mean - old_mean) ** 2 + ttl_ssr)
            self.ttl_ssr = abs(self.ttl_ssr) # Avoid negative values
            self.ttl_std = (self.ttl_ssr / self.ttl_packets) ** 0.5

        else:
            self._init_ttl_values()

    def _contains_crlf(self, value: str)->bool:
        crlf_patterns = ['\r\n', '%0d%0a', '%0D%0A', '\\r\\n']
        return any([pattern in value for pattern in crlf_patterns])

    def _update_retransmission_values(self, retransmission: str)->None:

        if retransmission != "": 
            self.retransmission_packets += 1
            if self.duration > 0:
                self.retransmission_rate = self.retransmission_packets /self.duration  
            else: 
                self.retransmission_rate = 0

    def _reduce_reteransmission_values(self, retransmission_packets: int)->None:

        self.retransmission_packets -= retransmission_packets
        if self.duration > 0:
            self.retransmission_rate = self.retransmission_packets / self.duration
        else:
            self.retransmission_rate = 0

        
    def _init_ttl_values(self)->None:
        """
        Initialize the ttl values.
        """
        self.ttl = 0
        self.ttl_mean = 0
        self.ttl_std = 0
        self.ttl_ssr = 0
        self.ttl_packets = 0
        
    def _reduce_packet_size(self, packet_size: float, packet_size_ssr: float)->None:
        """
        Remove the packet size from the netstats.

        Note: SSR and STD are approximated values.
        """
        if self.total_packet_count > 0:
            old_mean = self.packet_size_mean # Store the old mean for the SSR calculation
            
            self.packet_size -= packet_size
            self.packet_size_mean = self.packet_size / self.total_packet_count
            self.packet_size_ssr -= ((self.packet_size_mean - old_mean) ** 2 + packet_size_ssr) # Aggregated SSR - correction for reduction - SSR of the reduced values
            self.packet_size_ssr = abs(self.packet_size_ssr) # Avoid negative values
            self.packet_size_std = (self.packet_size_ssr / self.total_packet_count) ** 0.5
        else: 
            self._init_size_values()
    
    def _reduce_cookie_features(self, cookie_size: float, cookie_ssr: float)->None:
        """
        Reduce the cookie features from the netstats.
        """
        if self.http_cookie_size > 0 and self.total_packet_count > 0:
            old_mean = self.http_cookie_mean

            self.http_cookie_size -= cookie_size
            self.http_cookie_mean = self.http_cookie_size / self.total_packet_count
            self.http_cookie_ssr -= ((self.http_cookie_mean - old_mean) ** 2 + cookie_ssr)
            self.http_cookie_ssr = abs(self.http_cookie_ssr) # Avoid negative values
    
    def _init_size_values(self)->None:
        self.packet_size = 0
        self.packet_size_mean = 0
        self.packet_size_std = 0
        self.packet_size_ssr = 0

    def _update_time_features(self, current_ts: float, iat_time: float=None)->None:
        """
        Update the iat time from netstats iat values.
        
        current_ts: The current timestamp.
        iat_time: The inter arrival time. Default is None. Used for calculating aggregated dst conversations.
        """
        if self.last_ts != NetStats.UNITIALIZED or iat_time is not None:
            iat_time = current_ts - self.last_ts if iat_time is None else iat_time
            iat_packets = self.total_packet_count - 1
            self.iat_time += iat_time
            if iat_packets > 0:
                self.iat_time_mean = self.iat_time / iat_packets
                self.iat_time_ssr += (iat_time - self.iat_time_mean) ** 2
                self.iat_time_std = (self.iat_time_ssr / iat_packets) ** 0.5
    
    def _reduce_2D_stats(self, inbound_packet_cnt: int, outbound_packet_cnt: int):
        """
        Reduce the 2D stats from the netstats.
        """
        self.inbound_packet_count -= inbound_packet_cnt
        self.outbound_packet_count -= outbound_packet_cnt
        
        if self.duration > 0:
            self.inbound_packet_rate = self.inbound_packet_count / self.duration
            self.outbound_packet_rate = self.outbound_packet_count / self.duration
            self.transmission_rate = self.total_packet_count / self.duration
        else:
            self.inbound_packet_rate = 0
            self.outbound_packet_rate = 0
            self.transmission_rate = 0

    def _reduce_time_features(self, iat_time: float, iat_time_ssr: float)->None:
        """
        Reduce the iat time from netstats iat values.

        Note: SSR and STD are approximated values.
        """
        if self.duration > 0:
            iat_packets = self.total_packet_count - 1
            old_iat_mean = self.iat_time_mean

            self.iat_time -= iat_time
            self.iat_time_mean = self.iat_time / iat_packets
            self.iat_time_ssr -= ((self.iat_time_mean  - old_iat_mean) ** 2 + iat_time_ssr)
            self.iat_time_ssr = abs(self.iat_time_ssr) # Avoid negative values
            self.iat_time_std = (self.iat_time_ssr / iat_packets) ** 0.5
        else:
            self._init_iat_values()

    def _get_domain_name(self, packet: List[str])->str:
        """
        Get the domain name from the packet.
        """
        domain_name = None

        if packet[PacketFEIdx.HTTP_DOMAIN] != "":
            domain_name = packet[PacketFEIdx.HTTP_DOMAIN]
        elif packet[PacketFEIdx.HTTPS_DOMAIN] != "":
            domain_name = packet[PacketFEIdx.HTTPS_DOMAIN]
        elif packet[PacketFEIdx.DNS_DOMAIN_NAME] != "":
            domain_name = packet[PacketFEIdx.DNS_DOMAIN_NAME]
        
        return domain_name
    
    def _update_flags(self, packet: List[str]):
        """
        Update the flag counts.
        """
        timestamp = packet[PacketFEIdx.TIMESTAMP]
        if packet[PacketFEIdx.SYN_FLAG] == "True": 
            self.syn_flag_count += 1

            if (self.win_con_attempt > 0 and timestamp - self.win_start_ts > 1) or self.win_con_attempt == 0:
                self.win_con_attempt = timestamp
                self.connection_est_attempts_ps = 0
            
            self.connection_est_attempts_ps += 1
            
        self.rst_flag_count += 1 if packet[PacketFEIdx.RST_FLAG] == "True" else 0
        self.fin_flag_count += 1 if packet[PacketFEIdx.FIN_FLAG] == "True" else 0   

        if packet[PacketFEIdx.FIN_FLAG] == "True" or packet[PacketFEIdx.RST_FLAG] == "True":
            if self.win_ter_attempt > 0 and timestamp - self.win_start_ts > 1 or self.win_ter_attempt == 0:
                self.win_ter_attempt = timestamp
                self.connection_ter_attempts_ps = 0
            
            self.connection_ter_attempts_ps += 1

        self.ack_flag_count += 1 if packet[PacketFEIdx.ACK_FLAG] == "True" else 0
        self.push_flag_count += 1 if packet[PacketFEIdx.PUSH_FLAG] == "True" else 0
        self.urg_flag_count += 1 if packet[PacketFEIdx.URG_FLAG] == "True" else 0

        if packet[PacketFEIdx.SYN_FLAG] != "True" and packet[PacketFEIdx.ACK_FLAG] != "True" and packet[PacketFEIdx.RST_FLAG] != "True" and packet[PacketFEIdx.FIN_FLAG] != "True" and packet[PacketFEIdx.PUSH_FLAG] != "True" and packet[PacketFEIdx.URG_FLAG] != "True":
            self.null_flags_count += 1

        if packet[PacketFEIdx.FIN_FLAG] == "True" and packet[PacketFEIdx.PUSH_FLAG] == "True" and packet[PacketFEIdx.URG_FLAG] == "True":
            self.xmas_packets_count += 1

    def _reduce_flags(self, netstats: "NetStats"):
        """
        Reduce the flag counts.
        """
        self.syn_flag_count -= netstats.syn_flag_count
        self.ack_flag_count -= netstats.ack_flag_count
        self.rst_flag_count -= netstats.rst_flag_count
        self.fin_flag_count -= netstats.fin_flag_count
        self.push_flag_count -= netstats.push_flag_count
        self.xmas_packets_count -= netstats.xmas_packets_count
        self.urg_flag_count -= netstats.urg_flag_count
        self.null_flags_count -= netstats.null_flags_count
    
    def _get_avrg_domain_connection(self):
        """
        Get the average number of connections per domain.
        """
        domains = len(self.num_connection_per_domain)
        return 0 if domains == 0 else sum(self.num_connection_per_domain.values()) / domains
    
    def _reduce_connection_per_domain(self, dict: defaultdict) ->None:
        """
        Reduce the number of connections per domain.
        """
        for key in dict:
            if key in self.num_connection_per_domain:
                self.num_connection_per_domain[key] -= dict[key]
                if self.num_connection_per_domain[key] == 0:
                    del self.num_connection_per_domain[key]

    def _update_http_status_code(self, status_code: str)->None:
        """
        Update the http status code.
        """
        if "2" in status_code:
            self.http_success_count += 1
        elif "4" in status_code:
            self.http_client_side_error_count += 1
        elif "5" in status_code:
            self.http_server_side_error_count += 1
    
    def _reduce_http_status_code(self, netstats: "NetStats")->None:

        self.http_success_count -= netstats.http_success_count
        self.http_client_side_error_count -= netstats.http_client_side_error_count
        self.http_server_side_error_count -= netstats.http_server_side_error_count
    
    def _update_http_request_count(self, request_method: str)->None:
        """
        Update the http request count.
        """
        if "," in request_method:
            request_method = request_method.split(",")[0]
        if request_method == "GET":
            self.http_get_count += 1
        elif request_method == "POST":
            self.http_post_count += 1
        elif request_method == "PUT":
            self.http_put_count += 1
        elif request_method == "DELETE":
            self.http_delete_count += 1
        elif request_method == "HEAD":
            self.http_head_count += 1
        elif request_method == "PATCH":
            self.http_patch_count += 1
        elif request_method == "OPTIONS":
            self.http_options_count += 1
        elif request_method == "TRACE":
            self.http_trace_count += 1

    
    def _reduce_http_request_count(self, netstats: "NetStats")->None:
        self.http_get_count -= netstats.http_get_count
        self.http_post_count -= netstats.http_post_count
        self.http_put_count -= netstats.http_put_count
        self.http_delete_count -= netstats.http_delete_count
        self.http_head_count -= netstats.http_head_count
        self.http_patch_count -= netstats.http_patch_count
        self.http_options_count -= netstats.http_options_count
        self.http_trace_count -= netstats.http_trace_count

    def _update_http_payload(self, payload: float)->None:
        """
        Update the http payload.
        """
        self.http_payload_size += payload
        self.http_payload_mean = self.http_payload_size / (self.http_packet_count if self.http_packet_count > 0 else self.http_payload_size)
        self.http_payload_ssr += (payload - self.http_payload_mean) ** 2
        self.http_payload_std = (self.http_payload_ssr / self.total_packet_count) ** 0.5

    def _reduce_http_payload(self, payload: float, payload_ssr: float)->None:
        """
        Reduce the http payload.
        """
        if self.http_payload_size > 0 and self.total_packet_count > 0:
            old_mean = self.http_payload_mean

            self.http_payload_size -= payload
            self.http_payload_mean = self.http_payload_size / self.total_packet_count
            self.http_payload_ssr -= ((self.http_payload_mean - old_mean) ** 2 + payload_ssr)
            self.http_payload_ssr = abs(self.http_payload_ssr)

    def _update_http_header_size(self, header_size: float)->None:
        """
        Update the http header size.
        """
        self.http_header_size += header_size
        self.http_header_mean = self.http_header_size / self.http_packet_count
        self.http_header_ssr += (header_size - self.http_header_mean) ** 2
        self.http_header_std = (self.http_header_ssr / self.total_packet_count) ** 0.5

    def _reduce_http_header_size(self, header_size: float, header_ssr: float)->None:
        """
        Reduce the http header size.
        """
        if self.http_header_size > 0 and self.total_packet_count > 0:
            old_mean = self.http_header_mean

            self.http_header_size -= header_size
            self.http_header_mean = self.http_header_size / self.total_packet_count
            self.http_header_ssr -= ((self.http_header_mean - old_mean) ** 2 + header_ssr)
            self.http_header_ssr = abs(self.http_header_ssr)

    def _update_window_size(self, window_size: str)->None:
        """
        Update the tcp window size.
        Note: Assume that window_size is not nan.
        """
        if window_size != "":
            window_size = int(window_size)

            self.tcp_window_size += window_size
            self.tcp_window_size_mean = self.tcp_window_size / self.total_packet_count
            self.tcp_window_size_ssr += (window_size - self.tcp_window_size_mean) ** 2
            self.tcp_window_size_std = (self.tcp_window_size_ssr / self.total_packet_count) ** 0.5

            if self.max_window_size == NetStats.UNITIALIZED or window_size > self.max_window_size:
                self.max_window_size = window_size
            if self.min_window_size == NetStats.UNITIALIZED or window_size < self.min_window_size:
                self.min_window_size

            if window_size == 0:
                self.zero_window_count += 1
            
            if self.duration > 0:
                self.zero_window_frequency = self.zero_window_count / self.duration
                

    def _reduce_window_size(self, window_size: float, window_size_ssr: float, zero_window_count: int)->None:
        """
        Reduce the tcp window size.
        """
        if self.tcp_window_size > 0 and self.total_packet_count > 0:
            old_mean = self.tcp_window_size_mean

            self.tcp_window_size -= window_size
            self.tcp_window_size_mean = self.tcp_window_size / self.total_packet_count
            self.tcp_window_size_ssr -= ((self.tcp_window_size_mean - old_mean) ** 2 + window_size_ssr)
            self.tcp_window_size_ssr = abs(self.tcp_window_size_ssr)
            self.tcp_window_size_std = (self.tcp_window_size_ssr / self.total_packet_count) ** 0.5         


            # Overwrite the max and min queue size not the average
            if self.max_window_size == window_size:
                self.max_window_size = self.tcp_window_size_mean
            if self.min_window_size == window_size:
                self.min_window_size = self.tcp_window_size_mean

            self.zero_window_count -= zero_window_count
            if self.duration > 0:
                self.zero_window_frequency = self.zero_window_count / self.duration

    def _update_http_frame_count(self, frame_type: int)->None:
        """
        Update HTTP2 frame count.
        """
        if frame_type == 1: 
            self.http_header_count +=1
        elif frame_type == 3:
            self.http_rst_stream_count += 1

    
    def _update_ssh_values(self, code: str, packet_ts: float, conn_ps: int, src_ip: str)->None:
        """
        Update the ssh values
        """
        if code != "":
            if isinstance(code, list):
                for c in code:
                    self._upadte_ssh_codes(c, packet_ts, conn_ps, src_ip)
            else:
                self._upadte_ssh_codes(code, packet_ts, conn_ps, src_ip)

    def _update_ssh_payload(self, payload: float)->None:
        """
        Update the ssh payload size note that this includes SSH overhead and header size.
        """
        self.ssh_packet_size += payload
        if self.ssh_packet_count > 0:
            self.ssh_packet_size += payload
            self.ssh_packet_size_mean = self.ssh_packet_size / self.ssh_packet_count if self.ssh_packet_size > 0 else self.ssh_packet_size
            self.ssh_packet_size_ssr += (payload - self.ssh_packet_size_mean) ** 2
            self.ssh_packet_size_std = (self.ssh_packet_size_ssr / self.ssh_packet_count) ** 0.5
    
    # Revert
    def _upadte_ssh_codes(self, code: str, packets_ts: float, conn_ps: int, src_ip: str)->None:
        if code == 20:              
            self.ssh_init_key_exchange_count += 1              
            if conn_ps is not None:

                if self.ssh_connection_ps > 0 and packets_ts - self.win_start_ts_ssh > 1:
                    self.ssh_connection_ps = 0
                    self.win_start_ts_ssh = packets_ts

                self.ssh_connection_ps += conn_ps  
                if self.win_start_ts_ssh == 0:
                    self.win_start_ts_ssh = packets_ts
            else:   
                if self.start_sec == 0 or packets_ts - self.start_sec > 1 and self.src_ip == src_ip:         
                    self.start_sec = packets_ts                 
                    self.ssh_connection_ps = 1              
                else:                 
                    self.ssh_connection_ps += 1  

        elif code == 50: 
            self.ssh_auth_count += 1
        elif code == 51:
            self.ssh_userauth_failure_count += 1
        elif code == 52:
            self.ssh_userauth_success_count += 1

    
    def _update_performance_stats(self, lost_segment: str)->None:
        # throughput

        if self.duration > 0:
            self.throughput =  self.packet_size / self.duration # Total packet size / duration (in bytes/sec)

        if lost_segment != "":
            self.packet_loss_count += 1
            self.packet_loss_rate = self.packet_loss_count / self.total_packet_count   


    def _reduce_performance_stats(self, lost_packets: int)->None:
        """
        Reduce the performance stats.
        """
        if self.duration > 0:
            self.throughput = self.packet_size / self.duration 

        self.packet_loss_count -= lost_packets

        if self.total_packet_count > 0:
            self.packet_loss_rate = self.packet_loss_count / self.total_packet_count


    
    def _reduce_ssh_values(self, netstats: "NetStats")->None:
        """
        Reduce the ssh values.
        """
        self.ssh_init_key_exchange_count -= netstats.ssh_init_key_exchange_count
        self.ssh_auth_count -= netstats.ssh_auth_count
        self.ssh_userauth_failure_count -= netstats.ssh_userauth_failure_count
        self.ssh_userauth_success_count -= netstats.ssh_userauth_success_count

        # Reduce ssh payload stats
        if self.ssh_packet_count > 0:
            old_mean = self.ssh_packet_size_mean
            self.ssh_packet_count -= netstats.ssh_packet_count

            self.ssh_packet_size -= netstats.ssh_packet_size
            self.ssh_packet_size_mean = self.ssh_packet_size / self.ssh_packet_count if self.ssh_packet_size > 0 else self.ssh_packet_size
            self.ssh_packet_size_ssr -= ((self.ssh_packet_size_mean - old_mean) ** 2 + netstats.ssh_packet_size_ssr)
            self.ssh_packet_size_ssr = abs(self.ssh_packet_size_ssr)
            self.ssh_packet_size_std = (self.ssh_packet_size_ssr / self.ssh_packet_size) ** 0.5 if  self.ssh_packet_size > 0 else 0



    def _update_tcp_payload(self, payload: int)->None:
        """
        Update the tcp payload.
        """
        self.tcp_payload_size += payload
        self.tcp_payload_mean = self.tcp_payload_size / self.total_packet_count
        self.tcp_payload_ssr += (payload - self.tcp_payload_mean) ** 2
        self.tcp_payload_std = (self.tcp_payload_ssr / self.total_packet_count) ** 0.5

        if self.max_tcp_payload_size == NetStats.UNITIALIZED or payload > self.max_tcp_payload_size:
            self.max_tcp_payload_size = payload
        if self.min_tcp_payload_size == NetStats.UNITIALIZED or payload < self.min_tcp_payload_size:
            self.min_tcp_payload_size = payload


