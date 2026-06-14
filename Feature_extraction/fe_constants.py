
from enum import Enum

class FEConstants: 
    """
    This class contains constants used in the FE module.
    """

    
    # Packet level features
    THARK_CMD_MAP = {
        "source_ip": "ip.src",
        "destination_ip": "ip.dst",
        "source_port": ["tcp.srcport", "udp.srcport"],
        "destination_port": ["tcp.dstport", "udp.dstport"],
        "source_mac": "eth.src",
        "destination_mac": "eth.dst",
        "timestamp" : "frame.time_epoch", 
        "protocol": "_ws.col.Protocol",
        "syn_flag": "tcp.flags.syn",
        "ack_flag": "tcp.flags.ack",
        "fin_flag": "tcp.flags.fin",
        "rst_flag": "tcp.flags.reset",
        "push_flag": "tcp.flags.push",
        "sequence_number": "tcp.seq",
        "frame_len": "frame.len",
        "http_domain": "http.host",
        "https_domain": "tls.handshake.extensions_server_name",
        "dns_domain_name": "dns.qry.name", 
        "tcp_keep_alive": "tcp.analysis.keep_alive", 
        "protocol_hierarchy": "frame.protocols", 
        "ssh_encrypted": "ssh.packet_length_encrypted", 
        "ttl": "ip.ttl",
        "ack_number": "tcp.ack", 
        "http_cookie": "http.cookie",
        "http_status_code": "http.response.code", 
        "http_request_method": "http.request.method",
        "http_payload": "http.content_length", 
        "http_authorization": "http.authorization", 
        "tcp_window_size": "tcp.window_size", 
        "icmp_type": "icmp.type",
        "http_frame_type": "http2.type", 
        "http1_auth": "http.authorization", 
        "http2_auth": "http2.headers.authorization", 
        "http_resource": "http.request.uri",
        "urg_flag": "tcp.flags.urg",
        "source_ip": "ip.src",
        "destination_ip": "ip.dst", 
        "retransmission": "tcp.analysis.retransmission", 
        "lost_segment": "tcp.analysis.ack_lost_segment",  # Ack number for unseen segement -> Indicate packet losss
        "tcp_payload": "tcp.len", 
        "icmp_code": "icmp.code", 
        "http_header_size": "http.content_length_header", 
        "http2_frame_type": "http2.type",
        "http2_frame_size": "http2.length",
        "http_user_agent": "http.user_agent",
        "http_accept_encoding": "http.accept_encoding",
        "http_accept_language": "http.accept_language",
        "http_bad_header": "http.bad_header_name", 
        "ssh_message_code": "ssh.message_code",
        "ip_protocol": "ip.proto", 
        "ip_more_fragment": "ip.flags.mf",
        "ip_frag_offset": "ip.frag_offset", 
        "tcp_payload_size": "tcp.len"
    }   

    # Base feature that need to be extracted from the packet for correct feature extraction
    PACKET_FE = [ "source_port", "destination_port", "source_mac", "destination_mac", "protocol", "protocol_hierarchy",
                  "sequence_number", "timestamp", "syn_flag", "ack_flag", "fin_flag", "rst_flag", "frame_len", "ttl", "ack_number", "push_flag", "http_cookie",
                  "http_status_code", "http_request_method", "http_payload", "http_authorization", "tcp_window_size", "icmp_type", 
                  "http_frame_type", "http1_auth", "http2_auth", "http_resource" , "urg_flag"      
                ]
                            
    EXRACTION_FE = [
            "src_mac", "src_port","dst_mac", "src_ip", "dst_ip", "dst_port", "protocol",  "ex_ack_number", "ex_seq_num",  "last_ts", "start_ts", "receiver",
              "duration", "connection_count", "keep_alive_count", 
            "inbound_packet_rate", "outbound_packet_rate", "packet_size", "total_packet_count", 
            "packet_size_mean", "packet_size_std", "iat_time", "iat_time_mean", "iat_time_std",
            "invalid_checksums_count", "inbound_packet_count", "outbound_packet_count",
            "syn_flag_count", "rst_flag_count", "ack_flag_count",
            "fin_flag_count", "packet_size_ssr", "iat_time_ssr", "ttl_mean", "ttl_std", "ttl_ssr", "ttl_packets", "ttl", "push_flag_count",
            "http_cookie_size", "http_cookie_mean", "http_cookie_std", "http_cookie_ssr", 
            "http_get_count", "http_post_count", "http_put_count", "http_delete_count", "http_head_count", "http_patch_count",
            "http_payload_size", "http_payload_mean", "http_payload_std", "http_payload_ssr",
            "http_header_size", "http_header_mean", "http_header_std", "http_header_ssr",
            "http_auth_count", "http_packet_count", 
            "transmission_rate", "tcp_window_size", "tcp_window_size_mean", "tcp_window_size_std", "tcp_window_size_ssr", 
            "xmas_packets_count", "http_options_count", "http_trace_count", "ping_request_count", 
            "http_header_count", "http_rst_stream_count", 
            "ssh_packet_size", "ssh_packet_size_mean", "ssh_packet_size_std", "ssh_packet_size_ssr", 
            "http_auth_count" , "urg_flag_count", 
            "tcp_state", "init_out_of_order", "close_out_of_order", 
            "min_ttl", "max_ttl", "retransmission_packets", "idle_connections", 
            "request_interaval", "request_interval_mean", "response_interval", "response_interval_mean", 
            "last_request_ts", "last_response_ts", 
            "retransmission_rate", "throughput", "packet_loss_count", "packet_loss_rate", 
            "zero_window_count", "zero_window_frequency",
            "max_window_size", "min_window_size",
            "tcp_payload_size", "tcp_payload_mean", "tcp_payload_std", "tcp_payload_ssr", "max_tcp_payload_size", "min_tcp_payload_size",
            "icmp_packet_count", "icmp_error_count",
            "http_success_count", 
            "http_client_side_error_count", 
            "http_server_side_error_count", 
            "http_rst_stream_count", 
            "http_data_frame_count", 
            "http_goaway_count", 
            "http_frame_size", "http_frame_size_mean", "http_frame_size_std", "http_frame_size_ssr",
            "malfolded_user_agent_count", 
            "malfolded_accept_encoding_count", 
            "malfolded_accept_language_count", 
            "bad_http_header_count", 
            "null_flags_count", 
            "ssh_packet_count", 
            "ssh_init_key_exchange_count", 
            "ssh_auth_count", 
            "ssh_userauth_failure_count", 
            "ssh_userauth_success_count", 
            "tcp_fragmented_packet_count",
            "ssh_connection_ps", 
            "start_sec",
            "http_connection_p5s",
            "win_start_ts", 
            "win_http_pks", 
            "win_start_ts_ssh", 
            "win_con_attempt", 
            "win_ter_attempt", 
            "connection_est_attempts_ps", 
            "connection_ter_attempts_ps"
        ]


class PacketFEIdx(): 
    # Packet features
    SOURCE_PORT = 0
    DESTINATION_PORT = 1
    SOURCE_MAC = 2
    DESTINATION_MAC = 3
    PROTOCOL = 4
    PROTOCOL_HIERARCHY = 5
    SEQUENCE_NUMBER = 6
    TIMESTAMP = 7
    SYN_FLAG = 8
    ACK_FLAG = 9
    FIN_FLAG = 10
    RST_FLAG = 11
    FRAME_LEN = 12
    HTTP_DOMAIN = 13
    HTTPS_DOMAIN = 14
    DNS_DOMAIN_NAME = 15
    SSH_ENCRYPTED = 16
    TCP_KEEP_ALIVE = 17
    TTL = 18
    ACK_NUMBER = 19
    PUSH_FLAG = 20
    HTTP_COOKIE = 21
    HTTP_STATUS_CODE = 22
    HTTP_REQUEST_METHOD = 23
    HTTP_PAYLOAD = 24
    HTTP_AUTHORIZATION = 25
    TCP_WINDOW_SIZE = 26
    ICMP_TYPE = 27
    HTTP_FRAME_TYPE = 28
    HTTP1_AUTH = 29
    HTTP2_AUTH = 30
    HTTP_RESOURCE = 31
    URG_FLAG = 32
    SOURCE_IP = 33
    DESTINATION_IP = 34
    RETRANSMISSION = 35
    LOST_SEGMENT = 36
    TCP_PAYLOAD = 37
    ICMP_CODE = 38
    HTTP_HEADER_SIZE = 39
    HTTP2_FRAME_TYPE = 40
    HTTP2_FRAME_SIZE = 41
    HTTP_USER_AGENT = 42
    HTTP_ACCEPT_ENCODING = 43
    HTTP_ACCEPT_LANGUAGE = 44
    HTTP_BAD_HEADER = 45
    SSH_MESSAGE_CODE = 46
    IP_PROTOCOL = 47
    IP_MORE_FRAGMENT = 48
    IP_FRAG_OFFSET = 49
    TCP_PAYLOAD_SIZE = 50
