import os
import sys
import unittest
from typing import List

script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)
sys.path.append('../../')


from feature_extractor import FeatureExtractorChrollo
from fe_constants import PacketFEIdx


import unittest
from typing import List
from fe_constants import  PacketFEIdx
from netstats import NetStats
from enums import TCPState

import unittest
from unittest.mock import patch
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extractor import FeatureExtractorChrollo
from fe_constants import PacketFEIdx
from enums import TCPState

# Global test variables
SOURCE_IP = "TEST IP SRC"
DESTINATION_IP = "TEST IP DST"
SOURCE_MAC = "TEST MAC SRC"
DESTINATION_MAC = "TEST MAC DST"
SOURCE_PORT = "TEST PORT SRC"
DESTINATION_PORT = "TEST PORT DST"
    

class TestHandshake(unittest.TestCase):

    def file_exists(self, file_path: str)->bool:
        """
        Mock the file_exists method.
        """
        return True

    def setUp(self):
        """
        Set up the test environment with a mocked FeatureExtractorChrollo
        """
        with patch.object(FeatureExtractorChrollo, '_file_exists', new=self.file_exists):
            self.fe = FeatureExtractorChrollo("dummy.pcap", "dummy.csv")
        # Initialize the state dictionaries
        self.fe.channel_conversations = {}
        self.fe.dst_mac_conversations = {}

    def create_packet(
        self,
        src_ip: str = SOURCE_IP,
        dst_ip: str = DESTINATION_IP,
        src_mac: str = SOURCE_MAC,
        dst_mac: str = DESTINATION_MAC,
        src_port: str = SOURCE_PORT,
        dst_port: str = DESTINATION_PORT,
        seq_num: str = 0, 
        ack_num: str = "",
        syn_flag: str = "False",
        ack_flag: str = "False",
        fin_flag: str = "False",
        rst_flag: str = "False",
        protocol: str = "tcp",
        protocol_hierarchy: str = "eth:ethertype:ip:tcp",
        timestamp: str = 1.0
    ) -> List[str]:
        """Helper function to create test packets"""
        packet = [""] * len([attr for attr in dir(PacketFEIdx) if not attr.startswith('__')])
        
        packet[PacketFEIdx.SOURCE_IP] = src_ip
        packet[PacketFEIdx.DESTINATION_IP] = dst_ip
        packet[PacketFEIdx.SOURCE_MAC] = src_mac
        packet[PacketFEIdx.DESTINATION_MAC] = dst_mac
        packet[PacketFEIdx.SOURCE_PORT] = src_port
        packet[PacketFEIdx.DESTINATION_PORT] = dst_port
        packet[PacketFEIdx.SEQUENCE_NUMBER] = seq_num
        packet[PacketFEIdx.ACK_NUMBER] = ack_num
        packet[PacketFEIdx.SYN_FLAG] = syn_flag
        packet[PacketFEIdx.ACK_FLAG] = ack_flag
        packet[PacketFEIdx.FIN_FLAG] = fin_flag
        packet[PacketFEIdx.RST_FLAG] = rst_flag
        packet[PacketFEIdx.PROTOCOL] = protocol
        packet[PacketFEIdx.PROTOCOL_HIERARCHY] = protocol_hierarchy
        packet[PacketFEIdx.TIMESTAMP] = timestamp
        
        return packet

    def assert_TCP_State(self, expected_state, actual_state,
                          expected_channel_id, actual_channel_id,
                          expected_dst_id, actual_dst_id,
                          expected_init_state, actual_init_state,
                          expected_termination, actual_termination):
        
        self.assertEqual(expected_state, actual_state)
        self.assertEqual(expected_channel_id, actual_channel_id)
        self.assertEqual(expected_dst_id, actual_dst_id)
        self.assertEqual(expected_init_state, actual_init_state)
        self.assertEqual(expected_termination, actual_termination)


    def update_statistics(self, packet, channel_id,syn_flag, ack_flag): 
        """
        Update the statistics of the channel and destination conversations
        """
        
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].syn_flag_count += 1

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case1_normal_handshake(self, mock_file_exists):
        """
        Test Case 1: Normal handshake 
        (SYN → SYN-ACK → ACK)
        SYN_SENT → SYN_RECEIVED → ESTABLISHED
        SYN : Seq=0, Ack=''
        SYN-ACK : Seq=8, Ack=1
        ACK : Seq=1, Ack=9
        Out of order: 0
        """
        mock_file_exists.return_value = True
        
        # Create initial conversations

        # Initialize conversations
        packet = self.create_packet(syn_flag="True")
        channel_id, dst_id = self.fe._get_conversations(packet)
        
        # Send SYN
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                               NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        

        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].syn_flag_count = 1
        
        # # Send SYN-ACK
        syn_ack_packet = self.create_packet(
            src_ip= DESTINATION_IP, 
            dst_ip= SOURCE_IP,
            src_mac= DESTINATION_MAC,
            dst_mac= SOURCE_MAC,
            src_port= DESTINATION_PORT,
            dst_port= SOURCE_PORT,
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )

        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].init_out_of_order,
                                False, terminated)

        self.fe.channel_conversations[channel_id].total_packet_count =  2
        self.fe.channel_conversations[channel_id].syn_flag_count = 2
        self.fe.channel_conversations[channel_id].ack_flag_count = 1

        # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )
        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)

        self.fe.channel_conversations[channel_id].total_packet_count =  3
        self.fe.channel_conversations[channel_id].syn_flag_count = 2
        self.fe.channel_conversations[channel_id].ack_flag_count = 2

        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              0, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        
    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case2_early_ack(self, mock_file_exists):
        """
        Test Case 2: Early ACK 
        (SYN → ACK → SYN-ACK)
        SYN_SENT → ESTABLISHED → SYN_RECEIVED
        SYN : Seq=0, Ack=''
        ACK : Seq=1, Ack=9 
        SYN-ACK : Seq=8, Ack=1
        Out of order: 1
        """

        mock_file_exists.return_value = True

        packet = self.create_packet(syn_flag="True")
        channel_id, dst_id = self.fe._get_conversations(packet)
        
        # Send SYN
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(packet, channel_id, dst_id)

        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].syn_flag_count = 1
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)

        # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )
        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              1, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        
        self.fe.channel_conversations[channel_id].total_packet_count =  2
        self.fe.channel_conversations[channel_id].syn_flag_count = 1
        self.fe.channel_conversations[channel_id].ack_flag_count = 1
        
    # Send SYN-ACK
        
        syn_ack_packet = self.create_packet(
            src_ip= DESTINATION_IP, 
            dst_ip= SOURCE_IP,
            src_mac= DESTINATION_MAC,
            dst_mac= SOURCE_MAC,
            src_port= DESTINATION_PORT,
            dst_port= SOURCE_PORT,
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )

        channel_id, dst_id = self.fe._get_conversations(syn_ack_packet)

        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                1,  self.fe.channel_conversations[channel_id].init_out_of_order,
                                False, terminated)


    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case3_syn_ack_first(self, mock_file_exists):
        """
        Test Case 3: SYN-ACK First 
        (SYN-ACK → SYN → ACK)
        SYN_RECEIVED → SYN_SENT → ESTABLISHED
        SYN-ACK : Seq=8, Ack=1
        SYN : Seq=0, Ack=''
        ACK : Seq=1, Ack=9
        """
        mock_file_exists.return_value = True

        # Sent SYN-ACK
        syn_ack_packet = self.create_packet(
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )
        channel_id, dst_id = self.fe._get_conversations(syn_ack_packet)

        
        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)
        
        # The expected channel_id and dst_ids should be inverted SINCE the packet is initiated by the destination
        channel_id = self.fe._get_reverse_id(SOURCE_MAC, SOURCE_PORT, DESTINATION_MAC, DESTINATION_PORT, SOURCE_IP, DESTINATION_IP)
        dst_id = self.fe._get_dst_id_reverse(SOURCE_MAC, SOURCE_PORT, SOURCE_IP)

        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id_2].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                1,  self.fe.channel_conversations[channel_id_2].init_out_of_order,
                                False, terminated)
        
        # Send SYN
        syn_packet = self.create_packet(syn_flag="True")

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(syn_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id_1].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id_1].init_out_of_order,
                              False, terminated)
        
        # # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              1, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        
    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case4_syn_ack_first(self, mock_file_exists):
        """
        Test Case 4: SYN-ACK First 
        (SYN-ACK → ACK → SYN)
        SYN_RECEIVED → ESTABLISHED → SYN_SENT
        SYN-ACK : Seq=8, Ack=1
        ACK : Seq=1, Ack=9
        SYN : Seq=0, Ack=''
        """
        mock_file_exists.return_value = True

        # Sent SYN-ACK
        syn_ack_packet = self.create_packet(
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )
        channel_id, dst_id = self.fe._get_conversations(syn_ack_packet)

        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)

        channel_id = self.fe._get_reverse_id(SOURCE_MAC, SOURCE_PORT, DESTINATION_MAC, DESTINATION_PORT, SOURCE_IP, DESTINATION_IP)
        dst_id = self.fe._get_dst_id_reverse(SOURCE_MAC, SOURCE_PORT, SOURCE_IP)

        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id_2].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                1,  self.fe.channel_conversations[channel_id_2].init_out_of_order,
                                False, terminated)
        
        # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id_3].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              1, self.fe.channel_conversations[channel_id_3].init_out_of_order,
                              False, terminated)
        
        # Send SYN
        syn_packet = self.create_packet(syn_flag="True")

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(syn_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id_1].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id_1].init_out_of_order,
                              False, terminated)


    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case5_ack_first(self, mock_file_exists):
        """
        Test Case 5: ACK First 
        (ACK → SYN → SYN-ACK)
        UNITIALIZED(UNKNOWN) → SYN_SENT → SYN_RECEIVED
        ACK : Seq=1, Ack=9
        SYN : Seq=0, Ack=''
        SYN-ACK : Seq=8, Ack=1
        """
        mock_file_exists.return_value = True

        # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.NONE, self.fe.channel_conversations[channel_id_3].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              1, self.fe.channel_conversations[channel_id_3].init_out_of_order,
                              False, terminated)
        
        # Send SYN
        syn_packet = self.create_packet(syn_flag="True")

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(syn_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id_1].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id_1].init_out_of_order,
                              False, terminated)
        
        # Send SYN-ACK
        syn_ack_packet = self.create_packet(
            src_ip= DESTINATION_IP, 
            dst_ip= SOURCE_IP,
            src_mac= DESTINATION_MAC,
            dst_mac= SOURCE_MAC,
            src_port= DESTINATION_PORT,
            dst_port= SOURCE_PORT,
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )


        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                1,  self.fe.channel_conversations[channel_id].init_out_of_order,
                                False, terminated)

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case6_ack_first(self, mock_file_exists):
        """
        Test Case 6: ACK First 
        (ACK →SYN-ACK → SYN)
        UNITIALIZED(UNKNOWN) → SYN_RECEIVED → SYN_SENT
        ACK : Seq=1, Ack=9
        SYN-ACK : Seq=8, Ack=1
        SYN : Seq=0, Ack=''
        """
        mock_file_exists.return_value = True

        # Send ACK
        ack_packet = self.create_packet(
            seq_num=1,
            ack_num=9,
            ack_flag="True"
        )

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.NONE, self.fe.channel_conversations[channel_id_3].tcp_state,
                              channel_id, channel_id_3,
                              dst_id, dst_id_3,
                              1, self.fe.channel_conversations[channel_id_3].init_out_of_order,
                              False, terminated)
        
        # Send SYN-ACK
        syn_ack_packet = self.create_packet(
            src_ip= DESTINATION_IP, 
            dst_ip= SOURCE_IP,
            src_mac= DESTINATION_MAC,
            dst_mac= SOURCE_MAC,
            src_port= DESTINATION_PORT,
            dst_port= SOURCE_PORT,
            seq_num=8,
            ack_num=1,
            syn_flag="True",
            ack_flag="True"
        )

        terminated, channel_id_2 , dst_id_2 = self.fe._update_state(syn_ack_packet, channel_id, dst_id)
        self.assert_TCP_State(TCPState.SYN_RECEIVED, self.fe.channel_conversations[channel_id].tcp_state,
                                channel_id, channel_id_2,
                                dst_id, dst_id_2,
                                1,  self.fe.channel_conversations[channel_id].init_out_of_order,
                                False, terminated)
        
        # Send SYN
        syn_packet = self.create_packet(syn_flag="True")

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(syn_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.SYN_SENT, self.fe.channel_conversations[channel_id_1].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id_1].init_out_of_order,
                              False, terminated)

if __name__ == '__main__':
    unittest.main()
