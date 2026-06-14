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
from enum import Enum, auto
from typing import List, Dict
from dataclasses import dataclass
from fe_constants import FEConstants, PacketFEIdx
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


    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_abrupt_termination(self, mock_file_exists):
        """
        Test Case 1: Abrupt Termination
        RST -> CLOSED
        """
        mock_file_exists.return_value = True
        
        packet = self.create_packet(rst_flag="True")
        channel_id, dst_id = self.fe._get_conversations(packet)
        
        # Send SYN
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.CLOSED, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].close_out_of_order,
                              True, terminated)
        

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination1(self, mock_file_exists):
        """
        Test Case 1: Graceful Termination
        FIN → FIN-ACK → ACK (ACK piggy bagged with FIN)

        FIN_WAIT_1 → FIN_WAIT_2 → CLOSED

        FIN: Seq=5, Ack=3
        FIN-ACK: Seq=3, Ack=6
        ACK: Seq=6, Ack=4



        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True
        
        # Create initial conversations

        # Initialize conversations
        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        channel_id, dst_id = self.fe._get_conversations(fin_packet)
        
        # Send FIN
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].close_out_of_order,
                              False, terminated)
        
        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1

        terminated, channel_id_2, dst_id_2 = self.fe._update_state(fin_ack_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.TIME_WAIT, self.fe.channel_conversations[channel_id_2].tcp_state,
                              channel_id, channel_id_2,
                              dst_id, dst_id_2,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_2].close_out_of_order,
                              False, terminated)
        # Send ACK
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1
        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.CLOSED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                0, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                True, terminated)
        

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination2(self, mock_file_exists):
        """
        Test Case 2: Graceful Termination
        # The LAST_ACK arrives before FIN-ACK
        FIN → ACK → FIN-ACK 

        FIN_WAIT_1 → CLOSED  → Unitilized

        FIN: Seq=5, Ack=3
        FIN-ACK: Seq=3, Ack=6
        ACK: Seq=6, Ack=4

        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True
        

        # Initialize conversations
        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        channel_id, dst_id = self.fe._get_conversations(fin_packet)
        
        # Send FIN
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].close_out_of_order,
                              False, terminated)
        
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1

        # Send ACK
        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)

        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1

        self.assert_TCP_State(TCPState.CLOSED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                1, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                True, terminated)
        
        if terminated:
            self.fe.channel_conversations.pop(channel_id)
            self.fe.dst_mac_conversations.pop(dst_id)
        
        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)

        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        

        # Send FIN
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].close_out_of_order,
                              False, terminated)
        


    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination3(self, mock_file_exists):
        """
        Test Case 3: Graceful Termination
        FIN-ACK → FIN → ACK  
        [some packet sent in before
        FIN_WAIT_1  → FIN_WAIT_1  → CLOSED

        FIN-ACK: Seq=3, Ack=6
        FIN: Seq=5, Ack=3
        ACK: Seq=6, Ack=4
    
        FIN-ACK: Seq=10, Ack=6
        FIN: Seq=5, Ack=10
        ACK: Seq=6, Ack=11

        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True
        
        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)

        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        # Assume some packets were sent before
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1
        terminated, channel_id_2, dst_id_2 = self.fe._update_state(fin_ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id_2].tcp_state,
                              channel_id, channel_id_2,
                              dst_id, dst_id_2,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_2].close_out_of_order,
                              False, terminated)

        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1
        
        # Send FIN
        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id].close_out_of_order,
                              False, terminated)
        
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1

        # Send ACK
        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)
        # Send ACK
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1
        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.CLOSED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                1, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                True, terminated)
        


    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination4(self, mock_file_exists):
        """
        Test Case 4: Graceful Termination
        FIN-ACK → ACK → FIN
        [some packet sent in before
        FIN_WAIT_1  → CLOSED → Unitilized

        FIN-ACK: Seq=3, Ack=6
        ACK: Seq=6, Ack=4
        FIN: Seq=5, Ack=3
       

        FIN: Seq=5, Ack=10  -> FIN_WAIT_1 RFC: Dst 
        FIN-ACK: Seq=10, Ack=6 -> FIN_WAIT_2 
        ACK: Seq=6, Ack=11 0 -> CLOSED

        FIN-ACK: Seq=10, Ack=6 ->FIN_WAIT_1 Dst: Src
        ACK: Seq=6, Ack=11 ->CLOSED
        FIN: Seq=5, Ack=10 ->UNITIALIZED

        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True
        
        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)

        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        # Assume some packets were sent before
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1
        terminated, channel_id_2, dst_id_2 = self.fe._update_state(fin_ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id_2].tcp_state,
                              channel_id, channel_id_2,
                              dst_id, dst_id_2,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_2].close_out_of_order,
                              False, terminated)

        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1

        # Send ACK
        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.CLOSED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                1, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                True, terminated)
        
        self.fe.channel_conversations[channel_id].total_packet_count =  1

        if terminated:
            self.fe.channel_conversations.pop(channel_id)
            self.fe.dst_mac_conversations.pop(dst_id)

        # Send FIN

        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        channel_id, dst_id = self.fe._get_conversations(fin_packet)

        self.fe.channel_conversations[channel_id].fin_flag_count = 1
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination5(self, mock_file_exists):
        """
        Test Case 5: Graceful Termination
        [some packet sent in before]
        ACK → FIN → FIN-ACK
      
        Unitilized  → FIN_WAIT_1 → TIME_WAIT

        FIN-ACK: Seq=3, Ack=6
        ACK: Seq=6, Ack=4
        FIN: Seq=5, Ack=3
       

        FIN: Seq=5, Ack=10  -> FIN_WAIT_1 RFC: Dst 
        FIN-ACK: Seq=10, Ack=6 -> TIME_WAIT 
        ACK: Seq=6, Ack=11 0 -> CLOSED

        FIN-ACK: Seq=10, Ack=6 ->FIN_WAIT_1 Dst: Src
        ACK: Seq=6, Ack=11 ->CLOSED
        FIN: Seq=5, Ack=10 ->UNITIALIZED

        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True
        # Send ACK

        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        # Assume connection was initiated before
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].tcp_state = TCPState.ESTABLISHED
        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)


        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                False, terminated)
        
        
        # Send FIN
        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        channel_id, dst_id = self.fe._get_conversations(fin_packet)

        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)


        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1

        print(f"\nproduced state {self.fe.channel_conversations[channel_id].tcp_state}\n")
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id].init_out_of_order,
                              False, terminated)
        
        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)
        
        # Assume some packets were sent before
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1
        terminated, channel_id_2, dst_id_2 = self.fe._update_state(fin_ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.TIME_WAIT, self.fe.channel_conversations[channel_id_2].tcp_state,
                              channel_id, channel_id_2,
                              dst_id, dst_id_2,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_2].close_out_of_order,
                              False, terminated)

    @patch.object(FeatureExtractorChrollo, '_file_exists')
    def test_case_graceful_termination6(self, mock_file_exists):
        """
        Test Case 6: Graceful Termination
        ACK → FIN-ACK → FIN  
        FIN-ACK → ACK → FIN
        [some packet sent in before
        Unitilized  → FIN_WAIT_1 → FIN_WAIT_1

        FIN-ACK: Seq=3, Ack=6
        ACK: Seq=6, Ack=4
        FIN: Seq=5, Ack=3

        FIN: Seq=5, Ack=10  -> FIN_WAIT_1 RFC: Dst 
        FIN-ACK: Seq=10, Ack=6 -> FIN_WAIT_2 
        ACK: Seq=6, Ack=11 0 -> CLOSED

        FIN-ACK: Seq=10, Ack=6 ->FIN_WAIT_1 Dst: Src
        ACK: Seq=6, Ack=11 ->CLOSED
        FIN: Seq=5, Ack=10 ->UNITIALIZED

        Note: We skip the CLOSE-WAIT and only consider the FIN_WAIT_1, FIN_WAIT_2, and CLOSED states
        """
        mock_file_exists.return_value = True

        # Send ACK

        ack_packet = self.create_packet(ack_flag="True", seq_num=6, ack_num=4)

        channel_id, dst_id = self.fe._get_conversations(ack_packet)

        # Assume connection was initiated before
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].tcp_state = TCPState.ESTABLISHED
        terminated, channel_id_3, dst_id_3 = self.fe._update_state(ack_packet, channel_id, dst_id)


        self.assert_TCP_State(TCPState.ESTABLISHED, self.fe.channel_conversations[channel_id_3].tcp_state,
                                channel_id, channel_id_3,
                                dst_id, dst_id_3,
                                NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_3].close_out_of_order,
                                False, terminated)

        self.fe.channel_conversations[channel_id].total_packet_count +=  1

        # Send FIN-ACK
        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        channel_id, dst_id = self.fe._get_conversations(fin_ack_packet)

        fin_ack_packet = self.create_packet(fin_flag="True", ack_flag="True",
                                             seq_num=3, ack_num=6, src_ip=DESTINATION_IP, dst_ip=SOURCE_IP,
                                                src_mac=DESTINATION_MAC, dst_mac=SOURCE_MAC,
                                                src_port=DESTINATION_PORT, dst_port=SOURCE_PORT)
        
        # Assume some packets were sent before
        self.fe.channel_conversations[channel_id].total_packet_count =  1
        self.fe.channel_conversations[channel_id].fin_flag_count = 1
        terminated, channel_id_2, dst_id_2 = self.fe._update_state(fin_ack_packet, channel_id, dst_id)

        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id_2].tcp_state,
                              channel_id, channel_id_2,
                              dst_id, dst_id_2,
                              NetStats.UNITIALIZED, self.fe.channel_conversations[channel_id_2].close_out_of_order,
                              False, terminated)

        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1
        
        # Send FIN
        fin_packet = self.create_packet(fin_flag="True", seq_num=5, ack_num=3)
        terminated, channel_id_1, dst_id_1 = self.fe._update_state(fin_packet, channel_id, dst_id)
        
        self.assert_TCP_State(TCPState.FIN_WAIT_1, self.fe.channel_conversations[channel_id].tcp_state,
                              channel_id, channel_id_1,
                              dst_id, dst_id_1,
                              1, self.fe.channel_conversations[channel_id].close_out_of_order,
                              False, terminated)
        
        self.fe.channel_conversations[channel_id].total_packet_count +=  1
        self.fe.channel_conversations[channel_id].fin_flag_count += 1 
        
if __name__ == '__main__':
    unittest.main()
