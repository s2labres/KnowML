import unittest
from unittest.mock import patch
from test_util import TestUtil
from typing import List
import ast


# Add parent directory to reference feature_extractor
import os
import sys
from constants import IGNORE_COLS
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)
sys.path.append('../../')

from feature_extractor import FeatureExtractorChrollo
from fe_constants import FEConstants, PacketFEIdx

class TestFeatureExtractor(unittest.TestCase):
    """
    Test the FeatureExtractorChrollo class.
    """
    
    def file_exists(self, file_path: str)->bool:
        """
        Mock the file_exists method.
        """
        return True

    def _process_packet(self, packet: List[str]) -> List[str]:
        packet[PacketFEIdx.TCP_PAYLOAD] = 0
        packet[PacketFEIdx.ICMP_CODE] = -1
        packet[PacketFEIdx.ICMP_TYPE] = -1
        packet[PacketFEIdx.HTTP2_FRAME_SIZE] = 0
        packet[PacketFEIdx.HTTP_PAYLOAD] = 0
        packet[PacketFEIdx.TCP_PAYLOAD_SIZE] = 0
        return packet

    def test_extract(self, test_static=True):
        """
        Test the extract method of the FeatureExtractorChrollo/FeatureExtractorChrollo class.

        Note: When test_static is False, the KG API is expected to be up and running.
        """
        test_cases = [
            self._load_test_case_1(),
            self._load_test_case_2(), 
            # Note: 3- 4 are for UDP hence it will report an error for sequence number in case you are running testing code e.g. temporal_to_remove
            self._load_test_case_3(), 
            self._load_test_case_4(), 
            self._load_test_case_5(), 
            self._load_test_case_6()
        ]

        print("Running test cases for extract method")
        for test in test_cases:
            test_case_path = test["test_case_file_path"]

            with self.subTest(case=test["description"]):
                print(test['description'])

                class_to_test = FeatureExtractorChrollo
                with patch.object(class_to_test, '_file_exists', new=self.file_exists):
                    with patch.object(class_to_test, '_process_packet', new=self._process_packet):
                        mock_pcap_file = "fake_path.pcap"
                        mock_store_path = "fake_store_path"
                        max_iat = 60

                        fe = FeatureExtractorChrollo(mock_pcap_file, mock_store_path)
                        fe.TIMEOUT = max_iat
                        
                        mocked_packets, expected_channel_conversation, expected_dst_conversation = TestUtil.read_excel_sheet_to_arrays(
                            test_case_path, fe.packet_features, FEConstants.EXRACTION_FE)

                        with patch.object(class_to_test, 'pcap_reader', new=mocked_packets):
                            result_df = fe.extract(return_df=True)

                        self.assertTrue(all(feature in result_df.columns for feature in FEConstants.EXRACTION_FE), 
                                        "Not all features are present in the DataFrame columns")
                        
                        # Sort df columns according to the expected order
                        result_df = result_df[FEConstants.EXRACTION_FE]

                        index = 0
                        for i in range(0, len(result_df), 2):
                            channel_entry = result_df.iloc[i].to_numpy()
                            destination_entry = result_df.iloc[i + 1].to_numpy()
                            self._compare_arrays(channel_entry, expected_channel_conversation[index],
                                                f"Channel conversation at index {index}", result_df)
                            
                            ignore_columns = ["source_ip", "src_mac", "protocol", "src_port", "start_ts"]
                            self._compare_arrays(destination_entry, expected_dst_conversation[index],
                                                f"Destination conversation at index {index}", result_df, True, ignore_columns)
                            index += 1

                    print("All entries match the expected channel and destination conversations")
            
    def _compare_arrays(self, calculated_array, expected_array, message, result_df, is_dst_cnv=False, ignore_cols=[]):

        errors = 0
        error_message = f"{message} does not match.\n"
        # calculated_array = ast.literal_eval(calculated_array)


        ignore_columns = IGNORE_COLS
        ignore_columns = ignore_columns + ignore_cols
        
        for i in range(len(calculated_array)):
            column_name = result_df.columns[i]
            error = False
            # The source ip is separated by | any permutation of the ips is correct as longs as the count is the same
            if column_name in ignore_columns:
                continue
            if isinstance(expected_array[i], float): 
                # Note the formulas in the excel sheet are evaluated to different number of precision, hence the rounding
                expected_array[i] = round(expected_array[i], 3)
                calculated_array[i] = round(calculated_array[i], 3)
            if column_name == "src_mac" or column_name == "protocol": 
                if is_dst_cnv:
                    expected_array[i] = str(expected_array[i]).split("|")
                    expected_array[i] = set(expected_array[i])
                    calculated_array[i] = ast.literal_eval(calculated_array[i])
            if calculated_array[i] != expected_array[i]:
                error = True
            if error:
                error_message += f"Column: {column_name}, Expected: {expected_array[i]}, Actual: {calculated_array[i]}\n"
                errors += 1
        if errors > 0:
            self.fail(error_message)
        else: 
            print(f"{message} matches the expected conversation")

    def _get_path(self):
        # current dir
        return os.getcwd() +"/"
    
    def _load_test_case_1(self): 
        return {
            "test_case_num": 1,
            "description": "Test case 1:  Non-duplex | connection-oriented | non multi-origin | non-terminating | non exceeding-max iat\n",
            "test_case_file_path":  self._get_path() + "test_case1.xlsx", 
        }
    
    def _load_test_case_2(self): 
        return {
            "test_case_num": 2,
            "description": "Test case 2: Non-duplex | connection-oriented | multi-origin | non-terminating | non exceeding-max iat \n",
            "test_case_file_path": self._get_path() + "test_case2.xlsx"
        }
    

    def _load_test_case_3(self): 
        return {
            "test_case_num": 3,
            "description": "Test case 3: Non-duplex | connection-less | not multi-origin | non-terminating | non exceeding-max iat \n",
            "test_case_file_path": self._get_path() + "test_case3.xlsx"
        }
    
    def _load_test_case_4(self): 
        return {
            "test_case_num": 4,
            "description": "Test case 4) Non-duplex | connection-less | not multi-origin | non-terminating | exceeding-max iat \n",
            "test_case_file_path": self._get_path() + "test_case4.xlsx"
        }
        
    def _load_test_case_5(self):
        return {
            "test_case_num": 5,
            "description": "Test case 5) Non-duplex | connection-less | multi-origin | non-terminating |non-exceeding-max iat \n",
            "test_case_file_path": self._get_path() + "test_case5.xlsx"
        }
    
    def _load_test_case_6(self):
        return {
            "test_case_num": 6,
            "description": "Test case 6) duplex | connection-oriented | non-multi-origin | terminating | non - exceeding-max iat | protocol overwrite \n",
            "test_case_file_path": self._get_path() + "test_case6.xlsx"
        }

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTest(TestFeatureExtractor('test_extract'))

    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)