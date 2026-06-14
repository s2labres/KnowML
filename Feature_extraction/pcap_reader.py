"""
This script implements a pcap reader that is memory efficient - it reads the pcap file line by line and yields the packets one by one.
"""
import subprocess
from typing import  List, Optional

import subprocess
from typing import  List, Optional
import logging
import numpy as np

class PcapReader:
    def __init__(self, tshark_cmd: List[str], split_char: str=None) -> None:
        """
        Initialize the PcapReader class.
        
        :tshark_cmd: The tshark command to read the pcap file. 

        Example:
        >>> tshark_cmd = ["tshark", "-r", "test.pcap", "-T", "fields", "-E", "separator=|", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst"]
        """
        self.tshark_cmd = tshark_cmd
        self.process = None
        self.stdout_iter = None
        self.packet_count = 0
        self.split_char = split_char if split_char else "|"

    def __iter__(self):
        return self

    def __next__(self) -> Optional[List[str]]:
        if self.process is None:
            self._start_process()
        try:
            line = next(self.stdout_iter)
            self.packet_count += 1
            return line.strip().split(self.split_char)
        except StopIteration:
            self._cleanup()
            raise StopIteration("No more packets to read")

    def _start_process(self):
        try:
            self.process = subprocess.Popen(
                self.tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                shell=False  # Disabled for efficiency considereations
            )
            self.stdout_iter = iter(self.process.stdout)
        except Exception as e:
            logging.error(f"Failed to start tshark process: {str(e)}")
            raise

    def _cleanup(self):
        if self.process:
            self.process.stdout.close()
            return_code = self.process.wait()
            if return_code != 0:
                stderr_output = self.process.stderr.read()
                logging.error(f"tshark process exited with non-zero return code {return_code}. stderr: {stderr_output}")
            else:
                logging.info(f"tshark process completed successfully. Processed {self.packet_count} packets.")
            self.process = None
            self.stdout_iter = None
