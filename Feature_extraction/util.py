import logging
from pathlib import Path
from typing import List, Union, Any
import numpy as np
import csv

class Util:
    
    @staticmethod
    def init_logging(file_path: str)->None:
        """
        Initialize the logging configuration.

        :param file_path: The file path to log.
        """
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(file_path),
                logging.StreamHandler()
            ]
        )

class DataBuffer:
    def __init__(self, csv_path: Union[str, Path], buffer_size: int = 50000):  # Increased buffer size
        self.csv_path = Path(csv_path)
        self.buffer = []
        self.buffer_size = buffer_size
        self.total_processed = 0
        
        # Pre-allocate buffer to avoid resizing
        self.buffer = [None] * buffer_size
        self.buffer_index = 0
        
        # Open file once and keep it open
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.csv_path, 'a', newline='', buffering=8192*16)  # Increased buffer size
        self.writer = csv.writer(self.file)

    def add_row(self, row: str):
        self.buffer[self.buffer_index] = row
        self.buffer_index += 1
        self.total_processed += 1
        
        if self.buffer_index >= self.buffer_size:
            self.flush()

    def flush(self):
        if self.buffer_index == 0:
            return
            
        self.writer.writerows(self.buffer[:self.buffer_index])
        self.buffer_index = 0

    def close(self):
        self.flush()
        self.file.close()