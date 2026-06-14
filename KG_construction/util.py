
import logging
import matplotlib.pyplot as plt
from typing import Sequence
import os
import json
import pandas as pd
from typing import Dict
import re
import json
from typing import List

class Util:
    
    @staticmethod
    def check_and_create_path(file_path: str)->bool:
        """
        Check whether the directory and file exists. If not then create the directory and file.

        :param file_path: The file path.

        :return: True if the file exists, False otherwise.
        """
        exists = True
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))

        if not os.path.exists(file_path):
            exists = False
            with open(file_path, 'w') as f:
                pass  # Create an empty file
            
            return exists
        
        return exists

    @staticmethod
    def init_logging(file_path: str)->None:
        """
        Initialize the logging configuration.

        :param file_path: The file path to log.
        """

        Util.check_and_create_path(file_path)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(file_path),
                logging.StreamHandler()
            ]
        )

    @staticmethod
    def load_file(file_path: str)->list[str]:
        """
        Load the file and return the content as a list of strings.

        :param file_path: The file path.
        :return: A list of strings.
        """
        with open(file_path, "r") as file:
            lines = file.readlines()
            return [line.rstrip('\n') for line in lines]
        
        
    @staticmethod
    def load_attack_description(file_path: str)->str:
        """
        Load the attack description file and return the content as a string.

        :param file_path: The file path.
        :return: A string.
        """
        with open(file_path, "r") as file:
            lines = file.readlines()

            start_indx = 0

            if "source" in lines[0] or "Source" in lines[0]:
                start_indx = 1
            return ''.join(lines[start_indx:]).strip()
    
    @staticmethod
    def plot_scores(range :Sequence[int], scores :list[float], x_label :str, y_label :str, title :str, save_path : str, tick_interval :int = 10)->None: 
        """
        Plot the scores and save the plot.

        :param range: The range of the x-axis.
        :param scores: The scores.
        :param x_label: The x-axis label.
        :param y_label: The y-axis label.
        :param title: The title of the plot.
        :param save_path: The path to save the plot.
        :param tick_interval: The interval of the ticks.
        """
        plt.figure(figsize=(12, 6))
        plt.plot(range, scores, marker='o')
        plt.xlabel(x_label)
        plt.ylabel(y_label)
        plt.title(title)
        
        # Set x/y axis ticks
        tick_interval = 10 # Asuming the range is 0-100
        plt.xticks(range[::tick_interval], ha='right')
        plt.xlim(min(range), max(range))
        
        plt.grid(True)
        plt.tight_layout()
        
        # Save the plot        
        plt.savefig(save_path)
    
    @staticmethod
    def csv_file_exists(path: str)->bool:
        """
        Check whether the csv file exists.
        
        :param path: The file path.
        """
        return os.path.exists(path) and path.lower().endswith('.csv')
    
    @staticmethod
    def file_exists(path: str)->bool:
        """
        Check whether the file exists.
        If not then creates the file.
        
        :param path: The file path.
        """
        if os.path.exists(path):
            return True
        else:
            with open(path, "w") as file:
                return False

    @staticmethod
    def write_cache(cache_path: str, cache_field : str, value : int)->None:
        """
        Write the value to the cache file.

        :param cache_path: The cache file path.
        :param cache_field: The cache field.
        :param value: The value to write. Should be an index value. 
        """
        with open(cache_path, "r") as file:
            data = json.load(file)
        with open(cache_path, "w") as file:
            data[cache_field] = value
            json.dump(data, file)
    
    @staticmethod
    def save(cache_path: str, cache_field: str, column_name: str, value: str,
             df: pd.DataFrame, index: int, output_path: str) -> None:
        df.at[index, column_name] = value
        df.to_csv(output_path, index=False)
        Util.write_cache(cache_path, cache_field, index + 1)


    @staticmethod
    def prepare_dataframe(column_name: str, input_path: str, output_path: str) -> pd.DataFrame:
        """
        Prepare the dataframe for processing. It loads the dataframe from the output path if it exists, otherwise it loads the dataframe from the input path and adds a new column with the column name.
        
        :param column_name: The column name.
        :param input_path: The input path.
        :param
        """
        df = None
        path_exists = Util.check_and_create_path(output_path)
        if not path_exists:
            df = pd.read_csv(input_path)
            df[column_name] = None
            df.to_csv(output_path, index=False)
        else:
            df = pd.read_csv(output_path)
        return df
    
    @staticmethod
    def load_cache( field: str, cache_path: str, logger)->int:
        index = 0
        logger.info("Loading the last processed index from the cache file.")
        
        if os.path.exists(cache_path):
            with open((cache_path), "r") as file:
                try: 
                    cache = json.load(file)

                    if cache and field in cache and cache[field]:
                        index = int(cache[field])
                    else:
                        logger.info(f"Cache is not found for {field}. Index will be set to 0.")
                        Util.write_cache(cache_path, field, 0)
                     
                except json.JSONDecodeError:
                    logger.info("Failed to load the cache file...new empty cache will be created.")
                    with open(cache_path, "w") as file:
                        json.dump({}, file)
        else:
            logger.info("Cache file not found...new empty cache will be created.")
            with open(cache_path, "w") as file:
                json.dump({}, file)
                
        logger.info(f"Last processed index: {index}")          
        return index
    
    @staticmethod
    def get_response_content(response: Dict)->str:
        """
        Get the response content from the response dictionary.

        :param response: The response dictionary.
        :return: The response content.
        """
        return response.choices[0].message.content

    @staticmethod
    def process_response_as_json(response: str, logger) -> json:
        json_pattern =  r"```json(.*?)```"
        json_blocks = re.findall(json_pattern, response, re.DOTALL)
        json_objects = []

        # Process each JSON code block
        for block in json_blocks:
            try:
                json_data = json.loads(block.strip())
                if isinstance(json_data, list):
                    json_objects.extend(json_data)
                else:
                    json_objects.append(json_data)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse data: {response}")
                logger.error(f"Failed to parse the JSON data: {block}. Error: {e}")
        
        return json_objects
    
    @staticmethod
    def convert_to_gui_url(urls: List[str], store_file_path : List[str])->None:
        """
        Convert the URL to the GUI URL and store it in the file.
        Note: Crawled URL is different from GUI URL. The former will be displayed in the ` json` format. 

        :param urls: The list of URLs.
        """
        Util.check_and_create_path(store_file_path) 
        df = pd.DataFrame()
       
        gui_urls = []

        for url in urls:
            path = url.replace("https://api.github.com/repos", "")
            gui_urls.append("https://github.com" + path)

        df['GUI URL'] = gui_urls
        df['API URL'] = urls

        df.to_csv(store_file_path, index=False)