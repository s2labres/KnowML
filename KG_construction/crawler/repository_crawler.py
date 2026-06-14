"""
This module contains the RepositoryCrawler class to crawl repositories for redme files.
"""

import os
import sys
from .crawler_constants import CrawlerConstants
import requests
import time
import urllib.parse
import logging
from dotenv import load_dotenv
from tqdm import tqdm
import base64
import csv
import time 
import json
import pandas as pd
from typing import List, Optional

parent_dir = os.path.dirname(os.getcwd())
sys.path.append(parent_dir)

from util import Util

class RepositoryCrawler:
    """
    This class contains functions to crawl repositories and code snippets from GitHub.
    """

# Private static final constants, don't change at runtime
    parent_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Constructor
    def __init__(self, cache_path, attack_name: str)->None: 
        """
        Initialize the RepositoryCrawler

        :param cache_path: The path to the cache file.
        :param attack_name: The name of the attack to save the URLs.
        """
        # Get access token from environment variables
        load_dotenv()
        self.fine_grained_access_token = os.environ.get("GITHUB_PERSONAL_FINE_GRAINED_ACCESS_TOKEN")

        # Initialize logging
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing RepositoryCrawler")
        
        # Initialize search endpoints
        self.search_endpoint = CrawlerConstants.ENDPOINT + "/search"
        self.search_repository_url = self.search_endpoint + "/repositories"

        # Variables for throttling 
        self.remaining_requests = -1
        self.reset_time = -1

        self.cache_path = cache_path
        self.attack_name = attack_name

# Public functions and properties
    @property
    def headers(self)->dir:
        """
        Get default headers for call 
        """
        return {
            "Accept": CrawlerConstants.ACCEPT_FORMAT,
            "Authorization": f"Bearer {self.fine_grained_access_token}",
            "X-GitHub-Api-Version": CrawlerConstants.API_VERSION
        }
    
    def crawl_repo_for_relevant_urls(self, keywords: list)->list[str]:
        """
        Get relevant repository URLs based on the keywords.

        :param keywords: A list of keywords to search for.
        :param name: The name of the attack to save the URLs.
        :return: A list of uniquue repository URLs.
        """
        urls = []
        # Save the URLs to the file
        current_dir = os.getcwd()
        to_file_path = f"{current_dir}/output/step1/{self.attack_name}/repo_urls.txt"

        Util.check_and_create_path(to_file_path)    

        for keyword in tqdm(keywords, desc="Processing keywords", unit="keyword"):
            temp_repo_urls_size = len(urls)

            # Search for repositories
            self._search(self.search_repository_url, {"q": keyword}, urls)
            self.logger.info(f"By searching repositories total of {len(urls) - temp_repo_urls_size} urls were found for the keyword: {keyword}.\n")

        if to_file_path:
            if not Util.file_exists(to_file_path): 
                self.logger.info(f"File at path {to_file_path} doesn't exist. Creating a new file.\n")
            with open(to_file_path, 'a') as file:
                for url in urls:
                    file.write(f"{url}\n")
        self.logger.info(f"Total of {len(urls)} urls were found.\n")        
        
        return urls

    def crawl_repos_for_readme(self, repo_urls: list[str])->None:
        """
        Crawl the repositories for README files and save the results in a CSV file.
        If no README file is found, then empty string is saved.
        Note: This functio does't do a recursive search for README files just checks the root directory.

        :param repo_urls: A list of repository URLs.
        :param csv_file_path: The file path to save the results. 
        """
        total_readme_files = 0
        csv_file_path = f"{self.parent_path}/output/step2/{self.attack_name}/readme_data.csv"
        
        if not Util.check_and_create_path(csv_file_path): 
            self.logger.info(f"File at path {csv_file_path} doesn't exist. New file created.\n")
            with open(csv_file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Repository URL", "README Content"])

        start_index = self._load_cache()

        for url in tqdm(repo_urls[start_index:], desc="Processing repositories", unit="repository"):
            self._throttle_request()
            response = self._get_repo_contents(url)

            if response.status_code == 200:
                start_index += 1
                self._set_throttle_vars(response.headers)

                self.logger.info(f"Successfully retrieved the contents of the repository: {url}.\n")

                response_data = response.json()

                # Extract the file names from the respository 
                content_names = [content["name"] for content in response_data]

                # Save the README file if found
                save_readme = self._save_readme(url, content_names, csv_file_path, start_index)
                if save_readme:
                    total_readme_files += 1
            else:
                self.logger.error(f"Failed to retrieve the contents of the repository: {url}.\n"
                              f"Response content: {response.text}\n")
        
        self.logger.info(f"Total of {total_readme_files} README files were found for all repositories.\n")
        # Read all readme and return as array
        df = pd.read_csv(csv_file_path)
        readmes = df["README Content"].tolist()
        return readmes, csv_file_path


    def crawl_repos_for_code(self, input_file: str, attack_name: str)->str:
        """
        Crawls Github repositories for code snippets that are specified at the 'URL' and 'File name' columns in the input file.

        :param input_file: The input file that contains the URLs and file names.
        :param output_path: The output path to save the code snippets.
        """
        output_path = os.getcwd() +f"/output/step 6/{attack_name}/code_data.csv"
        cache_field = "Code crawler"
        column_name = "Code"
        counter = 0

        df = Util.prepare_dataframe(column_name, input_file, output_path)
        df[column_name] = df[column_name].astype(str) # Convert the column to string to avoid cast error
        start_index = self._load_cache(cache_field)

        for index, row in tqdm(df.iloc[start_index:].iterrows(), total=len(df) - start_index,desc="Processing repositories", unit="repository"):
            self._throttle_request()
            
            if pd.isna(row["Main file name"]):
                continue # Skip repositories that have empty repository graph 
                
            url = row["Repository URL"]
            content_url = f"{url}/contents"
            file_name = row["Main file name"] 
            # main_file_name = row["Main file name"]    
            # file_name = self._get_file_name(content_url, main_file_name)

            # Check if file is a folder if it is then try to find a file with the same name as the folder or the main file 
            if file_name:
                content_url = f"{url}/contents/{file_name}"
                if '.' not in file_name: # Assume that file is a folder , TODO: Check what happens if assumption is wrong
                    file_name = self._get_file_name(content_url, file_name)
                    content_url += f"/{file_name}"
                    if not file_name or '.' not in file_name or ".exe" in file_name or "dylib" in file_name or ".jar" in file_name:
                       continue # Skip the repository if the file is not found
                elif ".exe" in file_name or "dylib" in file_name or ".jar" in file_name: 
                    continue # Skip executable files
                counter += 1
                self._retrieve_code(content_url, file_name, column_name, cache_field, df, index, output_path)
            else: 
                self.logger.info(f"The code file {file_name} not found in the repository {url}.\n")

        
        self.logger.info(f"Total of {counter} code content was retrieved.\n")
        return output_path
    

    def _get_file_name(self, url: str, main_file_name: str)->Optional[str]:
        response = self._send_get_request(url, {})
        file_name = None
        if response.status_code == 200:
            self._set_throttle_vars(response.headers)

            self.logger.info(f"Successfully retrieved the contents of the repository: {url}.\n")

            response_data = response.json()

            # Extract the file names from the respository 
            try: 
                content_names = [content["name"] for content in response_data]
            except TypeError:
                # This exceptation is expected when URI returned is not a catalogue page,
                #  meaning that it doesn't contain the list of files in the repository
                return file_name
            file_name = self._find_relevant_files(main_file_name, content_names)
        else: 
            self.logger.error( f"Status code: {response.status_code}\n"
                                f"Failed to retrieve the contents of the repository: {url}.\n"
                                f"Response content: {response.text}\n")
            
        return file_name

    def _find_relevant_files(self, file_name :str, file_names: str)->str: 
        """
        Helper function to find the relevant file in the repository based on the file name.

        if the file name is not found, then it will try to find the file that starts with "main".

        :param file_name: The file name to search for.
        :param file_names: A list of file names in the repository.
        """
        relevant_file =  self.starts_with(file_names, file_name)
        if not relevant_file:
            relevant_file =  self.starts_with(file_names, "main")

        return relevant_file
    
    def starts_with(self, array: List, prefix: str)->Optional[str]:
        return next((item for item in array if str(item).startswith(prefix)), None)
    

    def get_repo_content(self, content_url: str)->str:
        """
        Get the content of the repository based on the URL.

        :param url: The URL of the repository.
        :return: 
        """

        self._throttle_request()

        response = self._send_get_request(content_url, {})
        if response.status_code == 200:
            self._set_throttle_vars(response.headers)

            self.logger.info(f"Successfully retrieved the content of the repository: {content_url}.\n")
            response_data = response.json()

            # Content of the file is base64 encoded
            encoded_content = response_data["content"]
            content = base64.b64decode(encoded_content).decode("utf-8")
            return content
        else:
            self.logger.error(f"Failed to retrieve the content of the repository: {content_url}.\n"
                          f"Response content: {response.text}\n")
            return None 
        
    def generate_keyword_combinations(self, base_keywords: str, variations :str)->list[str]:
        """
        Generate keyword combinations based on base keywords and variations for search query.

        :param base_keywords: A list of base keywords.
        :param variations: A list of variations to combine with base keywords.
        :return: A list of keyword combinations.
        """
        keyword_combinations = []
        for base_keyword in base_keywords:
            for variation in variations:
                keyword_combinations.append(f"{base_keyword} {variation}")
        return keyword_combinations 

# Private functions and properties 
    def _search(self, endpoint: str, query: dir, urls: list[str])->None:
        page = 1
        retry_count = 0

        while True: 
            self._throttle_request()
            response = self._send_get_request(endpoint, query)

            if response.status_code == 200:
                self._set_throttle_vars(response.headers)

                response_data = response.json()

                # Retry if incomplete results
                if response_data["incomplete_results"]:
                    # Retry only once
                    if retry_count == 0: 
                        self.logger.warning(f"Incomplete results for the query: {query}. Retrying...")
                        # Wait for a 10 seconds before retrying
                        time.sleep(10) 
                        retry_count += 1
                        continue

                # Extract relevant URLs
                for item in response_data["items"]:
                    repo_url = item["url"]
                    if repo_url not in urls:
                        urls.append(repo_url)

                # Navigate through pagination, ref: https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api?apiVersion=2022-11-28
                link_header = response.headers.get("Link")
                if link_header: 
                    links = link_header.split(", ")

                    # if current page is the first page then next page will be the first link otherwise second link as preceded by rel="prev"
                    if 'rel="next"' in links[0] or 'rel="next"' in links[1]:
                        page += 1
                        retry_count = 0
                        query["page"] = page
                        continue
                    else: # No more pages, stop the search and return
                        self.logger.info(f"For a query: {query}, total of {page} pages was processed. ")
                        return    
                else: 
                    break
            else: 
                self.logger.error(f"Failed to get relevant URLs. Status code: {response.status_code}\n"
                              f"Response content: {response.text}\n")
                return

        self.logger.info(f"For a query: {query}, total of {page} pages was processed. ")
            
    def _send_get_request(self, endpoint: str, query: dir)->requests.Response:
        """
        Send a GET request to the specified endpoint with the query.
        """
        
        return requests.get(endpoint, headers=self.headers, params=query)
    
    def _encode_query(self, query: str)->str:
        """
        Encode the query to the percent-encoded format.
        """
        encoded_query = urllib.parse.quote(query)
        return encoded_query.replace("%20", "+")
    
    def _throttle_request(self)->None: 
        """
        Throttle the request to avoid exceeding rate limit.
        """

        if self.remaining_requests == 0:
            current_time = int(time.time())
            wait_time = self.reset_time - current_time
            wait_time = max(wait_time, 1) # Ensure wait time is not negative
            # Add an extra second to ensure the rate limit is reset, it was found that sometimes the rate limit is not reset exactly at the reset time
            wait_time += 1 

            self.logger.info(f"Rate limit for remaining requests reached. Waiting for {wait_time} seconds.\n")

            time.sleep(wait_time)
    
    def _has_md_suffix(self, string: str)->bool:
        """
        Check if the string has a markdown suffix.
        """
        return string.endswith(".md")
    
    def _get_repo_contents(self, repo_url: str)->requests.Response:
        """
        Get the contents of the repository based on the URL.

        :param url: The URL of the repository.
        :return: 
        """
        contents_url = f"{repo_url}/contents"
        return self._send_get_request(contents_url, {})
    
    def _set_throttle_vars(self, headers: dir)->None:
        """
        Helper function to set the throttle variables.
        """
        self.remaining_requests = int(headers["x-ratelimit-remaining"])
        self.reset_time = int(headers["x-ratelimit-reset"]) # Reset time in seconds since epoch
    
    def _load_cache(self, field: str="readme crawler")->int:
        index = 0
        self.logger.info("Loading the last processed index from the cache file.")
        
        if os.path.exists(self.cache_path):
            with open(self.cache_path, "r") as file:
                try: 
                    cache = json.load(file)

                    if cache and field in cache and cache[field]:
                        index = int(cache[field])
                    else:
                        self.logger.info(f"Cache is not found for {field}.")
                except json.JSONDecodeError:
                    self.logger.info("Failed to load the cache file...new empty cache will be created.")
                    with open(self.cache_path, "w") as file:
                        json.dump({}, file)
                
        self.logger.info(f"Last processed index: {index}")
        return index
    
    def _write_cache(self, field: str, value: int)->None:
        """
        Write the cache to the file.
        """
        data = {}
        with open(self.cache_path, "r") as file:
            data = json.load(file)

        with open(self.cache_path, "w") as file:
            data[field] = value
            json.dump(data, file)
    
    def _save_readme(self, url: str, content_names: list[str], csv_file_path: str, index: int)->bool:
        """
        Helper function to save the README file content in the CSV file if found.

        :param url: The URL of the repository.
        :param content_names: A list of content names in the repository.
        :param csv_file_path: The file path to save the results.
        :param index: The index of the repository in the list for cache.

        :return: True if README file is saved, otherwise False.
        """   
        saveReadme = False

        # Check if README file is present
        with open(csv_file_path, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            for content_name in content_names:
                if self._has_md_suffix(content_name) and content_name.lower() == "readme.md":
                    saveReadme = True

                    # Get the content of the README file
                    content_url = f"{url}/contents/{content_name}"
                    readme_content = self.get_repo_content(content_url)
                    writer.writerow([url, readme_content])
                    
                    self.logger.info(f"README file found for the repository: {url}.\n")
                    self._write_cache("readme crawler", index+1)
                    break
            if not saveReadme:    
                writer.writerow([url, ""])

        return saveReadme    
    
    def _save(self, cache_field: str, column_name: str, value: str, df: pd.DataFrame, index: int) -> None:
        if index != 0 and pd.isna(df.at[0, column_name]):
            raise Exception("Repository graph already was removed. Please check the logic.")
        df.at[index, column_name] = value
        df.to_csv(self.output_path, index=False)
        self._write_cache(cache_field, index + 1)

    def _retrieve_code(self, url: str, file_name :str, column_name: str, cache_field: str, df: pd.DataFrame, 
                       index: int, output_path: str)->bool:
        """
        Helper function to retrieve the code from the repository. 
        """   
        retrived_code = False

        code =  self.get_repo_content(url)

        if code:
            Util.save(self.cache_path, cache_field, column_name, code, df, index,  output_path)
            return True

        return retrived_code    
    
if __name__ == "__main__":


    crawler = RepositoryCrawler()

    # Crawl for relevant URLs for HTTP Flood attack
    file_path = ""
    keywords = crawler.generate_keyword_combinations(CrawlerConstants.HTTP_FLOOD_BASE_KEYWORDS, CrawlerConstants.HTTP_FLOOD_VARIATIONS)
    crawler.crawl_repo_for_relevant_urls(keywords, file_path)

    # Crawl for README files
    repo_urls = Util.load_file(file_path)
    readme_file_path = ""
    crawler.crawl_repos_for_readme(repo_urls, readme_file_path)

    
    