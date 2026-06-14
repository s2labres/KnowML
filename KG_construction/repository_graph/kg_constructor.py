import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Dict, Callable, Union, Optional
import pandas as pd
import json
from llm.openai_api import OpenAIAPI
from llm.constants import LLMConstants
from llm.types import ChatCompletionLLM
from util import Util
import os
from tqdm import tqdm
from .configs import * 
import re
from .response import *
from .response_formats import *

# TODO: TO BE REMOVED FOR MONITORING GLEARING IMPROVEMENT
GLEARING_0 = 0
GLEARING_1 = 0
GLEARING_2 = 0

class BatchProcessor(ABC):
    @abstractmethod
    def process_batch(self, batch: List[Tuple[int, str]], df: pd.DataFrame, indices: List[int], 
                      model_params: ChatCompletionLLM, input_func: Callable, 
                      process_response_func: Callable, column_name: str, 
                      max_gleanings: int, code_analysis: bool, *input_args) -> None:
        pass # Abstract method MUST be implemented in the child class


class StandardBatchProcessor(BatchProcessor):
    def __init__(self, api: OpenAIAPI, cache_field: str):
        self.api = api
        self.cache_field = cache_field
        self.logger = logging.getLogger(__name__)

    def process_batch(self, batch: List[Tuple[int, str]], df: pd.DataFrame, indices: List[int], 
                      model_params: ChatCompletionLLM, input_func: Callable, 
                      process_response_func: Callable, column_name: str, output_path: str,
                      max_gleanings: int, code_analysis: bool, *input_args) -> None:
        content = KGConstructor.REQUEST_DELIMETER.join([x[1] for x in batch])
        response = self._process_single_batch(content, model_params, input_func, max_gleanings, code_analysis, *input_args, )

        process_response_func(self.cache_field, column_name, response, df, indices[0], output_path)

# TODO: TO BE REMOVED FOR MONITORING GLEARING IMPROVEMENT
    def _update_kg(self, repo_kg: Dict, response_content: str) -> Dict:
        parsed_data = json.loads(response_content)
        
        if repo_kg is None:
            return parsed_data
        else:
            entity = "strategies" if "strategies" in parsed_data else "features"
            entities = repo_kg[entity] + parsed_data[entity]
            repo_kg[entity] = entities
            return repo_kg 
        
    def _process_single_batch(self, content: str, model_params: ChatCompletionLLM, 
                              input_func: Callable, max_gleanings: int, code_analysis : bool,*input_args) -> Dict:
        repeat = True
        permitted_attempts = max_gleanings
        extraction_history = None
        last_gleaning_response = "" 
        empty_response = '{"strategies":[]}'
        repo_kg = json.loads(empty_response)

        # TODO: TO BE REMOVED FOR MONITORING GLEARING IMPROVEMENT
        repo_kg = None
        counter = 0
        global GLEARING_0, GLEARING_1, GLEARING_2

        while repeat and permitted_attempts > 0:

            user_message = self._get_user_message(input_func, extraction_history, content, code_analysis, last_gleaning_response,  *input_args)
            response_content = self._get_api_response(user_message, model_params)
            
            attempts = max_gleanings - permitted_attempts + 1
            extraction_history = self._update_history(extraction_history, response_content, attempts)
            permitted_attempts -= 1

            repo_kg = self._update_kg(repo_kg, response_content)

            # TODO: TO BE REMOVED FOR MONITORING GLEARING IMPROVEMENT
            if counter == 0:
                GLEARING_0 += self._count_kg(repo_kg)
                logging.info(f"Number of entities extracted in Glearing 0: {GLEARING_0}")
            elif counter == 1:
                GLEARING_1 += self._count_kg(repo_kg)
                logging.info(f"Number of entities extracted in Glearing 1: {GLEARING_1}")
            elif counter == 2:
                GLEARING_2 += self._count_kg(repo_kg)
                logging.info(f"Number of entities extracted in Glearing 2: {GLEARING_2}")

            # if response_content == empty_response: # Skip gleaning if no strategies are found
            #     break # Stop if no new information is extracted

            counter += 1
            if ('strategies' not in repo_kg or len(repo_kg['strategies']) == 0) and  not("features" in repo_kg and len(repo_kg["features"]) > 0):
                break

            if permitted_attempts > 0:
                repeat,  gleaning_response = self._should_stop_gleaning(extraction_history, content, code_analysis)
                last_gleaning_response = gleaning_response # This is a short description of missed entities
        return repo_kg 
    
    def _count_kg(self, repo_kg: Dict) -> int:
        if repo_kg is None:
            return 0
        elif "strategies" not in repo_kg: # GPT3.5 returns UNSTRUCTURED data
            return 0
        else:
            return len(repo_kg["strategies"])

    def _get_user_message(self, input_func: Callable, extraction_history: str, 
                          readme_content: str, code_analysis: bool, gleaning_response, *input_args) -> List[Dict]:
        if extraction_history is None:
            full_args = input_args + (readme_content,)
            user_message = input_func(*full_args)
        else:
            user_message = self._get_repo_continue_prompt(extraction_history, readme_content, code_analysis, gleaning_response)
            user_message[0]['content'] = user_message[0]['content'].strip()
            user_message[3]['content'] = user_message[3]['content'].strip()
        
        if isinstance(user_message[0]['content'], tuple): 
            user_message[0]['content'] = user_message[0]['content'][0]
        return user_message

    def _get_api_response(self, user_message: List[Dict], model_params: ChatCompletionLLM) -> str:
        response, *http = self.api.send_chat_completion_request(user_message, model_params)
        if response is None: #TODO: Handle this case of response doesn't limit http
            if http:
                self._handle_api_error(http)
            else:
                raise Exception("Failed to get response content for the batch."
                                "Response returned is None and no HTTP response is found.")
        # Check if valid json 
        self._is_valid_json_response(response.choices[0].message.content)
        return self._get_response_content(response)
    
    def _is_valid_json_response(self, response :str) -> None:
        try:
            json.loads(response)
        except json.JSONDecodeError:
            raise Exception("Invalid JSON response returned from the API"
                            f"Response: {response}")

    def _update_history(self, past_response: str, response_content: str, attempts :int) -> str:
        if past_response is None:
            return f"#### PAST EXTRACTION 1####: \n History: ```json {response_content}```"
        else:
            return past_response + f"#### PAST EXTRACTION {attempts}####:  \n History: ```json \n{response_content}\n\n```" 

    def _should_stop_gleaning(self, history: str, user_message: str, code_analysis: bool) -> Tuple[bool, str]:
        gleanings_msg = self._get_gleaning_prompt(history, user_message, code_analysis)   
        
        response_format = None

        if "gpt-4" in self.api.model:
            response_format = GLEANING_RESPONSE_FORMAT if not code_analysis else CODE_ANALYSIS_GLEANING_RESPONSE_FORMAT
        else:
            response_format = JSON_OBJECT
        gleanings_model = ChatCompletionLLM(temperature=GleaningConfig.TEMPERATURE, 
                                            seed=GleaningConfig.SEED, 
                                           top_p=GleaningConfig.TOP_P, 
                                           model=GleaningConfig.MODEL,
                                           max_tokens=GleaningConfig.MAX_TOKENS, 
                                           response_format=response_format)
        
        self.api.model = gleanings_model.model
        if isinstance(gleanings_msg[0]['content'], tuple): 
            gleanings_msg[0]['content'] = gleanings_msg[0]['content'][0]


        response, *_ = self.api.send_chat_completion_request(gleanings_msg, gleanings_model)
        response_content = self._get_response_content(response)

        # Note that GPT3.5 might hallucinate and provide incorrect information and unstructured data. To deals with this problem
        # if the response cannot me converted to a valid json object, we will treat the response as "Not Found" and no further gleaning will be done.
        try:
            response_content = json.loads(response_content)
        except json.JSONDecodeError:
            response_content = {"Answer": "YES", "Description": ""} # YES means that gleaning should stop 
            self.logger.info(
                                "Failed to convert the response to a valid json object. Treating the response as 'YES' to stop gleaning."
                                f"Response: {response_content}"
                             )
        return "NO" in response_content["Answer"], response_content["Description"]

    def _handle_api_error(self, http):
        _, http_response = http
        if self._is_repetitive_pattern_error(http_response):
            logging.info("Repetitive pattern found in readme. Treating the readme content as not found.")
            return "Not Found"
        else:
            raise Exception("Failed to get response content for the batch.")

    @staticmethod
    def _get_response_content(response):
        return response.choices[0].message.content

    @staticmethod
    def _is_repetitive_pattern_error(response: str) -> bool:
        return KGConstructor.REPETITIVE_PATTERN_ERROR in response
    
    @staticmethod
    def _get_repo_continue_prompt(extraction_history: str, user_input: str, code_analysis: bool, gleaning_response :str) -> List[Dict]:
        extraction_history = extraction_history.strip()
        gleaning_response = gleaning_response.strip()
        history = f"""
        {extraction_history}
        Missed entities: {gleaning_response}
        """
        return [
            {"role": "system", "content": RepositoryGraphConfig.SYSTEM_PROMPT if not code_analysis else CodeAnalysisConfig.SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
            {"role": "assistant", "content": history},
            {"role": "user", "content": RepositoryGraphConfig.CONTINUE_PROMPT if not code_analysis else CodeAnalysisConfig.CONTINUE_PROMPT}
        ]

    @staticmethod
    def _get_gleaning_prompt(history: str, user_input: str, code_analysis : bool) -> List[Dict]:
        history = history.strip()
        user_input = user_input.strip()

        return [
            {"role": "system", "content": RepositoryGraphConfig.SYSTEM_PROMPT if not code_analysis else CodeAnalysisConfig.SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
            {"role": "assistant", "content": history},
            {"role": "user", "content": RepositoryGraphConfig.GLEARING_PROMPT if not code_analysis else CodeAnalysisConfig.GLEANING_PROMPT}
        ]

class KGConstructor:
    REQUEST_DELIMETER = "<<|README_DELIMITER|>>"
    COLUMN_DELIMITER = "<<|COLUMN_DELIMITER|>>"
    REPETITIVE_PATTERN_ERROR = "Sorry! We've encountered an issue with repetitive patterns in your prompt. Please try again with a different prompt."
    MAX_BATCH_SIZE = 1
    counter = 0

    def __init__(self, api: OpenAIAPI, cache_path: str, openai_batch: bool = False, code_analysis=False):
        self.api = api
        self.cache_path = cache_path
        self.openai_batch = openai_batch
        self.logger = logging.getLogger(__name__)
        self.code_analysis = code_analysis

    def create_repository_graph(self, attack_name: str, input_path: str , max_gleanings: int = 3, attack_description: str = None) -> None:
        # Step 1.2: Construct the repository graph
        output_path = os.getcwd() + "/output/step3/" + attack_name + "/repository_graph.csv"
        self._log_repo_graph(attack_name, input_path, output_path)
        column_name = "Repository Graph"
        column_to_analyze = "README Content"

        df = Util.prepare_dataframe(column_name, input_path, output_path)
        df[column_name] = df[column_name].astype(str) 
        cache_field = "Repository Graph Construction"
        self.batch_processor = StandardBatchProcessor(self.api, cache_field)

        system_msg = self._get_system_message(RepositoryGraphConfig.SYSTEM_PROMPT) 
        # TODO: Remove if version update prove to be inadequate  
        # system_msg = self._get_system_message(RepositoryGraphConfig.SYSTEM_PROMPT) 
        # system_msg['content'] = system_msg['content'][0]
        system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])

        response_format = None

        if "gpt-4" in self.api.model:
            response_format = REPO_GRAPH_RESPONSE_FORMAT # Set response schema for GPT-4
        else: 
            response_format = JSON_OBJECT # For others set response format to `json_object`

        model_params = self._get_model_params(response_format) 
        
        self._batch_process(cache_field, df, system_ms_token_length, self._get_repo_graph_construction_prompt_2, 
                            self._process_repo_graph_response, column_name, output_path, model_params, max_gleanings, column_to_analyze, attack_name, attack_description)
    
        return output_path
        

    def retrieve_main_functions(self, graph_data_path: str, attack_name: str, attack_desc: str,  max_gleanings: int = 1) -> None:
        self.logger.info(f"Retrieving main functions for attack: {attack_name}")
        output_path = os.getcwd() + "/output/step6/" + attack_name + "/main_functions.csv"
        veriication_path = os.getcwd() + "/output/step6/" + attack_name + "/ver_strategies.csv"

        ver_column_name = "Relevant"
        self._verify_strategies(graph_data_path, veriication_path, attack_name, attack_desc, ver_column_name)
        self.logger.info(f"Files verified {attack_name}")
        
        column_to_analyze = "README Content"
        verification_df = pd.read_csv(veriication_path)

        column_name = "Main file name"
        verification_df = Util.prepare_dataframe(column_name, veriication_path, output_path)
        df = verification_df[verification_df[ver_column_name] == "YES"] # ONLY retrieve main functions for RELEVANT strategies. 

        cache_field = "Main file name retrieval"
        self.batch_processor = StandardBatchProcessor(self.api, cache_field)

        system_msg = self._get_system_message(RepositoryGraphConfig.FILTER_PROMPT)
        system_msg['content'] = system_msg['content'][0]
        system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])

        if "gpt-4" in self.api.model:
            response_format =  MAIN_FILE_RESPONSE_FORMAT# Set response schema for GPT-4
        else: 
            response_format = JSON_OBJECT # For others set response format to `json_object`

        model_params = self._get_model_params(response_format)
        
        self._batch_process(cache_field, df, system_ms_token_length, self._get_retrieval_prompt, 
                            self._process_retrieval_response, column_name, output_path, model_params, max_gleanings, column_to_analyze)

        return output_path

    def _verify_strategies(self, input_file :str, output_path: str, attack_name: str, attack_description: str, column_name: str)->None:

        self.logger.info("Verifying the strategies extracted from the repository graph before retrieving main files.")

        column_to_analyze = "README Content"
        max_gleanings = 1

        df = Util.prepare_dataframe(column_name, input_file, output_path)
        df = df[df['Representing'] != -1] # Only retrieve strategies that are representing the attack
        cache_field = "Analysis of Strategies"
        self.batch_processor = StandardBatchProcessor(self.api, cache_field)

        system_msg = self._get_system_message(RepositoryGraphConfig.FILTER_PROMPT)
        system_msg['content'] = system_msg['content'][0]
        system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])
        self.indx = self._load_cache(cache_field)

        if "gpt-4" in self.api.model:
            response_format = RELEVANCE_RESPONSE_FORMAT # Set response schema for GPT-4
        else: 
            response_format = JSON_OBJECT # For others set response format to `json_object`

        model_params = self._get_model_params(response_format)
        
        self._batch_process(cache_field, df, system_ms_token_length, self._get_relenvance_prompt, 
                            self._process_relevance_response, column_name, output_path, model_params, max_gleanings, column_to_analyze, attack_name, attack_description, df["Name"].values, df["Description"].values)
        


    # def retrieve_main_functions(self, graph_data_path: str, output_path: str, attack_name: str, max_gleanings: int = 1) -> None:
    #     self.logger.info(f"Retrieving main functions for attack: {attack_name}")
    #     column_name = "Relevant"
    #     column_to_analyze = "README Content"

    #     df = Util.prepare_dataframe(column_name, graph_data_path, output_path)
    #     cache_field = "Main file name retrieval"
    #     self.batch_processor = StandardBatchProcessor(self.api, cache_field)

    #     system_msg = self._get_system_message(RepositoryGraphConfig.RELEVANCE_PROMPT)
    #     system_msg['content'] = system_msg['content'][0]
    #     system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])

    #     if "gpt-4" in self.api.model:
    #         response_format = RELEVANCE_RESPONSE_FORMAT # Set response schema for GPT-4
    #     else: 
    #         response_format = JSON_OBJECT # For others set response format to `json_object`


    #     model_params = self._get_model_params(response_format)
        
    #     self._batch_process(cache_field, df, system_ms_token_length, self._get_retrieval_prompt, 
    #                         self._process_retrieval_response, column_name, output_path, model_params, max_gleanings, column_to_analyze)
        
    # def analyze_code(self, graph_data_path: str, output_path: str, max_gleanings: int = 1) -> None:
    #     self.logger.info(f"Analyzing the code at the Code column from the graph data.")
    #     column_name = "Features"
    #     column_to_analyze = ["Repository Graph", "Code"]
    #     self.code_analysis = True

    #     df = Util.prepare_dataframe(column_name, graph_data_path, output_path)
    #     df.columns = df.columns.astype(str)
    #     cache_field = "Code Analysis"
    #     self.batch_processor = StandardBatchProcessor(self.api, cache_field)

    #     system_msg = self._get_system_message(CodeAnalysisConfig.SYSTEM_PROMPT)
    #     system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])

    #     model_params = self._get_model_params()
        
    #     self._batch_process(cache_field, df, system_ms_token_length, self._get_analysis_prompt, 
    #                         self._process_analysis_response, column_name, output_path, model_params, max_gleanings, column_to_analyze)
        

    def analyze_code(self, graph_data_path: str, attack_name: str, max_gleanings: int = 1) -> str:
        output_path = os.getcwd() + "/output/step6/" + attack_name + "/code_analysis.csv"
        self.logger.info(f"Analyzing the code at the Code column from the graph data.")
        column_name = "Features"
        column_to_analyze = ["Code"]
        self.code_analysis = True

        df = Util.prepare_dataframe(column_name, graph_data_path, output_path)
        # Remove NaN code rows 
        df = df[~pd.isna(df["Code"])]
        df.columns = df.columns.astype(str)
        
        cache_field = "Code Analysis"
        self.batch_processor = StandardBatchProcessor(self.api, cache_field)

        self.indx = self._load_cache(cache_field)

        system_msg = self._get_system_message(CodeAnalysisConfig.SYSTEM_PROMPT)
        system_ms_token_length = self.api.get_token_length_from_messages(self.api.model, [system_msg])


        if "gpt-4" in self.api.model:
            response_format = CODE_ANALYSIS_RESPONSE_FORMAT # Set response schema for GPT-4
        else: 
            response_format = JSON_OBJECT # For others set response format to `json_object`

        model_params = self._get_model_params(response_format)
        
        self._batch_process(cache_field, df, system_ms_token_length, self._get_analysis_prompt, 
                            self._process_analysis_response, column_name, output_path, model_params, max_gleanings, column_to_analyze, df["Name"].values, df["Description"].values, df["Code"].values)
        
        return output_path
        

    def _get_model_params(self, response_format: Optional[Dict]=None) -> ChatCompletionLLM:
        return ChatCompletionLLM(temperature=RepositoryGraphConfig.TEMPERATURE, 
                                 seed=RepositoryGraphConfig.SEED, 
                                 max_tokens=RepositoryGraphConfig.MAX_TOKENS, 
                                 top_p=RepositoryGraphConfig.TOP_P, 
                                 frequency_penalty=RepositoryGraphConfig.FREQUENCY_PENALTY, 
                                 presence_penalty=RepositoryGraphConfig.PRESENCE_PENALTY, 
                                 response_format=response_format
                                 )


    def _batch_process(self, cache_field: str, df: pd.DataFrame, system_ms_token_length: int, 
                    input_func: Callable, process_response_func: Callable, column_name: str, output_path: str,
                    model_params: ChatCompletionLLM, max_gleanings: int, column_to_analyze: Union[str, List[str]], *input_args) -> None:
        maximum_input_tokens = LLMConstants.LIMITS[self.api.model]["Input"] - 200
        start_index = self._load_cache(cache_field)
        
        self.logger.info(f"Starting the batch processing from index: {start_index}")

        batch, indices = [], []

        for index, row in tqdm(df.iloc[start_index:].iterrows(), total=len(df) - start_index):
            
            if isinstance(column_to_analyze, str):
                columns = [column_to_analyze]
            else:
                columns = column_to_analyze

            if any(column in df.columns and (pd.isna(row[column]) or row[column] == "[]" or row[column] == "") for column in columns):
                continue 

            # Concatenate content from all specified columns
            content = self.COLUMN_DELIMITER.join(row[column].strip() for column in columns if column in df.columns and not pd.isna(row[column]))
            content_token_length = self.api.get_token_length_from_text(self.api.model, content)

            if self._should_add_to_batch(batch, content_token_length, system_ms_token_length, maximum_input_tokens):
                batch.append((content_token_length, content))
                indices.append(index)
            else:
                if batch:
                    self._process_batch(batch, df, indices, model_params, input_func, process_response_func, 
                                        column_name, output_path, max_gleanings, input_args)
                    batch, indices = [], []

                # Split the content if it's too long
                if content_token_length + system_ms_token_length > maximum_input_tokens:
                    self._split_and_process_content(content, df, index, system_ms_token_length, maximum_input_tokens,
                                                model_params, input_func, process_response_func, column_name, output_path, 
                                                max_gleanings, input_args)
                else:
                    batch = [(content_token_length, content)]
                    indices = [index]

        if batch:
            self._process_batch(batch, df, indices, model_params, input_func, process_response_func, 
                                column_name, output_path, max_gleanings, input_args)

    def _split_and_process_content(self, content: str, df: pd.DataFrame, index: int, system_ms_token_length: int,
                                  maximum_input_tokens: int, model_params: ChatCompletionLLM, input_func: Callable,
                                  process_response_func: Callable, column_name: str,  output_path: str, max_gleanings: int,
                                  input_args: Tuple) -> None:
        splits = self._split_content(content, maximum_input_tokens - system_ms_token_length)
        for split in splits:
            split_token_length = self.api.get_token_length_from_text(self.api.model, split)
            batch = [(split_token_length, split)]
            self._process_batch(batch, df, [index], model_params, input_func, process_response_func,
                                column_name, output_path,max_gleanings, input_args)

    def _split_content(self, readme: str, max_tokens: int) -> List[str]:
        sentences = readme.split("\n")
        splits = []
        current_split = ""
        current_tokens = 0

        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue

            sentence_tokens = self.api.get_token_length_from_text(self.api.model, sentence)

            if sentence_tokens > max_tokens:
                # If a single sentence is too long, split it into smaller chunks
                if current_split:
                    splits.append(current_split)
                    current_split = ""
                    current_tokens = 0
                splits.extend(self._split_sentence(sentence, max_tokens))
            elif current_tokens + sentence_tokens > max_tokens:
                splits.append(current_split)
                current_split = sentence + "\n"
                current_tokens = sentence_tokens
            else:
                current_split += sentence + "\n"
                current_tokens += sentence_tokens

        if current_split:
            splits.append(current_split)

        return splits

    def _split_sentence(self, sentence: str, max_tokens: int) -> List[str]:
        words = sentence.split()
        splits = []
        current_split = ""
        current_tokens = 0

        for word in words:
            word_tokens = self.api.get_token_length_from_text(self.api.model, word + " ")
            if current_tokens + word_tokens > max_tokens:
                splits.append(current_split.strip())
                current_split = word + " "
                current_tokens = word_tokens
            else:
                current_split += word + " "
                current_tokens += word_tokens

        if current_split:
            splits.append(current_split.strip())

        return splits

    def _should_add_to_batch(self, batch: List[Tuple[int, str]], content_token_length: int, 
                             system_ms_token_length: int, maximum_input_tokens: int) -> bool:
        batch_token_length = sum(token for token, _ in batch)
        total_token_length = (batch_token_length + content_token_length + system_ms_token_length + 
                              LLMConstants.TOKEN_PER_MESSAGE)
        return total_token_length < maximum_input_tokens and len(batch) < self.MAX_BATCH_SIZE

    def _process_batch(self, batch: List[Tuple[int, str]], df: pd.DataFrame, indices: List[int], 
                       model_params: ChatCompletionLLM, input_func: Callable, 
                       process_response_func: Callable, column_name: str, output_path: str, 
                       max_gleanings: int, input_args: Tuple) -> None:
                
        self.batch_processor.process_batch(batch, df, indices, model_params, input_func, 
                                           process_response_func, column_name, output_path,max_gleanings, self.code_analysis, *input_args)

    def _load_cache(self, field: str="mine_readme")->int:
        index = 0
        logging.info("Loading the last processed index from the cache file.")
        
        if os.path.exists(self.cache_path):
            with open((self.cache_path), "r") as file:
                try: 
                    cache = json.load(file)

                    if cache and field in cache and cache[field]:
                        index = int(cache[field])
                    else:
                        logging.info(f"Cache is not found for {field}. Index will be set to 0.")
                        Util.write_cache(self.cache_path, field, 0)
                     
                except json.JSONDecodeError:
                    logging.info("Failed to load the cache file...new empty cache will be created.")
                    with open(self.cache_path, "w") as file:
                        json.dump({}, file)
        else:
            logging.info("Cache file not found...new empty cache will be created.")
            with open(self.cache_path, "w") as file:
                json.dump({}, file)
                
        logging.info(f"Last processed index: {index}")          
        return index

    def _get_repo_graph_construction_prompt(self, attack_name: str, readme: str) -> List[Dict]:
        user_message = f"""
        ######################
        INPUT
        ######################

        #### **Goal Attack:** {attack_name}

        #### **README.md Content:**
        {readme}
        """

        return [
            {"role": "system", "content": RepositoryGraphConfig.SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ]

    def _get_repo_graph_construction_prompt_2(self, attack_name: str, attack_description: str, readme: str) -> List[Dict]:
        user_message = f"""
        Attack Name: {attack_name}
        Description: {attack_description}
        README.md : ```{readme}```
        """

        return [
            {"role": "system", "content": RepositoryGraphConfig.SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ]   

    def _get_retrieval_prompt(self, readme:str) -> List[Dict]:
        user_message = f"""
        **README.md Content:```
        {readme}
        ```
        """

        return [
            {"role": "system", "content": RepositoryGraphConfig.FILTER_PROMPT},
            {"role": "user", "content": user_message}
        ]
    

    def _get_relenvance_prompt(self, attack_name: str, attack_description : List[str], strategy_names: List[str], strategy_descriptions: str, readme: str) -> List[Dict]:
        strategy_name = strategy_names[self.indx]
        strategy_description = strategy_descriptions[self.indx]
        self.indx += 1  
        user_message = f"""
        1. Attack Information:
        - Name: {attack_name}
        - Description: {attack_description}

        2. Extracted Strategy:
        - Name: {strategy_name}
        - Description: {strategy_description}

        3. Source Context:
        ```
        {readme}
        ```
        """

        return [
            {"role": "system", "content": RepositoryGraphConfig.RELEVANCE_PROMPT},
            {"role": "user", "content": user_message}
        ]
    

    def _get_analysis_prompt(self, names: str, descriptions: str, code: str, reamde: str) -> List[Dict]:
        """
        Get the user message for the code analysis.

        :param content: The content to analyze. Which is the Repository Graph content concatenated with the Code column content delimited by the COLUMN_DELIMITER.
        """

        name = names[self.indx]
        description = descriptions[self.indx]
        code = code[self.indx]

        user_message = f"""
        Strategy
        name: {name}
        description: {description}
        Implementation:
        ```code
       {code}
        ```
        """
        return [
            {"role": "system", "content": CodeAnalysisConfig.SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ]
    


    # def _get_analysis_prompt(self, content: str) -> List[Dict]:
    #     """
    #     Get the user message for the code analysis.

    #     :param content: The content to analyze. Which is the Repository Graph content concatenated with the Code column content delimited by the COLUMN_DELIMITER.
    #     """
    #     split_content = content.split(self.COLUMN_DELIMITER)
    #     code = split_content[1]
    #     json_object = split_content[0]
    #     format = "```"
    #     user_message = "## INPUT CODE: \n" + \
    #                     format + "code" +code + format + "\n" + \
    #                     "## INPUT JSON Array: \n" + \
    #                     format + "json" + json_object + format 
        
    #     return [
    #         {"role": "system", "content": CodeAnalysisConfig.SYSTEM_PROMPT},
    #         {"role": "user", "content": user_message}
    #     ]
    
    @staticmethod
    def _get_system_message(content: str) -> Dict:
        return {
            "role": "system",
            "content": content.strip()
        }


    def _process_repo_graph_response(self, cache_field: str,column_name: str, response: str, df: pd.DataFrame, index: int, output_path: str) -> None:
        self.logger.info(f"Repository graph extracted at the index: {index}.")
        Util.save(self.cache_path, cache_field, column_name, json.dumps(response), df, index, output_path)
    
    def _log_repo_graph(self, attack_name :str, input_path: str, output_path : str) -> None:
        self.logger.info(f"Creating repository graph for attack: {attack_name}")
        self.logger.info(f"Loading READMEs from: {input_path}")
        self.logger.info(f"Graphs will be store to the path : {output_path}")
    
    def _process_retrieval_response(self, cache_field: str, column_name: str, response: str, df: pd.DataFrame, index: int, output_path: str) -> None:
        self.logger.info(f"Main function retrieved at the index: {index}.")
        # response = json.loads(file_name)
        file_name = "" if response["file_found"] == "NO" else response["main_file_name"]

        Util.save(self.cache_path, cache_field, column_name, file_name, df, index, output_path)

    def _process_relevance_response(self, cache_field: str, column_name: str, response: str, df: pd.DataFrame, index: int, output_path: str) -> None:
        self.logger.info(f"Relevancy analyzed for index: {index}.")
        # response = json.loads(file_name)
        answer = response["answer"]

        Util.save(self.cache_path, cache_field, column_name, answer, df, index, output_path)
    
    def _process_analysis_response(self, cache_field: str, column_name: str, response: str, df: pd.DataFrame, index: int, output_path: str) -> None:
        self.logger.info(f"Code analysis completed at the index: {index}.")
        # features = json.loads(response)
        Util.save(self.cache_path, cache_field, column_name, json.dumps(response), df, index, output_path)