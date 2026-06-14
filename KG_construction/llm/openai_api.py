import logging
import tiktoken
import os
from llm.constants import LLMConstants
from dotenv import load_dotenv
from openai import OpenAI
import requests
import time
import math
import httpx
from  openai.types.chat.chat_completion import ChatCompletion
import traceback
import sys
from openai.types import Batch
from typing import Tuple, List
from llm.types import ChatCompletionLLM

parent_dir = os.path.dirname(os.getcwd())
sys.path.append(parent_dir)

from util import Util

class OpenAIAPI:
    _UNINITIALIZED = -1
    
# Initialization
    def __init__(self, model: str="gpt-3.5-turbo-0125", ex_ouput_tokens: int=None)->None:
        """
        Initialize the OpenAI API.

        :param model: The model to use for the API. For available models, please refer to LLMConstants.MODELS.
        :param ex_output_tokens: The expected output tokens for the model.
        """
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initializing OpenAI API with model: {model}")

        # Load the API key from the environment
        load_dotenv()
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        #self.client = OpenAI(api_key="Test what is returned with incorrect key")

        self._init_model(model)
        self._init_costs()
        self._init_limits(model)

        # Variables for throttling requests
        self.remaining_tokens = OpenAIAPI._UNINITIALIZED
        self.token_reset_time = OpenAIAPI._UNINITIALIZED
        self.remaining_requests = OpenAIAPI._UNINITIALIZED
        self.request_reset_time = OpenAIAPI._UNINITIALIZED
        self.start_time = OpenAIAPI._UNINITIALIZED
        self.total_tokens_send = 0
        self.total_reqeust_send = 0

        self.exp_output_tokens = ex_ouput_tokens
        
    
    def _init_limits(self, model: str )->None:
        """
        Initialize the input token limits for the model.
        """

        if self.model not in LLMConstants.LIMITS or "Input" not in LLMConstants.LIMITS[self.model]:
            logging.error(f"No input token limit found for model: {model}. Please check the LLMConstants.")
            return
        self.input_token_budget = LLMConstants.LIMITS[self.model]["Input"]
    
    def _init_costs(self)->None:
        """
        Initialize the input and output costs for the model.
        """
        self.input_cost_per_unit = LLMConstants.COST[self.model]["Input"]
        self.output_cost_per_unit = None if "Output" not in LLMConstants.COST[self.model] else LLMConstants.COST[self.model]["Output"]

    def _init_model(self, model)->None: 
        """
        Initialize the model for the API.
        """
        if not self._is_valid_model(model):
            logging.error(f"Invalid model: {model}. Please use one of the following models: {LLMConstants.MODELS}")
            raise ValueError(f"Invalid model: {model}. Please use one of the following models: {LLMConstants.MODELS}")
        else: 
            self.model = model

            if "gpt" in model:
                self.expected_usage_ratio = 0.33 # Default expected token usage for input and output - 3:1 ratio
            elif "text-embedding" in model:
                self.expected_usage_ratio = 0
    
# Public functions     

    QUICK_FIX_TOBE_REMOVED = "# Attack Strategy Entity Extraction Instructions\nYou are an assistant designed for the Named Entity Recognition tasks.\n\n\n## Context\nYou are investigating how attacks can mutate through different configurations. Each parameter or argument that controls attack execution represents a potential strategy that an attacker could use to modify the attack's behaviour. Your goal is to map this attack mutation space by identifying these strategic options.\n\n## Core Understanding\nA strategy entity is any parameter or argument that represents a choice an attacker can make to modify attack behaviour. These choices shape how the attack manifests and operates. Strategy entities that indicate how the attack's effectiveness is measured.\n\n## Primary Task\nIdentify how an attacker could vary their attack approach by examining all parameters and arguments that:\n- Modify attack behaviour\n- Create variations in attack execution\n- Represent strategic choices in attack configuration\n- Measure attack effectiveness \n\n## Key Principles\n- Every parameter that allows attack variation represents a potential strategy\n- Each configuration option could enable a different attack mutation\n- Parameters are the mechanisms through which strategies manifest\n- Measurement parameters reveal attack objectives\n\n## Critical Requirements\n- Parameters must be explicitly documented\n- Must influence attack behaviour or measurement\n- Must represent actual strategic choices\n\n## Input Format\n```\nAttack Name: <name of the goal attack>\nDescription: <description of the attack>\nREADME.md: ```<content>```\n```\n\n## Response Format\n```json \n\n {\"strategies\": [\n{name: <name_of_strategy>}, \n{description: <description_of_strateg>}\n]\n}\n```\n\n## Important Note\n* Return NOTHING if the README lacks specific execution instructions. Only return strategy entities described above LEAVE OUT anything that describes help, logging, version settings and others that are UNRELEVANT.\n* Sometimes, the provided README.md file doesn't describe the attack given in `Attack Name` and  `Description inputs  in this case returns an EMPTY response"
    def send_chat_completion_request(self, 
                                    messages: list[dict[str, str]], 
                                    model_params: ChatCompletionLLM,
                                    log_cost=True) -> Tuple: # TODO: Add the return type
        """
        Send a chat completion request to the OpenAI API.
        Note: Assume that the input message does not exceed the context window.

        :param messages: The messages to send in the request.
        :param model_params: Parameters for the chat completion.
        :param log_cost: If True, then log the cost of the request.
        :return: A tuple of string containing the response content, a http request, and a http response.
        """
        if "text-embedding" in self.model:
            logging.error("Chat completion is not supported for text-embedding models. Use one of the gpt series models.")
            return None
        
        try:
            if model_params.response_format is not None:
                self.throttle_request(messages=messages)

            # Start with required parameters
            api_params = {
                "model": self.model,
                "messages": messages
            }
            raw_response = None
            # Add optional parameters if they are not None
            if model_params.temperature is not None:
                api_params["temperature"] = model_params.temperature
            if model_params.seed is not None:
                api_params["seed"] = model_params.seed
            if model_params.logit_bias is not None:
                api_params["logit_bias"] = model_params.logit_bias
            if model_params.max_tokens is not None:
                api_params["max_tokens"] = model_params.max_tokens
            if model_params.top_p is not None:
                api_params["top_p"] = model_params.top_p
            if model_params.frequency_penalty is not None:
                api_params["frequency_penalty"] = model_params.frequency_penalty
            if model_params.presence_penalty is not None:
                api_params["presence_penalty"] = model_params.presence_penalty
            if model_params.response_format is not None:
                if "gpt-4" not in self.model and model_params.response_format != LLMConstants.JSON_OBJECT:
                    raise Exception("Response format is only supported for gpt-4 models.")
                api_params["response_format"] = model_params.response_format

            if model_params.response_format is not None:

                # QUICK FIX, need to be removed it seemd like the system prompt is not formulated correctly (Additional unwanted spaces and \ hence we hard-coded the system prompt)
                # TODO: Find a root cau  se and fix it 
                api_params['messages'][0]['content'] = api_params['messages'][0]['content'].strip()
                
                if self.start_time == OpenAIAPI._UNINITIALIZED:
                    self.start_time = time.time()
                response = self.client.chat.completions.create(**api_params)

                # Account number tokens send and number of requests send
                self.total_reqeust_send += 1
                used_tokens = OpenAIAPI.get_token_length_from_messages(self.model, messages)
                self.total_tokens_send += used_tokens

                self._set_throttle_custom()
                return response, None, None
            else:
                
                raw_response = self.client.chat.completions.with_raw_response.create(**api_params)
                
                http_request = raw_response.http_request.content.decode('utf-8')
                http_response = raw_response.http_response.content.decode('utf-8')
                
                if raw_response.status_code != 200:
                    logging.error(f"Error sending chat completion request. Code: {raw_response.status_code}. \n"
                                f"Request: {http_request}"
                                f"Response: {http_response}")
                    
                    return None, http_request, http_response
                
                response = raw_response.parse()
                headers = raw_response.headers
                self._set_throttle_vars(headers)
                
                if log_cost:
                    self._log_cost(response)
                
                return response, http_request, http_response
        except Exception as e:
            # The expected error type is <class 'openai.BadRequestError'>
            logging.error(f"Error sending chat completion request. Code: {e.status_code}. \n"
                        f"The error occurred for parameters {e.param} with message: {e.message}.\n"
                        f"Request sent: {e.request.content.decode('utf-8')}")
            return None, None, e.message
        
    
    def send_text_embedding_request(self, text: str,log_cost=True)->List[float]:
        """
        Send a text embedding request to the OpenAI API.
        Note: Assume that the input message does not exceed the context window.

        :param text: The text to send in the request.
        :param log_cost: If True, then log the cost of the request.
        :return: A tuple of string containing the response content, a http request, and a http response.
        """

        if "text-embedding" not in self.model:
            logging.error("Text embedding is not supported for chat completion models. Use one of the text-embedding models.")
            return None
        
        try:
            self.throttle_request(text=text)

            raw_response = self.client.embeddings.with_raw_response.create(
                model=self.model,
                input=text,
                encoding_format= LLMConstants.EMBEDDING_RESPONSE_FORMAT
            )

            http_request = raw_response.http_request.content.decode('utf-8')
            http_response = raw_response.http_response.content.decode('utf-8')

            if raw_response.status_code != 200:
                logging.error(f"Error sending text embedding request. Code: {response.status_code}. \n"
                              f"Request: {http_request}"
                              f"Response: {http_response}")
                return None

            response = raw_response.parse()
            headers = raw_response.headers
            self._set_throttle_vars(headers)

            if log_cost:
                self._log_cost(response)

            return response
        except Exception as e:
            e = traceback.format_exc()
            logging.error(f"Error sending text embedding request. Error: {e}")

    def send_post_request(self, url: str, data: dir, headers: dir=None)->dict:
        """
        Send a POST request to the OpenAI API.

        :param url: The URL to send the request.
        :param data: The data to send in the request.
        :param headers: The headers to send in the request.
        :return: The response from the request.
        """
        
        self.throttle_request(data)

        if headers is None:
            headers = self.headers
        response = requests.post(url, data=data, headers=headers)

        if response.status_code != 200:
            logging.error(f"Error sending POST request to {url}. Code {response.status_code}. \n"
                          f"Response: {response.text}")
            return None
        
        self._set_throttle_vars(response)

        return response.json()

    def get_cost_from_messages(self, messages: list[dict[str, str]], digits=5, log_cost=True)->float:
        """
        Get the cost of the input messages.

        :param messages: The messages to get the cost.
        :return: The cost of the messages in USD.
        :param digits: The number of digits to round the cost.
        """
        num_tokens = OpenAIAPI.get_token_length_from_messages(self.model, messages)
        input_cost = round(self._get_input_cost(num_tokens), digits)

        if log_cost:
            logging.info("The total cost of the messages is: {input_cost} USD. \n")

        return input_cost

    def get_cost(self, input: str, output: str, digits=5, log_cost: bool=True)->float: 
        """
        Get the cost of the request.
        Please note that this is an estimate and the actual cost may vary due to additional tokens incurred
        during formatting a request. 

        :param input: The input text.
        :param log_cost: If True, then log the cost of the request.
        :param output: The output text.
        :return: The cost of the request in USD.
        """
   
        input_tokens = OpenAIAPI.get_token_length_from_text(input)
        output_tokens = OpenAIAPI.get_token_length_from_text(output)

        input_cost = self._get_input_cost(input_tokens)
        output_cost = self._get_output_cost(output_tokens)

        total_cost = input_cost + output_cost
        if log_cost:
            logging.info(f"\n\tTotal string length: {len(input) + len(output)}  \n"
                        f"\tTotal tokens: {input_tokens + output_tokens}. \n"
                        f"\tTotal cost of the request is: {total_cost} USD. \n")

        return round(total_cost, digits)
    
    # Source of the function:https://platform.openai.com/docs/guides/batch/getting-started
    def send_batch_request(self, file_path: str, endpoint: str)->Batch:
        """
        Send request file to batch processing.

        :param file_path: The path to the request file to send. Must be a .jsonl file.
        :param endpoint: The endpoint to send the request to. Must be one of the following: ["/v1/chat/completions", "/v1/embeddings"]

        :return: The batch object.

        Developer Note: 
            1. Handle rate limit per day outside of the function -> Split the file into multiple files and send them separately.
            2. Calculate the cost of the batch request. The cost is original price per unit * LLMConstants.BATCH_API_DISCOUNT
            3. Ensure that model used in the request is in the LLMConstants.BATCH_MODELS
            4. Store batch ID in cache to retrieve the results later.
        """
        self._validate_batch_param(file_path, endpoint)
        
        
        # Upload the batch file
        batch_input_file = self.client.files.create(
        file=open(file_path, "rb"),
        purpose="batch"
        )

        # Create the batch job
        batch_input_file_id = batch_input_file.id

        batch_object = self.client.batches.create(
            input_file_id=batch_input_file_id,
            endpoint="/v1/chat/completions",
            completion_window="24h",
            metadata={
            "description": "nightly eval job"
            }
        )

        logging.info(f"Batch job created with ID: {batch_object.id}")

        return batch_object

    def get_batch_status(self, batch_id: str)-> Tuple[str, str]:
        """
        Get the status of the batch request.

        :param batch_id: The ID of the batch request.
        :return: The status of the batch request and the file ID of the output file if the status is "completed", otherwise None.
        """
        batch_object = self.client.batches.retrieve(batch_id)

        file_id = None if batch_object.status != "completed" else batch_object.error_file_id

        return batch_object.status, file_id


    def retrieve_batch_results(self, batch_id: str)->str: 
        """
        Retrieve the results of the batch request.

        :param batch_id: The ID of the batch request.
        :return: The results of the batch request in jsonl format.

        Developer Note: The output line order may not match the input line order.
        """
        status, file_id = self.get_batch_status(batch_id)

        if status != "completed":
            logging.error(f"Batch job with ID: {batch_id} is not completed. The status is: {status}.")
            return None
        
        file_response = self.client.files.content(file_id)
        
        return file_response.text
    
    def cancel_batch(self, batch_id: str)->bool:
        """
        Cancel the batch request with the given ID.

        :param batch_id: The ID of the batch request.
        :return: True if the batch request is cancelled or scheduled to be cancelled, otherwise False.
        """
        batch_object = self.client.batches.cancel(batch_id)

        if batch_object.status != "cancelled" or batch_object.status != "cancelling":
            logging.error(f"Batch job with ID: {batch_id} could not be cancelled. The status is: {batch_object.status}.")
            return False

        return True

    @staticmethod
    def get_token_length_from_text(model: str, text: str)->int:
        """
        Get the token length of the text.

        :param text: The text to get the token length.
        :return: The token length of the text.
        """

        # Get the encoding for the model
        if model not in LLMConstants.MODELS:
            raise ValueError(f"Model: {model} is not supported. Please use one of the following models: {LLMConstants.MODELS}")
        encoding = tiktoken.encoding_for_model(model)

        return len(encoding.encode(text))
    
    @staticmethod
    def get_token_length_from_messages(model: str, messages: List[dict[str, str]])->int:
        """
        Get the token length of the messages. 
        Note: Chat completetion models are assumed to be gpt-4 or gpt-3.5-turbo series.

        : param model: The model to get the token length.
        :param messages: The messages to get the token length.
        :return: The token length of the messages.
        """

        encoding = tiktoken.encoding_for_model(model)

        tokens_per_message = 0
        tokens_per_name = 0
        if "gpt-4" in model or "gpt-3.5-turbo" in model:
            tokens_per_message = LLMConstants.TOKEN_PER_MESSAGE
            tokens_per_name = LLMConstants.TOKEN_PER_NAME
        else:
            raise ValueError(f"Model: {model} is not supported for chat completion. \
                             Please use one of the following models series: gpt-4, gpt-3.5-turbo")

        num_tokens = 0     
        for message in messages:
            num_tokens += tokens_per_message
            for key, value in message.items():
                num_tokens += len(encoding.encode(value))
                if key == "name":
                    num_tokens += tokens_per_name
        num_tokens += 3  # every reply is primed with <|start|>assistant<|message|>
        return num_tokens

    @property
    def headers(self):
        """
        Get default headers for call 
        """
        return {
            f"Content-Type: {LLMConstants.DEFAULT_CONTENT_TYPE}",
            f"Authorization: Bearer: {self.api_key} "
        }
    
    def set_model(self, model: str)->None:
        self.model = model
            

    def throttle_request(self, messages: List[dict[str, str]]=None, text: str=None)->None:
        """
        Throttle the request based on the last response.

        :param messages: The messages to be sent in the request.
        """

        if messages is None and text is None:
            logging.error("No messages or text provided for throttling request to check the remaining token limit.")
            raise ValueError("No messages or text provided for throttling request.")
            
        time_elapsed = 0

        if self.remaining_requests == 0: 
            sleep_time = self._extract_sleep_time(self.request_reset_time)
            logging.info(f"Rate limit  for request per minute reached. Waiting for the next window....{sleep_time}.")
            time.sleep(sleep_time)
            time_elapsed += sleep_time
        if self.remaining_tokens == 0:
            sleep_time = self._extract_sleep_time(self.token_reset_time)
            if time_elapsed < sleep_time: 
                logging.info(f"Rate limit per minute reached. Waiting for the next window....{sleep_time}s.")
                sleep_time -= time_elapsed
                time.sleep(sleep_time)
                time_elapsed += sleep_time
        
        # Check if remaining tokens are sufficient to complete the request
        request_token_length =  OpenAIAPI.get_token_length_from_messages(self.model, messages) \
                                if text is  None else self.get_token_length_from_text(self.model, text) + LLMConstants.TOKEN_PER_MESSAGE
        # Assume that input is 3 times the output
        expected_token_usage = request_token_length + (self.exp_output_tokens if self.exp_output_tokens is not None else math.ceil(request_token_length * self.expected_usage_ratio))

        if self.remaining_tokens != -1 and self.remaining_tokens < expected_token_usage:
            logging.info(f"Insufficient tokens to complete the request. \n"
                         f"Remaining tokens: {self.remaining_tokens}. \n"
                         f"Expected token usage: {expected_token_usage}. \n"
                         f"Waiting for the next window...{self.token_reset_time}.")
            
            time.sleep(self._extract_sleep_time(self.token_reset_time))

# Private functions
    def _validate_batch_param(self,file_path: str, endpoint: str)->None:
        """
        Validate the parameters for the batch request.
        """
        if not os.path.exists(file_path):
            logging.error(f"File {file_path} does not exist.")
            raise ValueError(f"File {file_path} does not exist.")
        if not file_path.endswith(".jsonl"):
            logging.error(f"File {file_path} is not a .jsonl file.")
            raise ValueError(f"File {file_path} is not a .jsonl file.")
        
        if endpoint not in ["/v1/chat/completions", "/v1/embeddings"]:
            logging.error(f"Endpoint {endpoint} is not supported. Please use one of the following endpoints: {LLMConstants.API_URLs.keys()}")
            raise ValueError(f"Endpoint {endpoint} is not supported. Please use one of the following endpoints: {LLMConstants.API_URLs.keys()}")
    
    def _set_throttle_vars(self, headers: httpx.Headers)->None:
        """
        Helper function to set the throttle variables.
        """
        self.remaining_requests = int(headers["x-ratelimit-remaining-requests"])
        self.request_reset_time = headers["x-ratelimit-reset-requests"]
        if "x-ratelimit-remaining-tokens" in headers:
            self.remaining_tokens = int(headers["x-ratelimit-remaining-tokens"])
        # TODO: Add logic to handle rest time for epoch time 
        if "x-ratelimit-reset-tokens" in headers:
            self.token_reset_time = headers["x-ratelimit-reset-tokens"]


    def _set_throttle_custom(self)->None:
        """
        Set a throttle limit for request based on the User Tier. 
        Note that some response doesn't return the remaining tokens and request statistics. 
        Hence, this function throttle the request based on the API specified limit of User Tier. 
        """
        current_time = time.time()


        if self.start_time != OpenAIAPI._UNINITIALIZED and current_time - self.start_time > LLMConstants.WAIT_UNIT:
            
            if self.total_tokens_send > LLMConstants.MODEL_LIMITS[self.model]["TPM"] or \
                self.total_reqeust_send > LLMConstants.MODEL_LIMITS[self.model]["RPM"]:
                logging.info(f"Rate limit for the model reached. Waiting for the next window...{self.token_reset_time}.")

                time.sleep(LLMConstants.WAIT_UNIT) # Throttle the request
                self.start_time = current_time

            # Zero the throttle variables            
            self.total_tokens_send = 0
            self.total_reqeust_send = 0


    def _is_valid_model(self, model: str)->bool:
        """
        Check if the model is valid.
        """
        return model in LLMConstants.MODELS
    
    def _get_input_cost(self, input_tokens: int)->float:
        """
        Get the cost of the input tokens.
        """
        return (input_tokens / LLMConstants.BILLING_TOKEN_UNIT) * self.input_cost_per_unit
    
    def _get_output_cost(self, output_tokens: int)->float:
        """
        Get the cost of the output tokens.
        """
        return  (output_tokens / LLMConstants.BILLING_TOKEN_UNIT) \
            * self.output_cost_per_unit if self.output_cost_per_unit is not None else 0
    
    def _extract_sleep_time(self, time : str)->int:
        """
        Extract the sleep time in seconds from the response headers for rate limiting.
        """
        hours = 0
        minutes = 0
        seconds = 0
        miliseconds = 0

        acc = ""

        for char in time: 
            if char.isdigit():
                acc += char
            else: 
                if "h" in char:
                    hours = int(acc)
                elif "m" in char:
                    minutes = int(acc)
                elif "s" in char:
                    seconds = int(acc)
                elif "ms" in char:
                    miliseconds = int(acc)
                acc = ""
        
        sleep_time = hours * 3600 + minutes * 60 + seconds + (miliseconds / 1000)

        return sleep_time

    def _log_cost(self, response: ChatCompletion)->None: 
        """
        Helper function to log the cost of the request.
        """
        total_cost = 0
        if "gpt" in self.model:
            prompt_tokens = response.usage.prompt_tokens
            completion_tokens =  response.usage.completion_tokens
            input_cost = self._get_input_cost(prompt_tokens)
            output_cost = self._get_output_cost(completion_tokens)
            total_cost = input_cost + output_cost
        else:
            prompt_tokens = response.usage.prompt_tokens
            total_cost = self._get_input_cost(prompt_tokens)

        logging.info(f"The total cost of the request is: {total_cost} USD. \n")

# Testing
if __name__ == "__main__":
    api = OpenAIAPI()
    # print(api.get_cost("Hello, my name is", "What is your name?"))

    strategy = "time | Duration of the execution of the attack in seconds"

    ntoken = api.get_token_length_from_text("text-embedding-3-small", strategy)

    print(ntoken)