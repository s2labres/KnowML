from typing import Dict, Optional

class ChatCompletionLLM: 
    """
    A class to represent a LLM chat completion model configurations.
    """
    def __init__(self, temperature :int=None, seed :int=None, logit_bias :Dict[int, int]=None, max_tokens :int=None, top_p :int=None, frequency_penalty :int=None, presence_penalty :int=None, model :str=None, response_format :Optional[Dict]=None):

        self.temperature = temperature
        self.seed = seed
        self.logit_bias = logit_bias
        self.max_tokens = max_tokens
        self.top_p = top_p
        self.frequency_penalty = 0
        self.presence_penalty = 0
        self.model = model 
        self.response_format = response_format
        