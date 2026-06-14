"""
This module includes constants for the strategy miner such as the system messages to guide the Knowledge Graph construction process.
"""

class LLMConstants: 
    
    LIMITS = {
    # Ref: https://platform.openai.com/docs/guides/embeddings/embedding-models
    "text-embedding-3-large": {
        "Input": 8191, # Maximum input tokens
        "Output": 3072 # Length output embedding vector
    }, 
    "text-embedding-3-small": {
        "Input": 8191, # Maximum input tokens
        "Output": 1536 # Length output embedding vector
    },
    # Ref: https://platform.openai.com/docs/models/gpt-3-5-turbo
    "gpt-3.5-turbo-0125": {
        "Context Window": 16385, # Maximum context window
        "Input": 12289, # Maximum input tokens (Context Window - Prompt)
        "Ouput": 4096, # Maximum input tokens
    }, 
    # Ref: https://platform.openai.com/docs/models/gpt-4
    "gpt-4o": {
        "Context Window": 8192, # Maximum context window
        "Input": 4096, # Maximum input tokens (Context Window - Prompt)
        "Ouput": 4096, # Maximum input tokens
    }, 
    # Ref: https://platform.openai.com/docs/models/gpt-3-5-turbo
    "gpt-3.5-turbo-1106": {
        "Context Window": 16385, # Maximum context window
        "Input": 12289, # Maximum input tokens (Context Window - Prompt)
        "Ouput": 4096, # Maximum input tokens
    }, 
    # Ref: https://platform.openai.com/docs/models/gpt-4o-mini
    "gpt-4o-mini": {
        "Context Window": 128000, # Maximum context window
        "Input": 123904, # Maximum input tokens (Context Window - Prompt)
        "Ouput": 16384, # Maximum input tokens
    }
}

    API_URLs = {
        "chat-completion": "https://api.openai.com/v1/chat/completions",
        "text-embedding": "https://api.openai.com/v1/embeddings",
    }

    DEFAULT_CONTENT_TYPE = "application/json"

    BILLING_TOKEN_UNIT = 1000000 # Unit of tokens per pricing

    # Unit of pricing per input in USD
    COST = {
        "text-embedding-3-large": {
            "Input": 0.13
        }, 
        "text-embedding-3-small": {
            "Input": 0.02
        }, 
        "gpt-3.5-turbo-0125": {
            "Input": 0.5, 
            "Output": 1.5 
        }, 
        "gpt-4o": {
            "Input": 2.5, 
            "Output": 10.0 
        }, 
        "gpt-3.5-turbo-1106": {
            "Input": 1.0, 
            "Output": 2.0,
        }, 
        "gpt-4o-mini": {
            "Input": 0.3, 
            "Output": 1.2,
        },
        "gpt-3.5-turbo": {
            "Input": 3, 
            "Output": 6
        }, 
    }

    BATCH_API_DISCOUNT = 0.5 

    MODELS = ["text-embedding-3-large", "gpt-3.5-turbo-0125", "text-embedding-3-small", "gpt-4o", "gpt-3.5-turbo-1106", "gpt-4o-mini", "gpt-3.5-turbo"]

    # Rate limit for the API
    # Note: Rate limits can be hit across any of the options depending on what occurs first
    # Ref: https://platform.openai.com/docs/guides/rate-limits/rate-limits
    # 1. RPM - Request per minute
    # 2. RPD - Request per day
    # 3. TPM - Tokens per minute
    # 4. TPD - Tokens per day
    # 5. IPM - Images per minute

    WAIT_UNIT = 60 # Seconds 

    MODEL_LIMITS = { # Limits for real-time model response
        "gpt-4o-mini": {
            "RPM" : 500, 
            "TPM": 	200000  
        }, 
        "gpt-4": {
            "RPM" : 500, 
            "TPM": 30000
        }, 
        "gpt-3.5-turbo-0125": {
            "RPM" : 3500, 
            "TPM": 	2000000  
        }, 
    }

    BATCH_RATE_LIMITS = {
        "gpt-3.5-turbo-0125" : {
            "TPD" : 2000000
        },
        "gpt-4o-mini": {
            "TPD" : 2000000
        }, 
        "gpt-4": {
            "TPD" : 90000
        }, 
        "text-embedding-3-small": {
            "TPD" : 3000000
        }
    }

    DEFUALT_RESPONSE_FORMAT = "json_object"
    EMBEDDING_RESPONSE_FORMAT = "float"

    TOKEN_PER_MESSAGE = 3
    TOKEN_PER_NAME = 1

    BATCH_FORMAT = "jsonl"

    # Permitted BATCH models
    BATCH_MODELS = [
    "gpt-4o",
    "gpt-4o-2024-08-06",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    "gpt-4-32k",
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-16k",
    "gpt-4-turbo-preview",
    "gpt-4-vision-preview",
    "gpt-4-turbo-2024-04-09",
    "gpt-4-0314",
    "gpt-4-32k-0314",
    "gpt-4-32k-0613",
    "gpt-3.5-turbo-0301",
    "gpt-3.5-turbo-16k-0613",
    "gpt-3.5-turbo-1106",
    "gpt-3.5-turbo-0613",
    "text-embedding-3-large",
    "text-embedding-3-small",
    "text-embedding-ada-002"
    ]

    JSON_OBJECT = {"type": "json_object"}