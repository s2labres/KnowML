"""
This schema strore response format for the LLM model. 
The schema ensure that LLM returns only the structured format. 

Ref: https://cookbook.openai.com/examples/structured_outputs_multi_agent
"""

REPO_GRAPH_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "strategies",
      "schema": {
        "type": "object",
        "required": [
          "strategies"
        ],
        "properties": {
          "strategies": {
            "type": "array",
            "items": {
              "type": "object",
              "required": [
                "name",
                "description"
              ],
              "properties": {
                "name": {
                  "type": "string",
                  "description": "The name of the strategy."
                },
                "description": {
                  "type": "string",
                  "description": "The description of the strategy."
                }
              },
              "additionalProperties": False, 
            },
            "description": "An array of strategy entities."
          }
        },
        "additionalProperties": False, 
      },
      "strict": True
    }
  }


GLEANING_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "response_schema",
      "schema": {
        "type": "object",
        "required": [
          "Answer",
          "Description"
        ],
        "properties": {
          "Answer": {
            "enum": [
              "YES",
              "NO"
            ],
            "type": "string",
            "description": "The allowed response indicating either affirmation or negation."
          },
          "Description": {
            "type": "string",
            "description": "If any items are missing (Answer is NO), give a brief explanation of omissions"
          }
        },
        "additionalProperties": False
      },
      "strict": True
    }
  }

MAIN_FILE_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "attack_execution",
      "strict": True,
      "schema": {
        "type": "object",
        "properties": {
          "main_file_name": {
            "type": "string",
            "description": "The name of the main file used to execute the attack."
          },
          "file_found": {
            "type": "string",
            "description": "Indicates whether the main file has been found or not.",
            "enum": [
              "YES",
              "NO"
            ]
          }
        },
        "required": [
          "main_file_name",
          "file_found"
        ],
        "additionalProperties": False
      }
    }
  }


RELEVANCE_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "entity_answer",
      "strict": True,
      "schema": {
        "type": "object",
        "properties": {
          "answer": {
            "type": "string",
            "enum": [
              "YES",
              "NO"
            ],
            "description": "Response indicating the relevance of the strategy."
          }
        },
        "required": [
          "answer"
        ],
        "additionalProperties": False
      }
    }
  }

JSON_OBJECT = {"type": "json_object"}


CODE_ANALYSIS_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "feature_schema",
      "schema": {
        "type": "object",
        "required": [
          "features"
        ],
        "properties": {
          "features": {
            "type": "array",
            "items": {
              "type": "object",
              "required": [
                "name",
                "description",
                "code",
                "rationale"
              ],
              "properties": {
                "code": {
                  "type": "string",
                  "description": "Relevant code section associated with the feature."
                },
                "name": {
                  "type": "string",
                  "description": "The name of the feature."
                },
                "rationale": {
                  "type": "string",
                  "description": "How this feature reflects the strategy."
                },
                "description": {
                  "type": "string",
                  "description": "What this feature measures."
                }
              },
              "additionalProperties": False
            },
            "description": "A list of features with their descriptive properties."
          }
        },
        "additionalProperties": False
      },
      "strict": True
    }
  }

CODE_ANALYSIS_GLEANING_RESPONSE_FORMAT ={
    "type": "json_schema",
    "json_schema": {
      "name": "schema_description",
      "schema": {
        "type": "object",
        "required": [
          "complete",
          "rationale"
        ],
        "properties": {
          "complete": {
            "enum": [
              "YES",
              "NO"
            ],
            "type": "string",
            "description": "Indicates whether the schema is complete"
          },
          "rationale": {
            "type": "string",
            "description": "A brief description of missing elements"
          }
        },
        "additionalProperties": False
      },
      "strict": True
    }
  }


CODE_ANALYSIS_GLEANING_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
      "name": "response",
      "strict": True,
      "schema": {
        "type": "object",
        "properties": {
          "Answer": {
            "type": "string",
            "description": "The answer indicating 1) YES - No features entities or 2) No - Missing features identified."
          },
          "Description": {
            "type": "string",
            "description": "A brief description of the missing elements."
          }
        },
        "required": [
          "Answer",
          "Description"
        ],
        "additionalProperties": False
      }
    }
  }