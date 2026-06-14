"""
This module defines the response model KG contruction that is going to be parsed to the JOSON object

Note: DON"T USE RESPONSE FORMAT FOR OPENAI API, YOU CANNOT THROLTTLE THE LIMIT WITH BETA.PARSE
"""


from pydantic import BaseModel
from typing import List, Literal

class Strategy(BaseModel):
    type: Literal["strategy"]
    name: str
    description: str

class Relationship(BaseModel):
    type: Literal["relationship"]
    source: str
    target: str
    description: str

class Entity(BaseModel):
    type: Literal["entity"]
    name: str
    description: str

class Relation(BaseModel):
    type: Literal["relation"]
    source: str
    target: str
    relation: str
    description: str

class AttackStrategyExtraction(BaseModel):
    extracted_items: List[Strategy | Relationship | Entity | Relation]


Repo_KG_response = {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_strategy_extraction",
            "schema": {
                "type": "object",
                "properties": {
                    "extracted_items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "explanation": {"type": "string"},
                                "output": {
                                    "type": "object",
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "properties": {
                                                "type": {"const": "strategy"},
                                                "name": {"type": "string"},
                                                "description": {"type": "string"}
                                            },
                                            "required": ["type", "name", "description"],
                                            "additionalProperties": False
                                        },
                                        {
                                            "type": "object",
                                            "properties": {
                                                "type": {"const": "relationship"},
                                                "source": {"type": "string"},
                                                "target": {"type": "string"},
                                                "description": {"type": "string"}
                                            },
                                            "required": ["type", "source", "target", "description"],
                                            "additionalProperties": False
                                        },
                                        {
                                            "type": "object",
                                            "properties": {
                                                "type": {"const": "entity"},
                                                "name": {"type": "string"},
                                                "description": {"type": "string"}
                                            },
                                            "required": ["type", "name", "description"],
                                            "additionalProperties": False
                                        },
                                        {
                                            "type": "object",
                                            "properties": {
                                                "type": {"const": "relation"},
                                                "source": {"type": "string"},
                                                "target": {"type": "string"},
                                                "relation": {"type": "string"},
                                                "description": {"type": "string"}
                                            },
                                            "required": ["type", "source", "target", "relation", "description"],
                                            "additionalProperties": False
                                        }
                                    ]
                                }
                            },
                            "required": ["explanation", "output"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["extracted_items"],
                "additionalProperties": False
            },
            "strict": True
        }
    }