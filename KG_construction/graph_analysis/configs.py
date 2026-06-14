from llm.types import ChatCompletionLLM
class GraphAnalysisConfig:
    model = "text-embedding-3-small"

    LABELLING_LLM = ChatCompletionLLM(
        temperature=0,
        max_tokens=16384,
        top_p=0,
        frequency_penalty=0,
        presence_penalty=0,
        model="gpt-4o"
    )