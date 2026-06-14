
# Configuration  for the KG construction pipeline for the FILTERING task
class RepositoryGraphConfig: 
    TEMPERATURE = 0
    SEED = 0
    MAX_BATCH_SIZE = 1 # Maximum number of readme files to process in a single batch, it was tested that any request with more than 1 readme files will not be processed by the model
    REQUEST_DELIMETER = "<<|README_DELIMITER|>>"
    MAX_TOKENS = 16384
    # MAX_TOKENS = 4095
    TOP_P = 0
    FREQUENCY_PENALTY = 0


    # GPT-3.5 Prompt
    SYSTEM_PROMPT = """
    # Attack Strategy Entity Extraction Instructions\nYou are an assistant designed for the Named Entity Recognition tasks.\n\n\n## Context\nYou are investigating how attacks can mutate through different configurations. Each parameter or argument that controls attack execution represents a potential strategy that an attacker could use to modify the attack's behaviour. Your goal is to map this attack mutation space by identifying these strategic options.\n\n## Core Understanding\nA strategy entity is any parameter or argument that represents a choice an attacker can make to modify attack behaviour. These choices shape how the attack manifests and operates. Strategy entities that indicate how the attack's effectiveness is measured.\n\n## Primary Task\nIdentify how an attacker could vary their attack approach by examining all parameters and arguments that:\n- Modify attack behaviour\n- Create variations in attack execution\n- Represent strategic choices in attack configuration\n- Measure attack effectiveness \n\n## Key Principles\n- Every parameter that allows attack variation represents a potential strategy\n- Each configuration option could enable a different attack mutation\n- Parameters are the mechanisms through which strategies manifest\n- Measurement parameters reveal attack objectives\n\n## Critical Requirements\n- Parameters must be explicitly documented\n- Must influence attack behaviour or measurement\n- Must represent actual strategic choices\n\n## Input Format\n```\nAttack Name: <name of the goal attack>\nDescription: <description of the attack>\nREADME.md: ```<content>```\n```\n\n## Response Format\n```json \n{\n  \"strategies\": [\n    {\n      \"name\": \"<name_of_strategy>\",\n      \"description\": \"<description_of_strategy>\"\n    }\n  ]\n}\n```\n\n## Important Note\n* Return NOTHING if the README lacks specific execution instructions. Only return strategy entities described above LEAVE OUT anything that describes help, logging, version settings and others that are UNRELEVANT.\n* Sometimes, the provided README.md file doesn't describe the attack given in `Attack Name` and  `Description inputs  in this case returns an EMPTY response
    """

    GLEARING_PROMPT = """
    Attack Strategy Extraction Validation Instructions\n\nYour task is to validate the completeness of strategy entity and relationship extraction from README files based on previous analyses.\n\n## Context\nYou'll review past extractions provided in this format:\n```#### PAST EXTRACTION {index}####: \\n <response_content> \\n\\n```\n\nCompare these against the README content to ensure all attack strategy parameters have been identified.\n\n## Core Understanding\nReview previous extractions for parameters and arguments that represent attacker choices in modifying attack behavior. These include configuration options that enable attack mutations and measurement parameters revealing attack objectives.\n\n## Validation Criteria\n1. Strategy Entities\n- All explicit parameters/arguments that modify attack behavior\n- Configuration options enabling attack variations \n- Measurement parameters showing attack objectives\n\n\n## Response Format\nRespond with:\n- YES: If all strategy entities are completely extracted\n- NO: If any items are missing, give  a brief explanation of omissions\n\n```json\n{\n  \"Answer\": \"<YES/NO>\",\n  \"Description\": \" Brief explanation of omissions.\"\n}\n```\n\n## Critical Requirements\n- Only validate explicitly documented parameters\n- Focus on items that influence attack behaviour or measurement\n- Exclude help commands, logging, version settings, or other non-strategic elements\n- Return EMPTY if README doesn't match the specified attack name and description\n\n\n## Note\nExamine past extractions thoroughly before validation to avoid unnecessary duplication and ensure no strategic elements are missed.\n
    """

    CONTINUE_PROMPT = """
    Attack Strategy Entity Extraction - Incremental Update\n\n## Context\nYou will extract additional attack strategy parameters and relationships from README files that were not captured in previous extractions. Past extractions are provided as:\n\n#### PAST EXTRACTION {index}####:\nMissed Entities: <short_description of missed entities>\nHistory: ```json <response_content>```\n\n## Core Understanding\nIdentify new parameters and arguments that represent strategic choices in attack configuration, focusing only on previously uncaptured elements that modify attack behaviour or measure effectiveness.\n\n\n## Critical Requirements\n- Extract only explicitly documented parameters\n- Focus on elements that influence attack behaviour\n- Exclude help commands, logging, version settings\n- Return EMPTY if README doesn't match the attack description\n- Never duplicate previously extracted information\n- Only capture new, relevant strategic elements\n\n## Output Format\nReturn a JSON array containing only newly identified:\n- Strategy parameters that modify attack behaviour\n- Attack adaptation possibilities\n- Essential attack components and their relationships\n\n## Response Format\n```json \n{\n  \"strategies\": [\n    {\n      \"name\": \"<name_of_strategy>\",\n      \"description\": \"<description_of_strategy>\"\n    }\n  ]\n}\n```\n\n## Note\nCarefully review past extractions to avoid duplication and ensure all new strategic elements are properly documented.
    """
    
    FILTER_PROMPT = """
    ######################\n    #GOAL\n    ######################\n\n    **Your task is to process provided README files from code repositories and extract the name of the main file responsible for implementing the attack. This main file is the entry point that must be called to execute the attack code. .**\n\n    **Definitions:**\n\n    - **Main F\\file**: In the context of the `README.md`, the main file refers to the primary script or executable that initiates and runs the attack. This is typically the file that users are instructed to execute to perform the attack.\n\n    ######################\n    # INSTRUCTIONS\n    ######################\n\n    1. **Carefully read through the entire README file**, focusing on sections such as Installation, Usage, Requirements, or Setup that typically mention executable files and dependencies.\n\n    2. **Identify the main file** that is designated to execute the attack. This is usually referenced in command-line instructions, usage examples, or installation guides.\n\n    3. **If no main file is identified**, respond with `\"NO\"` for `file_found` and keep the `main_file_name` empty  \n    ---\n    ### **Steps:**\n\n    1. **Identify the Main File:**\n      \n      - Look for command-line instructions or usage examples that specify a file to be executed (e.g., `python attack.py`, `./run_attack.sh`).\n      \n      - Extract the name of this main file.\n\n    Note: JUST extract the file  name  with file  extension NOTHING else \n\n    ######################\n    EXAMPLE\n    ######################\n\n    ***Input example**:\n    SYN flood a tcp service in any port Usage: sudo python SYNFlood.py\n\n    ***Output example**:\n    SYNFlood.py
    """

    RELEVANCE_PROMPT = """
    # Strategy Relevance Verification Prompt\n\nYou are a cybersecurity expert tasked with verifying whether an extracted strategy is truly relevant to its associated attack. Given the following information:\n\n1. Attack Information:\n   - Name: {attack_name}\n   - Description: {attack_description}\n\n2. Extracted Strategy:\n   - Name: {strategy_name}\n   - Description: {strategy_description}\n\n3. Source Context:\n   ```\n   {original_readme_content}\n   ```\n\nEvaluate whether this strategy is a genuine and relevant method that could be used to execute the specified attack. Consider:\n\n- Does the strategy directly contribute to achieving the attack's objectives?\n- Is there a clear causal relationship between the strategy and the attack?\n- Is the strategy mentioned in the README.md in the context of executing this specific attack?\n- Would this strategy be recognized by security professionals as a valid method for this attack?\n\nRules for verification:\n- A strategy is relevant if it describes specific technical or procedural steps that could be used to execute the attack\n- A strategy is irrelevant if it:\n  - Is merely mentioned in passing without connection to the attack\n  - Describes general security concepts not specific to the attack\n  - Represents defensive measures rather than offensive strategies\n  - Is a consequence or outcome of the attack rather than a method to execute it\n\nOutput format:\n```json\n{\n    \"answer\": \"YES/NO\",\n}\n```\nNote: Reconnaissance step are ALSO considered VALID strategies.
    """
    
    SYSTEM_PROMPT_V1 = """
    ######################
    GOAL
    ######################

    **Your task is to process provided README files from code repositories and extract strategy entities along with their corresponding descriptions and relations to other attacks, assuming a specified goal attack (e.g., TCP DoS). Additionally, extract any other entities and relationships related to the use or application of the attack, if encountered. For these, specify the entity name and relation name.**

    **Definitions:**

    - **Strategy Entity**: In the context of the `README.md`, a strategy entity refers to the **arguments or parameters passed into functions or commands to execute the attack**. These arguments define the specific strategies, methods, or techniques used in the attack and may influence how the attack behaves or mutates to evade detection.

    - **Sucess Entity**: In the context of `README.md`, a success entity refers to an argument passed into the function to measure whether the attack is successful. 

    - **Goal Attack**: The primary attack of interest (e.g., TCP DoS) for which you are extracting strategy entities and relations.

    - **Other Entities**: Any additional relevant entities related to the execution of the attack mentioned in the README.

    **Instructions:**

    1. **Always assume that you have a specified goal attack** (e.g TCP DoS).

    2. Carefully read through the entire README file, paying close attention to any sections that mention arguments, options, parameters, configurations, tools, platforms, or environments required to run or apply the attack.

    3. Identify any information that suggests the attack can be transferred or adapted to different protocols, methods, targets, or involves other entities, establishing relations to different attacks or entities (e.g., transferring from TCP DoS to UDP DoS)

    ---

    ### **Steps:**

    1. **Identify all strategy entities.** For each identified strategy entity (argument or parameter), extract the following information:

      - **`strategy_name`**: Name of the strategy entity (argument name), capitalized.

      - **`strategy_description`**: Comprehensive description of the strategy's attributes and activities.

      **Format each strategy as a JSON object:**

      ```json
      {
        "type": "strategy",
        "name": "<strategy_name>",
        "description": "<strategy_description>"
      }
      ```

    2. **Identify relationships among the strategy entities and other attacks.** For each relevant relation:

      - **If the README.md suggests that the attack can be transferred or adapted to a different protocol, method, or attack (e.g., from TCP DoS to UDP DoS), extract this relationship.**

      For each such relationship, extract the following information:

      - **`source_strategy`**: Name of the source strategy entity, as identified in step 1.

      - **`related_attack`**: Name of the related attack or strategy (e.g., UDP DoS).

      - **`relationship_description`**: Explanation as to why the source strategy entity and the related attack are connected, including how the attack is transferable or adaptable.


      **Format each relationship as a JSON object:**

      ```json
      {
        "type": "relationship",
        "source": "<source_strategy>",
        "target": "<related_attack>",
        "description": "<relationship_description>",
      }
      ```

    3. **Identify any other entities and relationships related to the use or application of the attack, if encountered.** For each such entity and relationship, extract the following information:

      - **`entity_name`**: Name of the entity (e.g., a tool, platform, protocol), capitalized.

      - **`entity_description`**: Description of the entity's role in the attack.

      - **`relation_name`**: Name of the relationship (e.g., "requires", "runs on", "exploits").

      - **`relation_description`**: Explanation of how the entity is related to the attack.

      **Format each entity and relationship as a JSON object:**

      ```json
      {
        "type": "entity",
        "name": "<entity_name>",
        "description": "<entity_description>"
      },
      {
        "type": "relation",
        "source": "<source_entity>",
        "target": "<target_entity>",
        "relation": "<relation_name>",
        "description": "<relation_description>"
      }
      ```

    4. **Return the output** as a JSON array containing all the strategy entities, relationships, and other entities identified in steps 1, 2, and 3, OMITT unrelevant entities and relations 


    5. **When finished, output the complete JSON array.**0

    ---

    ######################
    EXAMPLES
    ######################

    #### **Goal Attack:** TCP Denial of Service (TCP DoS)

    #### **Example Input:**

    ```
    # Network Flood Tool

    This tool allows you to perform network flood attacks using customizable parameters.

    ## Usage

    ```
    python flood.py --protocol udp --target 192.168.1.1 --port 80 --threads 10
    ```

    ### Arguments:

    - `--protocol`: Specifies the protocol to use. Options are `tcp` or `udp`.

    - `--target`: IP address of the target machine.

    - `--port`: Port number to attack.

    - `--threads`: Number of threads to use for the attack.


    ## Description

    By default, the tool performs a TCP flood attack, but you can specify `--protocol udp` to perform a UDP flood attack.

    ## Requirements

    - **Python 3.6+**: The script requires Python version 3.6 or higher.

    - **Scapy Library**: Used for crafting and sending packets.

    ```

    #### **Example Output:**

    ```json
    [
      {
        "type": "strategy",
        "name": "--PROTOCOL",
        "description": "Specifies the protocol to use. Options are tcp or udp."
      },
      {
        "type": "strategy",
        "name": "--TARGET",
        "description": "IP address of the target machine."
      },
      {
        "type": "strategy",
        "name": "--PORT",
        "description": "Port number to attack."
      },
      {
        "type": "strategy",
        "name": "--THREADS",
        "description": "Number of threads to use for the attack."
      },
      {
        "type": "relationship",
        "source": "--PROTOCOL",
        "target": "UDP Denial of Service (UDP DoS)",
        "description": "By changing the protocol from TCP to UDP using the --protocol argument, the attack is transferable from TCP DoS to UDP DoS.",
      },

    ]
    ```

    ---

    ### **Remember:**

    - **Always assume a specified goal attack** (e.g., TCP DoS).

    - **Focus** on extracting:

      - **Strategy entities** (arguments or parameters passed into functions or commands), and their descriptions.

      - **Relationships** to other attacks, especially where the attack is transferable or adaptable to different methods or protocols.

      - **Other entities** related to the use or application of the attack (e.g., tools, libraries, platforms), and their relationships.

    - **Specify** the entity name and relation name for any other entities and relationships extracted.

    - **Present the extracted information** in the **specified JSON format** to enhance readability and processability.

    ---
    """
    PRESENCE_PENALTY = 0
    
    GLEARING_PROMPT_V1 = """
    ######################
    GOAL
    ######################

    **Your task is to determine if all entities and relationships described below have been extracted for the provided README files of code repositories, based on past extractions.** You will be provided with all past extractions in the format:

    ```
    #### PAST EXTRACTION {index}####: \n <response_content> \n\n
    ```

    Analyze the provided past extractions and README content before answering YES or NO to ensure the completeness of the entity and relationship extraction.

    ---

    ### **Criteria for Extraction:**

    - **Strategy Entities**: Have all arguments or parameters (strategy entities) passed into functions or commands to execute the attack been extracted? This includes naming and describing the specific strategies used in the attack.

    - **Relationships**: Have all relationships been identified, particularly if the README suggests that the attack can be adapted or transferred to other protocols, methods, or attacks (e.g., TCP DoS to UDP DoS)?

    - **Other Entities**: Have any additional relevant entities (e.g., attack methodologies, protocols, attack covariants) and their relationships to the attack been fully extracted?

    ---

    ### **Instructions:**

    1. **Review the past extractions**, which are provided in the format `#### PAST EXTRACTION {index}####: \n <response_content> \n\n`, and compare them with the README content.

    2. **Analyze the completeness** of the extraction based on the three criteria:
      - Have all **Strategy Entities** been extracted (arguments or parameters)?
      - Have all **Relationships** between strategy entities and other attacks or protocols been identified?
      - Have any **Other Entities** (tools, platforms, libraries) and their relationships to the attack been fully extracted?

    3. **Provide a simple YES or NO answer**:
      - **Answer YES** if:
        - All strategy entities, relationships, and other relevant entities have been fully identified and extracted as per the criteria.
      
      - **Answer NO** if:
        - Any strategy entities, relationships, or other relevant entities described in the README are missing or incomplete based on your analysis of the past extractions.

    4. **If answering NO**, provide a brief explanation of what is missing or incomplete.

    ---

    ### **Remember:**

    - Carefully analyze the past extractions and README content to avoid unnecessary duplication.
    - Ensure that no entities, relationships, or additional relevant information have been missed before making your determination.

    ---
    """

    CONTINUE_PROMPT_V1 = """
    ######################
    GOAL
    ######################

    **Your task is to continue the extraction of strategy entities, relationships, and other relevant entities from the provided README files, but only extract any additional entities or relationships that were not previously extracted.** You will be given all past extractions formatted as follows:

  
    #### PAST EXTRACTION {index}####:
    description: ```<short_description of missed entities>```
    history: ```<response_content>```
    


    These past extractions should not be duplicated or repeated in your current extraction. Your goal is to supplement the initial extractions based on what was missed or newly relevant parts of the README.

    ---

    ### **Steps:**

    1. **Review the provided README file and past extractions**, paying attention to any sections that describe additional arguments, parameters, options, tools, platforms, or relationships to other attacks or entities. The past extractions will be provided in the format:  
      `#### PAST EXTRACTION {index}####: \n <response_content> \n\n`  
      **Ensure that you avoid duplicating any entities or relationships already extracted.**

    2. **Identify any new strategy entities** that were not extracted in the past. For each newly identified strategy entity (argument or parameter), extract the following information:

      - **`strategy_name`**: Name of the new strategy entity (argument name), capitalized.

      - **`strategy_description`**: Comprehensive description of the strategy's attributes and activities.

      **Format each new strategy as a JSON object:**

      ```json
      {
        "type": "strategy",
        "name": "<strategy_name>",
        "description": "<strategy_description>"
      }
      ```

    3. **Identify any new relationships** among the strategy entities and other attacks or protocols that were not previously extracted. For each new relationship:

      - **If the README.md suggests that the attack can be transferred or adapted to a different protocol, method, or attack that wasn't previously extracted, capture this new relationship.**

      For each such new relationship, extract the following information:

      - **`source_strategy`**: Name of the new source strategy entity, as identified in step 1.

      - **`related_attack`**: Name of the related attack or protocol.

      - **`relationship_description`**: Explanation as to why the source strategy entity and the related attack or protocol are connected, including how the attack is transferable or adaptable.

      **Format each new relationship as a JSON object:**

      ```json
      {
        "type": "relationship",
        "source": "<source_strategy>",
        "target": "<related_attack>",
        "description": "<relationship_description>"
      }
      ```

    4. **Identify any new other entities and relationships** related to the use or application of the attack, if they were missed previously. For each newly identified entity and relationship, extract the following information:

      - **`entity_name`**: Name of the new entity (e.g., a tool, platform, protocol), capitalized.

      - **`entity_description`**: Description of the new entity's role in the attack.

      - **`relation_name`**: Name of the relationship (e.g., "requires", "runs on", "exploits").

      - **`relation_description`**: Explanation of how the new entity is related to the attack.

      **Format each new entity and relationship as a JSON object:**

      ```json
      {
        "type": "entity",
        "name": "<entity_name>",
        "description": "<entity_description>"
      },
      {
        "type": "relation",
        "source": "<source_entity>",
        "target": "<target_entity>",
        "relation": "<relation_name>",
        "description": "<relation_description>"
      }
      ```

    5. **Return the output** as a JSON array containing only the new strategy entities, relationships, and other entities identified in steps 1, 2, and 3, ensuring no duplication of already extracted data. Be mindful that all previous extractions are clearly indicated in the format:  
      `#### PAST EXTRACTION {index}####: \n <response_content> \n\n`

    ---

    ### **Remember:**

    - Focus only on extracting new information that wasn't included in the initial extraction.
    - Do not repeat or re-extract entities, strategies, or relationships that have already been processed, based on the provided past extractions.

    ---
    """

    FILTER_PROMPT_V1 = """
    ######################
    #GOAL
    ######################

    **Your task is to process provided README files from code repositories and extract the name of the main file responsible for implementing the attack. This main file is the entry point that must be called to execute the attack code. .**

    **Definitions:**

    - **Main F\file**: In the context of the `README.md`, the main file refers to the primary script or executable that initiates and runs the attack. This is typically the file that users are instructed to execute to perform the attack.

    ######################
    # INSTRUCTIONS
    ######################

    1. **Carefully read through the entire README file**, focusing on sections such as Installation, Usage, Requirements, or Setup that typically mention executable files and dependencies.

    2. **Identify the main file** that is designated to execute the attack. This is usually referenced in command-line instructions, usage examples, or installation guides.

    3. **If no main file is identified**, respond with `"NO"`
    ---
    ### **Steps:**

    1. **Identify the Main File:**
      
      - Look for command-line instructions or usage examples that specify a file to be executed (e.g., `python attack.py`, `./run_attack.sh`).
      
      - Extract the name of this main file.

    Note: JUST extract the file  name  with file  extension NOTHING else 

    ######################
    EXAMPLE
    ######################

    ***Input example**:
    SYN flood a tcp service in any port Usage: sudo python SYNFlood.py

    ***Output example**:
    SYNFlood.py
    """


class CodeAnalysisConfig: 
    
    SYSTEM_PROMPT = """
    # Network Attack Feature Extraction Instructions\n\nYou are a network security analyst specialized in identifying both general network traffic characteristics and strategy-specific features that indicate the presence and success of PROVIDED attack strategies. Focus on features that can be measured from actual network packet streams and can be monitored using ML-algorithms.\n\n## Analysis Steps: \n\n1) Analyze the input strategies (name + description) and identify the section of the code that implements the strategy. This is the \"code\" section of the output RESPONSIBLE for implementing the provided strategy. \n2) Analyze how this \"code\" tampers with packets and what network behaviour can be observed as a result of this tampering process. i.e., How does the implementation affect general network behaviour?\n3) Derive a set of OBSERVABLE features that can monitor such behaviour. \n\n### Feature requirements: \n- Features MUST be REALISTICALLY obtainable from stream of incoming packets.\n- Features MUST  be MEASURABLE using incremental statistics. \n- Features MUST reflect the provided STRATEGY but should be GENERAL network features. \n- If possible, give statistical measures, e.g. size, mean, standard deviation etc.\n- AVOID vague features that  cannot be provided as INPUT for the ML model to monitor e.g. Distribution or variation\n\n\n## Input Format\n```\nStrategy\nname: <strategy name>\ndescription: <strategy description>\nImplementation:\n```code\n<implementation code>\n```\n\n## Output Format\n```json\n{\n  \"features\": [\n    {\n      \"name\": \"<feature name>\",\n      \"description\": \"<what this feature measures>\",\n      \"code\": \"<relevant code section>\",\n      \"rationale\": \"<how this reflects the strategy>\"\n    }\n  ]\n}\n```\n\n\n## Key Guidelines\n1. Focus on observable network traffic patterns\n2. Features must be measurable from packet data\n3. Features should clearly manifest the strategy\n4. Prioritize realistic and obtainable measurements\n5. ONLY extract features that directly REFLECT the strategy\n6. EXCLUDE features that don't manifest the strategy's core purpose\n8. EXCLUDE vague features that is not directly measurable using statistical measures e.g. Distribution\n\nFollow the chain of thought process to identify both general network metrics and strategy-specific features that manifest the attack pattern.
    """

    GLEANING_PROMPT = """
    "# Network Attack Feature Completeness Verification\n\nAs a network security analyst, your task is to verify the COMPLETENESS of previously extracted network features for the PROVIDED attack implementation. Focus on OBSERVABLE and MEASURABLE characteristics from network packet streams.\n\n## Analysis Process\n\n1. Review past extractions given in the following form:\n #### PAST EXTRACTION {index} ####:\n   ```json\n   {\n     \"features\": [\n       {\n         \"name\": \"<feature name>\",\n         \"description\": \"<what this feature measures>\",\n         \"code\": \"<relevant code section>\",\n         \"rationale\": \"<how this reflects the strategy>\"\n       }\n     ]\n   }\n   ```\n\n2. Verify Feature Coverage\n   - Confirm all OBSERVABLE network-level features are identified\n   - Validate MEASURABLE traffic characteristics\n   - Ensure features support INCREMENTAL monitoring\n\n3. Completeness Assessment\n   - Check feature descriptions completeness\n   - Verify code section relevance\n   - Validate feature rationales\n\n## Verification Requirements\n\n1. Feature Analysis MUST:\n   - Have clear, MEASURABLE names\n   - Include statistical descriptions\n   - Link to relevant code sections\n   - Provide strategy-based rationales\n\n2. Features MUST be:\n   - OBSERVABLE in packet streams\n   - MEASURABLE using statistics\n   - REALISTICALLY monitorable\n   - Relevant to the STRATEGY\n\n## Response Format\n```json\n{\n  \"Answer\": \"YES/NO\",\n  \"Description\": \"<brief description of missing elements>\"\n}\n```\n\n## Evaluation Criteria\n\nAnswer YES if:\n- All features that manifest strategy have been identified. \n- Code sections implement the strategy\n- Rationales explain strategic relevance\n\nAnswer NO if:\n- Missing OBSERVABLE features that can manifest strategies\n- Vague or non-MEASURABLE descriptions that can be replaced with more concrete features\n- Incomplete code references\n- Weak strategic rationales\n\n## Key Guidelines\n\n1. ONLY validate features that are:\n   - OBSERVABLE in network traffic\n   - MEASURABLE using statistics\n   - Directly tied to the STRATEGY\n   - REALISTICALLY monitorable\n\n2. EXCLUDE validation of:\n   - Non-network characteristics\n   - Vague DISTRIBUTIONS\n   - Features without statistical basis\n   - Implementation-specific details\n\nFollow systematic reasoning to ensure comprehensive coverage of network-level attack manifestations."
    """

    CONTINUE_PROMPT = """
    # Network Attack Feature Extension Instructions\n\nAs a network security analyst, your task is to identify additional OBSERVABLE network features that MANIFEST the attack strategy, based on previous extraction analysis. Focus on features not already covered that are REALISTICALLY obtainable from network packet streams.\n\n## Analysis Process: \n1. Review Previous Analysis\n#### PAST EXTRACTION {index}: ####:\n\n```json\n{\n  \"features\": [\n    {\n      \"name\": \"<feature name>\",\n      \"description\": \"<what this feature measures>\",\n      \"code\": \"<relevant code section>\",\n      \"rationale\": \"<how this reflects the strategy>\"\n    }\n  ]\n}\n```\nMissed Entities: \n\n   ```json\n   {\n     \"complete\": \"YES/NO\",\n     \"rationale\": \"<brief description of missing elements>\"\n   }\n   ```\n\n2. Generate Additional Features\n     - Address gaps identified in the rationale\n     - Add MISSING features described\n     - Ensure full strategy coverage\n\n## Feature Requirements\n\n1. New Features MUST:\n   - Be DISTINCT from past extractions\n   - MANIFEST the strategy differently\n   - Support INCREMENTAL monitoring\n   - Use statistical measures\n\n2. Features MUST remain:\n   - OBSERVABLE in packet streams\n   - MEASURABLE using statistics\n   - REALISTICALLY monitorable\n   - Relevant to the STRATEGY\n\n## Output Format\n```json\n{\n  \"additional_features\": [\n    {\n      \"name\": \"<feature name>\",\n      \"description\": \"<what this feature measures>\",\n      \"code\": \"<relevant code section>\",\n      \"rationale\": \"<how this reflects the strategy>\"\n    }\n  ]\n}\n```\n\n## Key Guidelines\n\n1. ONLY add features that:\n   - Are NOT in past extractions\n   - MANIFEST new aspects of strategy\n   - Provide UNIQUE monitoring angles\n   - Support ML-based detection\n\n2. EXCLUDE features that:\n   - Duplicate existing metrics\n   - Use vague DISTRIBUTIONS\n   - Lack statistical basis\n   - Cannot be monitored INCREMENTALLY\n\nFollow systematic reasoning to expand coverage while maintaining measurability and relevance to the attack strategy.
    """

    SYSTEM_PROMPT_V1 = """
      ## Goal
    You are provided with: 
    1) A JSON array of attack strategies with relevant relations and entities
    2) Code that implements those strategies

    Your task is to analyze the provided attack implementation code and extract detailed information for each element in the JSON array, as well as overall information from the entire code.

    ## Information to extract for each element in the JSON array:

    1. **Per-element Analysis** [MANDATORY]
      - element_name: Name of the JSON array element
      - element_type: Type of the JSON array element (e.g., strategy, relation)
      - description: Provide a detailed description of how the element is implemented by analyzing the code
      - features: List of features that reflect the implementation of this element
        - name: Identify a measurable, general network-level feature or observable that reflects this element
        - feature_description: Give a clear description of the identified feature
        - characteristics: Describe in a single word or short phrase what network characteristics are expected from this feature
      - Note: Provide ONLY network-level features, packet features, or observable characteristics and give features in-context of the attack implementation. Omit features such as abnomal_pattern THAT IS NOT DIRECTLY MEASURABLE.

    ## Information to extract from the entire code:

    2. **Success Criteria** [OPTIONAL, Can be multiple]
      - description: Describe the success criteria for the implemented attack
      - features: List of features that indicate attack success
        - name: Identify a measurable, general network-level feature or observable that can indicate attack success.  Where appropriate : Use network performance features or  changes to the given state of the victim or attacker
        - feature_description: Provide a description of this success-indicating feature
        - characteristics: Describe in a single word or short phrase what network characteristics are expected when this success criteria is met

    3. **Vulnerability (Targeted Vulnerability)** [OPTIONAL]
      - If present, analyze and describe the vulnerability that the attack seems to target

    4. **Process (Execution Process)** [MANDATORY, ONE PER CODE FILE]
      - Break down the overall attack execution into a series of steps, focusing on network interactions

    ## Output Format
    Provide your analysis using the following JSON format:

    ```json
    {
      "per_element_analysis": [
        {
          "element_name": "<name_of_json_array_element>",
          "element_type": "<type_of_json_array_element>",
          "description": "<detailed_description_of_implementation>",
          "features": [
            {
              "name": "<feature_name>",
              "feature_description": "<description_of_general_network_level_feature>",
              "characteristics": "<single_word_or_short_phrase_describing_expected_network_characteristics>"
            }
          ]
        }
      ],
      "overall_analysis": {
        "success_criteria": [
          {
            "type": "Success",
            "description": "<description_of_success_criteria>",
            "features": [
              {
                "name": "<feature_name>",
                "feature_description": "<description_of_general_network_level_feature>",
                "characteristics": "<single_word_or_short_phrase_describing_expected_network_characteristics>"
              }  
            ]
          }
        ],
        "vulnerability": {
          "type": "Vulnerability",
          "description": "<description_of_targeted_vulnerability>"
        },
        "process": {
          "type": "Process",
          "steps": [
            {
              "number": 1,
              "description": "<description_of_network_interaction_step_1>"
            },
            {
              "number": 2,
              "description": "<description_of_network_interaction_step_2>"
            }
          ]
        }
      }
    }
    ```

    ## Important Guidelines
    1. Analyze each element in the JSON array individually, providing a description and relevant features for each.
    2. A strategy or element might involve multiple steps or aspects, so it may be reflected by multiple features. Include all relevant features for each element.
    3. For the overall analysis, consider the entire code implementation to identify Success criteria, Vulnerabilities, and the overall Process.
    4. Success criteria may also have multiple associated features. Include all relevant features for each success criterion.
    5. Ensure all features focus on general network-level observables, not attack-specific metrics.
    6. Provide clear, concise, and technically accurate descriptions for all fields.
    7. If a mandatory element cannot be identified, return "NO" for that specific part of the analysis.
    8. The Process should describe the overall attack flow, not individual steps for each strategy.
    9. You may identify multiple Success criteria if applicable.
    10. If no Vulnerability can be inferred from the code, omit this section from the output.

    ## Example
    Input JSON Array:
    ```json
    [
      {
        "type": "strategy",
        "name": "TCP_FLOOD",
        "description": "Sends a large number of TCP packets to overwhelm the target's network resources"
      },
      {
        "type": "strategy",
        "name": "NUM_PACKETS",
        "description": "Defines the number of packets to be sent in the attack"
      }
    ]
    ```

    Input Code:
    ```python
    import socket
    import random

    def tcp_flood(target_ip, target_port, num_packets):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        
        for _ in range(num_packets):
            data = random.randbytes(1024)
            sock.send(data)
        
        sock.close()

    if __name__ == "__main__":
        target_ip = "192.168.1.1"
        target_port = 80
        num_packets = 1000
        tcp_flood(target_ip, target_port, num_packets)
    ```

    Example Output:
    ```json
    {
      "per_element_analysis": [
        {
          "element_name": "TCP_FLOOD",
          "element_type": "strategy",
          "description": "Implements a TCP flood attack by establishing a connection and sending a large number of packets with random data",
          "features": [
            {
              "name": "tcp_connection_rate",
              "feature_description": "Rate of TCP connections established per second",
              "characteristics": "Connection spike"
            },
            {
              "name": "packet_transmission_rate",
              "feature_description": "Rate of packets sent over an established TCP connection",
              "characteristics": "Traffic volume surge"
            }
          ]
        },
        {
          "element_name": "NUM_PACKETS",
          "element_type": "strategy",
          "description": "Defines the total number of packets to be sent in the attack",
          "features": [
            {
              "name": "flow_duration",
              "feature_description": "Duration of a single TCP flow",
              "characteristics": "Extended connection"
            },
            {
              "name": "flow_size",
              "feature_description": "Total number of packets in a single TCP flow",
              "characteristics": "Large flow"
            }
          ]
        }
      ],
      "overall_analysis": {
        "success_criteria": [
          {
            "type": "Success",
            "description": "The attack is successful if it overwhelms the target's ability to process incoming connections",
            "features": [
              {
                "name": "connection_backlog",
                "feature_description": "Number of pending TCP connections in the target's backlog",
                "characteristics": "Connection queue saturation"
              },
              {
                "name": "connection_timeout_rate",
                "feature_description": "Rate of connection timeouts on the target system",
                "characteristics": "Increased timeout frequency"
              }
            ]
          },
          {
            "type": "Success",
            "description": "The attack succeeds if it consumes a significant portion of the target's network bandwidth",
            "features": [
              {
                "name": "bandwidth_utilization",
                "feature_description": "Percentage of target's available bandwidth consumed by attack traffic",
                "characteristics": "Bandwidth exhaustion"
              },
              {
                "name": "packet_drop_rate",
                "feature_description": "Rate of dropped packets due to network congestion",
                "characteristics": "Increased packet loss"
              }
            ]
          }
        ],
        "vulnerability": {
          "type": "Vulnerability",
          "description": "The attack exploits the target's inability to handle a high rate of incoming TCP connections and process large volumes of data efficiently"
        },
        "process": {
          "type": "Process",
          "steps": [
            {
              "number": 1,
              "description": "Establish a TCP connection to the target IP and port"
            },
            {
              "number": 2,
              "description": "Generate random payload data for each packet"
            },
            {
              "number": 3,
              "description": "Send a specified number of packets with random data over the established connection"
            },
            {
              "number": 4,
              "description": "Close the TCP connection after sending all packets"
            }
          ]
        }
      }
    }
    ```

    Remember to adapt your analysis to the specific details and complexity of the provided attack implementation code and JSON array.
"""
 

    GLEANING_PROMPT_V1 = """
   ## Goal
Your task is to determine if all network-level features, success criteria, vulnerabilities, and execution processes have been fully extracted for the provided attack implementation code, based on past extractions.

## Instructions

1. **Review the past extractions**, which are provided in the format:
  ```
  #### PAST EXTRACTION {index} ####:
  <response_content>
  ```

2. **Analyze the completeness** of the extraction based on the following criteria:
  - Have all **Features** been extracted for each element, including network-level modifications and traffic characteristics?
  - Have all **Success Criteria** been identified, if applicable, including all relevant features?
  - Has the **Vulnerability** been fully described, if present?
  - Has the **Process** been broken down into clear, network-focused steps?

3. **Provide a simple YES or NO answer**:
  - **Answer YES if**:
    - All elements in the "per_element_analysis" have been fully identified and extracted, including element_name, element_type, description, and features.
    - The "overall_analysis" section is complete, with all applicable success criteria (including their features), vulnerability (if present), and process steps.
    - All descriptions focus on network-level features, traffic patterns, and observable characteristics.
  
  - **Answer NO if**:
    - Any elements in the "per_element_analysis" are missing or incomplete.
    - The "overall_analysis" section is incomplete or missing applicable parts.
    - Descriptions lack focus on network-level features and traffic patterns.

4. **If answering NO**, provide a brief explanation of what is missing or incomplete.

## Remember
- Carefully analyze the past extractions and the attack implementation code to avoid unnecessary duplication.
- Ensure that no network-level features, traffic patterns, or execution steps have been missed before making your determination.
- Focus on the network-centric aspects of the attack, including observable traffic anomalies and patterns.
- Verify that each element and success criterion has all relevant features identified.
"""
    CONTINUE_PROMPT_V1 = """
## Goal
Your task is to continue the extraction of network-level features, success criteria, vulnerabilities, and execution processes from the provided attack implementation code, but only extract additional information that was not previously extracted.

## Instructions

1. **Review the provided attack implementation code and past extractions**. Past extractions will be in the format:
  ```
  #### PAST EXTRACTION {index} ####:
  <response_content>
  ```
  Ensure that you avoid duplicating any information already extracted.

2. **Identify any new or incomplete elements** in the "per_element_analysis" section. For each new or incomplete element:
  ```json
  {
    "element_name": "<name_of_json_array_element>",
    "element_type": "<type_of_json_array_element>",
    "description": "<detailed_description_of_implementation>",
    "features": [
      {
        "name": "<feature_name>",
        "feature_description": "<description_of_general_network_level_feature>",
        "characteristics": "<single_word_or_short_phrase_describing_expected_network_characteristics>"
      }
    ]
  }
  ```

3. **Identify any new or incomplete Success Criteria** in the "overall_analysis" section:
  ```json
  {
    "type": "Success",
    "description": "<description_of_success_criteria>",
    "features": [
      {
        "name": "<feature_name>",
        "feature_description": "<description_of_general_network_level_feature>",
        "characteristics": "<single_word_or_short_phrase_describing_expected_network_characteristics>"
      }
    ]
  }
  ```

4. **Identify any new Vulnerabilities** or refine existing ones:
  ```json
  {
    "type": "Vulnerability",
    "description": "<description_of_targeted_vulnerability>"
  }
  ```

5. **Identify any new Process steps** or refine existing ones to focus more on network interactions:
  ```json
  {
    "type": "Process",
    "steps": [
      {
        "number": 1,
        "description": "<description_of_network_interaction_step_1>"
      },
      {
        "number": 2,
        "description": "<description_of_network_interaction_step_2>"
      }
      // Additional steps as needed
    ]
  }
  ```

6. **Return the output** as a JSON object containing only the new or refined information identified in steps 2-5, ensuring no duplication of already extracted data. Use the following structure:
  ```json
  {
    "per_element_analysis": [
      // New or refined elements
    ],
    "overall_analysis": {
      "success_criteria": [
        // New or refined success criteria
      ],
      "vulnerability": {
        // New or refined vulnerability
      },
      "process": {
        // New or refined process steps
      }
    }
  }
  ```

## Remember
- Focus only on extracting new information or refining incomplete extractions.
- Ensure all new extractions emphasize network-level features, traffic patterns, and observable characteristics.
- Do not repeat or re-extract information that has already been processed in the past extractions.
- If no new information can be extracted, return an empty JSON object.
      """
class GleaningConfig:
  MAX_TOKENS=16384
  # MAX_TOKENS=4095
  #LOGIT_BIAS = { 31958:100, 14695:100 } # Token IDs for YES- > 14331 and 31958 -> 9173. Tokenizer ref: https://platform.openai.com/tokenizer?view=bpe
  TEMPERATURE = 0
  TOP_P = 0
  SEED = 0
  MODEL = "gpt-4o-mini"
  # MODEL = "gpt-3.5-turbo-0125"