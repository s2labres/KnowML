

class LabellingPrompts: 
    ENTITY = \
    """      
    ## Goal
    Analyze a set of semantically similar entities related to a given attack type and generate a concise, general entity label that captures their common characteristics or purpose.

    ## Instructions
    1. Review the provided information for each entity in the set:
    - Entity name
    - Entity description
    - Network features that reflect this entity
    2. Analyze the common themes, characteristics, and purposes across all entities.
    3. Consider the given overall attack label for context.
    4. Generate a concise general entity label (2-5 words) that best represents the shared characteristics or purpose of the entities.
    5. Provide a brief explanation (2-3 sentences) justifying your chosen entity label.

    ## Input Format
    Attack Label: [Given attack label]

    Entity 1:
    Name: [Entity name]
    Description: [Entity description]
    Features: [Network features that reflect this entity]
    <SEP>
    Entity 2:
    Name: [Entity name]
    Description: [Entity description]
    Features: [Network features that reflect this entity]
    <SEP>
    [Additional entities as needed]

    ## Output Format
    ```json
    {
    "Entity label": "[Your 2-5 word label]",
    "Explanation": "[Your 2-3 sentence explanation]"
    }
    ```

    ## Example

    ### Input
    Attack Label: TCP SYN Flood

    Entity 1: 
    Name: Hping3
    Description: 'A command-line tool used for network packet generation and analysis, essential for executing SYN attacks.'
    Features: '[{"name": "packet_generation", "feature_description": "Ability to generate and send packets with specified parameters such as size and flags.", "characteristics": "Customizable traffic"}]'
    <SEP>

    Entity 2:
    Name: hping3
    Description: 'A command-line tool used for network packet generation and analysis, often utilized for crafting SYN packets for DDoS attacks.'
    Features: 'A command-line tool used for network packet generation and analysis, often utilized for crafting SYN packets for DDoS attacks.'

    ### Output
    ```json
    {
    "Entity label": "Network Packet Manipulation Tool",
    "Explanation": "These entities represent a command-line tool designed for network packet generation and analysis, specifically capable of crafting SYN packets for attacks. The tool's ability to generate customizable traffic and manipulate packet parameters makes it a versatile instrument for both network testing and potential misuse in DDoS attacks."
    }
    ```
    """

    STRATEGY = \
    """
    ## Goal
    Analyze a cluster of related cybersecurity strategies and generate a concise label that captures the essence of their common approach or technique, within the context of a given attack type.

    ## Instructions
    1. Review the provided information for each strategy in the cluster:
    - Strategy name
    - Implementation description
    - Description (Which descsribes the use of the strategy)
    - Features (network characteristics that reflect this strategy)
    2. Analyze the common themes, characteristics, and objectives across all strategies.
    3. Consider the given overall attack label for context.
    4. Generate a concise strategy label (2-5 words) that best represents the shared approach or technique. The label should be reflective of the attack strategy in the context of the given attack type.
    5. Provide a brief explanation (2-3 sentences) justifying your chosen strategy label.

    ## Input Format
    Attack Label: [Given attack label]

    Strategy 1:
    Name: [Strategy name]
    Implementation description: [Implementation description]
    Description: [Strategy description]
    Features: [Network features that reflect this strategy]
    <SEP>
    Strategy 2:
    Name: [Strategy name]
    Implementation description: [Implementation description]
    Description: [Strategy description]
    Features: [Network features that reflect this strategy]
    <SEP>
    [Additional strategies as needed]

    ## Output Format
    ```json
    {
    "Strategy Label": "[Your 2-5 word label reflective of the attack strategy]",
    "Explanation": "[Your 2-3 sentence explanation]"
    }
    ```

    ## Example

    ### Input
    Attack Label: Simulation-based DDoS Attack

    Strategy 1:
    Name: NUMBER OF EXECUTIONS
    Implementation description: 'The user specifies how many times the Simulink model will execute during the simulation process, influencing the overall results and effectiveness of the attack.'
    Description: 'The user specifies how many times the Simulink model will execute during the simulation process, which can affect the overall results and effectiveness of the attack.'
    Features: '[{"name": "execution_count", "feature_description": "The number of times the model is run during the simulation.", "characteristics": "Result variability"}]'
    <SEP>
    Strategy 2:
    Name: --SYN-PACKETS
    Implementation description: "The number of packets to be sent is defined by user input, which determines the intensity of the attack. The number of SYN packets to send is specified multiple times, emphasizing its importance in the attack's execution. The number of packets to be sent is defined by user input, which determines the intensity of the attack. The number of SYN packets to send is specified multiple times, emphasizing its importance in the attack's execution. This parameter directly affects the volume of traffic directed at the target."
    Description: 'Number of SYN packets to send to the target server to initiate the flood.'
    Features: '[{"name": "packet_count", "feature_description": "Total number of packets sent to the target during the attack.", "characteristics": "Attack intensity"}, {"name": "packet_count_repetition", "feature_description": "Reiterates the total number of packets sent to the target during the attack.", "characteristics": "Attack intensity"}, {"name": "attack_intensity", "feature_description": "The overall impact of the number of SYN packets sent on the target\'s ability to handle connections.", "characteristics": "Flood intensity"}, {"name": "traffic_volume", "feature_description": "The total amount of traffic generated by the specified number of SYN packets sent to the target.", "characteristics": "High traffic load"}, {"name": "connection_attempt_rate", "feature_description": "The rate at which connection attempts are made to the target server, influenced by the number of SYN packets.", "characteristics": "Connection surge"}]'
    <SEP>

    ### Output
    ```json
    {
    "Strategy Label": "Attack Count Control",
    "Explanation": "These strategies focus on controlling the intensity and effectiveness of the simulated DDoS attack by allowing the user to specify the number of executions or packets sent. This approach enables fine-tuning of the attack's impact by adjusting the volume of simulated traffic or model iterations."
    }
    ```
    """
    SUCCESS = \
    """
    ## Goal
    Analyze a set of related Success criteria for a given attack type and generate a concise Success Indicator that captures the essence of what constitutes a successful attack, along with an explanation of the overall success criteria.

    ## Instructions
    1. Review the provided information for each Success criterion:
    - Success description
    - Features (network characteristics that reflect this success criterion)
    2. Analyze the common themes and key elements that define a successful attack outcome across all criteria.
    3. Consider the given Attack Label for context.
    4. Generate a concise Success Indicator (2-5 words) that best represents the overall criteria for a successful attack.
    5. Provide a brief explanation (2-3 sentences) justifying your chosen Success Indicator and how it relates to the various success criteria and features.

    ## Input Format
    Attack Label: [Given attack label]

    Success 1:
    Description: [Success criterion description]
    Features: [Network features that reflect this success criterion]
    <SEP>
    Success 2:
    Description: [Success criterion description]
    Features: [Network features that reflect this success criterion]
    <SEP>
    [Additional success criteria as needed]

    ## Output Format
    ```json
    {
    "Success Indicator": "[Your 2-5 word indicator]",
    "Explanation": "[Your 2-3 sentence explanation]"
    }
    ```

    ## Example

    ### Input
    Attack Label: TCP SYN DoS

    Success 1:
    Description: The attack is successful if it causes the target to experience significant packet loss, indicating that the network is overwhelmed.
    Features: [{"name": "packet_loss_rate", "feature_description": "The percentage of packets that are lost during transmission to the target, which should increase under attack conditions.", "characteristics": "Network congestion"}]
    <SEP>
    Success 2:
    Name: Resource Exhaustion
    Description: The attack is successful if it overwhelms the target's ability to process incoming SYN packets, leading to resource exhaustion.
    Features: [{"name": "connection_backlog", "feature_description": "Number of pending TCP connections in the target's backlog due to SYN flood.", "characteristics": "Connection queue saturation"}, {"name": "packet_drop_rate", "feature_description": "Rate of dropped packets due to network congestion caused by the attack.", "characteristics": "Increased packet loss"}]

    ### Output
    ```json
    {
    "Success Indicator": "Network and Resource Exhaustion",
    "Explanation": "This Success Indicator encompasses the key aspects of a successful TCP DoS attack. It reflects the attack's ability to overwhelm the network, causing significant packet loss, and exhaust server resources by flooding with SYN packets. The features, including packet loss rate, connection backlog, and packet drop rate, collectively measure the attack's effectiveness in degrading network performance and overwhelming the target's processing capabilities."
    }
    ```
    """
    
    RELATIONSHIP = \
    """
    ## Goal
    Analyze a cluster of related relationships within a cybersecurity attack and generate a concise overall label and explanation that capture the essence of how these elements are interconnected, within the context of a given attack type.

    ## Instructions
    1. Review the provided information for each relationship in the cluster:
    - Relationship description
    2. Analyze the common themes, characteristics, and objectives across all relationships.
    3. Consider how these relationships connect different strategies, processes, vulnerabilities, or success criteria within the attack.
    4. Analyze the significance of these relationships in the context of the overall attack strategy.
    5. Consider the given overall attack label for context.
    6. Generate a concise overall relationship label (2-5 words) that best represents the shared connections and their importance.
    7. Provide a brief explanation (2-3 sentences) elaborating on how these relationships collectively contribute to the effectiveness or understanding of the attack.

    ## Input Format
    Attack Label: [Given attack label]

    Relationship 1:
    Description: [Relationship description]
    <SEP>
    Relationship 2:
    Description: [Relationship description]
    <SEP>
    [Additional relationships as needed]

    ## Output Format
    ```json
    {
    "Relationship Label": "[Your 2-5 word label]",
    "Explanation": "[Your 2-3 sentence explanation]"
    }
    ```

    ## Example

    ### Input
    Attack Label: TCP SYN Denial of Service

    Relationship 1:
    Description: The SYN flood attack executed by hping3 is a method of performing a TCP SYN Denial of Service attack.
    <SEP>
    Relationship 2:
    Description: Using the --flood option with hping3 allows for a rapid and overwhelming SYN flood attack, which is the essence of a TCP SYN Denial of Service attack.

    ### Output
    ```json
    {
    "Relationship Label": "Hping3-Enabled SYN Flooding",
    "Explanation": "These relationships highlight the connectuibs between the hping3 tool and TCP SYN Denial of Service attacks. They demonstrate hping3's capabilities, particularly its --flood option, enable the rapid execution of SYN flood attacks, which form the core of TCP SYN DoS strategies. This connection underscores the tool's effectiveness in overwhelming target systems through automated, high-volume SYN packet transmission."
    }
    ```

    """

    VULNERABILITY = \
    """
    ## Goal
    Analyze a list of vulnerability descriptions that are semantically similar and generate a single, concise vulnerability label with an explanation that captures the essence of the group of vulnerabilities in context of the given attack label. 

    ## Instructions
    1. Review all provided vulnerability descriptions.
    2. Identify common themes, characteristics, and potential impacts across the vulnerabilities.
    3. Analyze the key technical aspects shared by these vulnerabilities.
    4. Consider the broader context in which these vulnerabilities might be exploited and their collective significance in cybersecurity.
    5. Generate a single, concise vulnerability label (2-5 words) that best represents the nature of the entire group of vulnerabilities.
    6. Provide a brief explanation (2-3 sentences) elaborating on the common aspects of these vulnerabilities, their collective potential impact, and why they are significant as a group.

    ## Input Format
    Attack Label: [Given attack label]

    Vulnerability 1:
    Description: [Vulnerability description]
    <SEP>
    Vulnerability 2:
    Description: [Vulnerability description]
    <SEP>
    [Additional vulnerabilities as needed]

    ## Output Format
    ```json
    {
    "Vulnerability Label": "[Your 2-5 word label]",
    "Explanation": "[Your 2-3 sentence explanation]"
    }
    ```

    ## Example

    ### Input
    Attack Label: TCP SYN DoS
    Vulnerability 1:
    Description: The attack exploits the target's inability to handle a high rate of incoming SYN packets, leading to resource exhaustion and denial of service. The attack exploits the target's TCP stack's inability to handle unexpected flags and high volumes of SYN packets, leading to resource exhaustion and connection mismanagement.
    <SEP>
    Vulnerability 2:
    Description: The attack targets the target's ability to handle multiple concurrent connections and high traffic volume, exploiting weaknesses in its network capacity. The attack exploits the target's inability to handle a high volume of concurrent connections and requests, particularly when the attack duration is extended, leading to potential denial of service.

    ### Output
    ```json
    {
    "Vulnerability Label": "Resource Exhaustion DoS Vulnerability",
    "Explanation": "This group of vulnerabilities exploits the target system's inability to handle high volumes of network traffic or connection requests. Whether through SYN flooding or sustained connection overload, these attacks aim to exhaust system resources, leading to denial of service. The vulnerabilities highlight weaknesses in traffic management, connection handling, and resource allocation, making them particularly effective against systems with limited capacity or inadequate protection mechanisms."
    }
    ```
    """

    PROCESS = \
    """
    ## Goal
    Analyze a set of similar cybersecurity processes and generate a single representative process that captures the essential steps and common themes across all input processes.

    ## Instructions
    1. Review the provided process steps for each process in the set.
    2. Identify common themes, objectives, and patterns across all processes.
    3. Create a single representative process that:
    a. Captures the essential steps common to most or all input processes
    b. Includes unique, important steps that significantly contribute to the overall goal
    c. Maintains a logical flow of steps
    d. Numbers steps sequentially
    4. Ensure the representative process is general enough to encompass the key aspects of all input processes, but specific enough to be meaningful.
    5. Generate a concise general process label (2-5 words) that best represents the nature of the entire group of processes.
    6. Provide a brief explanation (2-3 sentences) elaborating on the common aspects of these processes and their significance.

    ## Input Format
    Process 1:
    Steps: [List of process steps]
    <SEP>
    Process 2:
    Steps: [List of process steps]
    <SEP>
    [Additional processes as needed]

    ## Output Format
    ```json
    {
    "Process Label": "[Your 2-5 word label]",
    "Representative Process": [
        {"number": 1, "description": "[Step description]"},
        {"number": 2, "description": "[Step description]"},
        ...
    ]
    }
    ```

    ## Example

    ### Input
    Process 1:
    Steps: [{"number": 1, "description": "Initialize the TCP server and bind it to the specified port."}, {"number": 2, "description": "Listen for incoming client connections."}, {"number": 3, "description": "Accept a client connection and enter the data transmission loop."}, {"number": 4, "description": "Read random data into a buffer and transmit it to the client at the specified rate."}, {"number": 5, "description": "Monitor the transmission rate and adjust the delay to maintain the specified maximum rate."}, {"number": 6, "description": "Close the connection after reaching the maximum output limit."}, {"number": 7, "description": "Monitor the network for packet loss and response times to assess the effectiveness of the attack."}, {"number": 8, "description": "Adjust the buffer size dynamically based on observed network performance to optimize data transmission."}]
    <SEP>
    Process 2:Attack Label: [Given attack label]
    Steps: [{"number": 1, "description": "Parse command-line arguments to retrieve the target IP address for monitoring."}, {"number": 2, "description": "Initialize parameters for detecting SYN Flood attacks, including thresholds and rate limits."}, {"number": 3, "description": "Use Scapy to sniff packets on the specified network interface, filtering for packets destined for the target IP."}, {"number": 4, "description": "For each sniffed packet, check if it is a TCP packet with the SYN flag set."}, {"number": 5, "description": "Count the number of SYN packets from each source IP and compare it against the adaptive threshold."}, {"number": 6, "description": "If the count exceeds the threshold, trigger an alert indicating a possible SYN Flood attack."}, {"number": 7, "description": "Monitor the rate of SYN packets per source IP and destination port, triggering alerts if the rate limit is exceeded."}, {"number": 8, "description": "Log the details of detected SYN Flood alerts for further analysis and reporting."}, {"number": 9, "description": "Implement a mechanism to notify network administrators in real-time when a potential SYN Flood attack is detected."}]

    ### Output
    ```json
    {
    "Process Label": "Network Traffic Analysis and Control",
    "Representative Process": [
        {"number": 1, "description": "Initialize system parameters and parse command-line arguments."},
        {"number": 2, "description": "Set up network monitoring or connection handling based on the specific attack or defense scenario."},
        {"number": 3, "description": "Begin primary operation loop (e.g., accepting connections, sniffing packets)."},
        {"number": 4, "description": "Process network data according to the specific attack or defense mechanism."},
        {"number": 5, "description": "Monitor key metrics relevant to the attack or defense strategy."},
        {"number": 6, "description": "Implement dynamic adjustments based on observed network behavior and performance."},
        {"number": 7, "description": "Log relevant data and events for analysis and reporting."},
        {"number": 8, "description": "Trigger alerts or notifications when predefined thresholds are exceeded."},
        {"number": 9, "description": "Conclude operations based on predetermined criteria or continue monitoring as needed."}
    ]
    }
    ```

    """