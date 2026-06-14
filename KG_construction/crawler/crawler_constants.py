class CrawlerConstants:
    """
    This class store static constants used by the repository crawler.
    """

    # Constants for API calls, don't change at runtime
    # API doc reference: https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#about-search
    SEARCH_RATE_LIMIT = 30 # Rate limit for search API in minutes
    SEARCH_CODE_RATE_LIMIT = 10 # Rate limit for search code API in minutes
    RATE_LIMIT_UNIT = 60 # Rate limit unit in seconds
    QUERY_LENGTH = 256 # Maximum query character length for search API
    QUARY_PARAM_LIMIT = 5 # Maximum number of operators used in search query (e.g. NOT, AND, OR, etc.)
    ENDPOINT = "https://api.github.com"
    ACCEPT_FORMAT= "application/vnd.github+json"

    # API constants
    # Reference: https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2022-11-28#supported-api-versions
    API_VERSION = "2022-11-28"

    # Constants for searching repositories
    # API doc reference: https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#search-repositories
    MAX_SEARCH_RESULT_PER_PAGE = 100 # Maximum number of repositories returned per page

    # Constants for searching TCP DoS attacks -> Done
    TCP_SYN_BASE_KEYWORDS = ["TCP", "SYN", "TCP SYN", "ACK", "TCP ACK", "SYN-ACK", "TCP SYN-ACK", "RESET", "TCP RESET", "RST", "TCP RST", "FIN", "TCP FIN", "ACK-FIN", "TCP ACK-FIN", "ACK-RST", "TCP ACK-RST", "SYN-FIN", "TCP SYN-FIN"]
    TCP_SYN_VARIATIONS = ["Flood", "DoS", "Denial of Service", "Attack"]

    # Constant for searching SSH dictionary brute force attacks -> Done
    SSH_DICTIONARY_BRUTE_FORCE_BASE_KEYWORDS = ["SSH Dictionary", "SSH Brute Force", "SSH Password Guessing", "SSH Password Cracking", "SSH", "SSH Login Guessing", "SSH Password Spraying"]
    SSH_DICTIONARY_BRUTE_FORCE_VARIATIONS = ["Attack", "Technique", "Method", "Tool", "Hack", "Crack", "Attempt", "Threat", "Vulnerability", "Exploit", "Breach", "Intrusion", "Brute Force"]
    
    # Constants for searching attacks UDP attacks -> Done
    UDP_FLOOD_BASE_KEYWORDS = ["UDP"]
    UDP_FLOOD_VARIATIONS = ["Flood", "DoS", "Denial of Service", "Attack", "Amplification"]

    # Constants for searching attacks HTTP Dos attacks 
    HTTP_FLOOD_BASE_KEYWORDS = ["HTTP", "HTTP GET", "HTTP POST", "HTTP Request"]
    HTTP_FLOOD_VARIATIONS = ["Flood", "Flooding", "DoS", "DDoS", "Denial of Service", "Attack", "Bombardment", "Overload"]

    # Constants for SMTP Brute Force attack
    SMTP_BRUTE_FORCE_BASE_KEYWORDS = ["SMTP", "SMTP Dictionary", "SMTP Brute Force", "SMTP Password Guessing", "SMTP Password Cracking"]
    SMTP_BRUTE_FORCE_VARIATIONS = ["Brute Force", "Dictionary Attack", "Password Guessing", "Password Cracking", "Credential Stuffing"]

    # Constants for searching attacks Telnet Brute Force attack
    TELNET_BRUTE_FORCE_BASE_KEYWORDS = ["Telnet", "Telnet Dictionary", "Telnet Brute Force", "Telnet Password Guessing", "Telnet Password Cracking"]
    TELNET_BRUTE_FORCE_VARIATIONS = ["Brute Force", "Dictionary Attack", "Password Guessing", "Password Cracking", "Credential Stuffing"]

    # Constants for searching attacks Slowerloris attack
    SLOWLORIS_BASE_KEYWORDS = ["SlowLoris", "Slowloris Attack", "Slow HTTP"]
    SLOWLORIS_VARIATIONS = ["Attack", "DoS", "DDoS", "Denial of Service", "Overload", "Bombardment", "Low Bandwidth", "Incomplete HTTP Requests"]

    # Constants for HTTP Dictionary Brute Force attack
    HTTP_BRUTE_FORCE_BASE_KEYWORDS = ["HTTP", "HTTP Dictionary", "HTTP Brute Force"]
    HTTP_BRUTE_FORCE_VARIATIONS = ["Brute Force", "Dictionary Attack", "Password Guessing", "Password Cracking", "Credential Stuffing"]

    # Constants for searching attacks HTTPS Flood attack
    HTTPS_BRUTE_FORCE_BASE_KEYWORDS = ["HTTPS", "HTTPS Dictionary", "HTTPS Brute Force"]
    HTTPS_BRUTE_FORCE_VARIATIONS = ["Brute Force", "Dictionary Attack", "Password Guessing", "Password Cracking", "Credential Stuffing"]

    # Constants for searching attacks IRC Dictionary Brute Force attack
    IRC_BRUTE_FORCE_BASE_KEYWORDS = ["IRC", "IRC Dictionary", "IRC Brute Force"]
    IRC_BRUTE_FORCE_VARIATIONS = ["Brute Force", "Dictionary Attack", "Password Guessing", "Password Cracking", "Credential Stuffing"]

    # Constants for searching attacks Mirai Botnet
    MIRAI_BASE_KEYWORDS = ["Mirai", "Botnet", "IoT", "DDoS", "Mirai Botnet"]
    MIRAI_VARIATIONS = ["Distributed Denial of Service", "DDoS", "Brute Force", "Attack", "Infection", "IoT Malware", "Device Exploit", "Telnet Attack", "Remote Code Execution", "Compromise", "Botnet Expansion"]

    # Constants for searching attacks Web-based attacks 
    COMMAND_INJECTION_BASE_KEYWORDS = [ "Command", "Code", "Shell ", "OS Command Injection"]

    COMMAND_INJECTION_VARIATIONS = ["Injection", "Attack", "Execution Vulnerability", "Vulnerability" ]
