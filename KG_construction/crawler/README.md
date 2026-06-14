# Repository Crawler

The `repository_crawler.py` module provides a `RepositoryCrawler` class that enables crawling GitHub repositories for README files and code snippets based on a keyword search.

## Table of Contents

- [Requirements](#requirements)
- [Usage](#usage)
- [Logging](#logging)


## Requirements

To use the `RepositoryCrawler` class, you need to have the following:

- Python 3.x
- GitHub Personal Access Token (Fine-grained)

### GitHub Personal Access Token

In order to access the GitHub API and crawl repositories, you need to provide a GitHub Personal Access Token with fine-grained access. Follow the steps outlined in the reference to obtain the token:

https://docs.github.com/en/enterprise-server@3.9/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens


To use the token in your code, you have two options:

1. Set the token as an environment variable:
  - Open a terminal or command prompt.
  - Set the environment variable using the following command:
    ```
    export GITHUB_PERSONAL_FINE_GRAINED_ACCESS_TOKEN=your_token
    ```
  - Replace `your_token` with your actual GitHub Personal Access Token.

2. Create a `.env` file in the project directory and add the token:
  - Create a new file named `.env` in the same directory as `repository_crawler.py`.
  - Open the `.env` file and add the following line:
    ```
    GITHUB_PERSONAL_FINE_GRAINED_ACCESS_TOKEN=your_token
    ```
  - Replace `your_token` with your actual GitHub Personal Access Token.

## Usage
To use the crawl for read me files follow these steps:

1. Replace base keywords and its possible variations in `crawler_constants.py`.

```python
    # Constants for searching attacks 
    TCP_SYN_BASE_KEYWORDS = ["TCP", "SYN", "TCP SYN"]
    TCP_SYN_VARIATIONS = ["Flood", "DoS", "Denial of Service", "Attack"]
```

2. Generate keyword combination to search for.
```python
# Crawl for relevant URLs for TCP SYN Flood attack
keywords = crawler.generate_keyword_combinations(CrawlerConstants.TCP_SYN
_BASE_KEYWORDS, CrawlerConstants.TCP_SYN_VARIATIONS)
```
3. Specify the output file where to store found url of repositories.
```python
repo_file_path = os.getcwd() + "/" +"TCP SYN Flood/repo_urls.txt"
```
4. Load the repository urls and pull readme content into a csv.
```python
  readme_file_path = os.getcwd() + "/" +"readme_data.csv"
  crawler.crawl_repos_for_readme(repo_urls, readme_file_path)
```

The created csv file store values in the following format: 
```python
url, readme
```

## Logging
The `RepositoryCrawler` class logs all errors and progress information to a log file named `repository_crawler.log` in the current directory. This log file provides detailed information about the crawling process, including any encountered errors and the progress.
