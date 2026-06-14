"""
This script is$ pipeline for threat analysis. It takes as an input a set of attack to investigate and outputs the possible muations space for the attack. Including: 
    - Attack strategies 
    - The origin of the strategies
    - The corresponding features that manifest the strategies
"""
import logging
import os

from crawler.repository_crawler import RepositoryCrawler
from crawler.crawler_constants import CrawlerConstants
from util import Util
from repository_graph.kg_constructor import KGConstructor
from llm import OpenAIAPI 
from graph_analysis.graph import Graph


log_file_path = os.path.join(os.path.dirname(__file__), "output", "logs", "create_kg.log")
os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
logging.basicConfig(filename=log_file_path, level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

cache_file_path = os.path.join(os.path.dirname(__file__), "storage", "cache", "cache.json")
Util.check_and_create_path(cache_file_path)


def run_kg_construction_pipeline(attack_name, description, keywords, max_round=3, derive_features: bool=False):
    repository_crawler = RepositoryCrawler(cache_file_path)
    api = OpenAIAPI(model="gpt-4o-mini")
    kg_constructor = KGConstructor(api, cache_file_path)
    graph_creator = Graph(cache_file_path)
    logger = logging.getLogger(__name__)

    # 1. PARAMETER EXTRACTION AND EMBEDDING
    ##  Retrieving data from Github ##
    ### Step 1. Retrieve all URLs implementing the attack 
    repo_urls = repository_crawler.crawl_repo_for_relevant_urls(keywords, attack_name)
    logger.info(f"Retrieved {len(repo_urls)} repositories for attack {attack_name}")

    ### Step 2. Retrieve attack implementation documentation (README.md)
    _, readme_file_path = repository_crawler.crawl_repos_for_readme(repo_urls)
    logger.info(f"Retrieved READMEs for the attack {attack_name} and saved to {readme_file_path}")
    
    ## Strategy Extraction (using GPT-4/NER) ## 

    ## Step 3. Extract parameter mentions with descriptions & Store parameter-description pairs with metadata
    repo_graph_file = kg_constructor.create_repository_graph(attack_name, readme_file_path , max_rounds, description)
    logger.info(f"Created repository graph for attack {attack_name} and saved to {repo_graph_file}")#

    ## Step 4. Transform the extracted data into embeddings & Store the embeddings
    ## Note we must fist extract strategies from json elementes before transforming them into embeddings
    analyzer = Graph(cache_file_path)
    tranformed_data_path = analyzer.process(repo_graph_file, attack_name) # Process the data 
    
    api.model = "text-embedding-3-small" 
    embedding_path = analyzer.transfrom_to_embedding(tranformed_data_path, attack_name, api)
    logger.info(f"Transformed the extracted data into embeddings and saved to {attack_name}")
    
    ## Step 5. Cluster the embeddings to identify unique strategies
    k = 3 # Number of strategies per cluster to select as representative (per cluster basis)
    unified_graph_file, dendo_path = graph_creator.create_unified_graph(embedding_path, attack_name,k=k)
    logger.info(f"Selected strategies save to {unified_graph_file}, dendogram saved to {dendo_path}")
    
    
    ## OPTIONAL: 
    # 6. Analyze the code to derive observation points or point of manifastations 
    # a.  Retrieve the main functions from the code to anlyze as exhaustive search is not feasible
    if derive_features:
        max_rounds = 1
        kg_constructor.api.model="gpt-4o-mini"
        # Retrieve the main functions from the code to anlyze 
        main_func_path = kg_constructor.retrieve_main_functions(unified_graph_file, attack_name, description, max_rounds)
        logger.info(f"Retrieved main functions for attack {attack_name}")

        # b. Find features for strategies
        code_path = repository_crawler.crawl_repos_for_code(main_func_path, attack_name)
        logger.info(f"Retrieved code for attack {attack_name}")
        # c. Analyze the code to derive observation points
        obsv_path = kg_constructor.analyze_code(code_path, attack_name, max_rounds)

        # d. Transform features into embeddings
        api.model="text-embedding-3-small"
        # # Note: Convert features to name, description, and code embeddings format 
        _ = analyzer.transfrom_to_embedding(obsv_path, attack_name, api, step="step6")

        # e. Cluster the embeddings to identify unique features
        k  = 1 # Number of features per cluster to select as representative (per cluster basis)
        unified_graph_file, dendo_path = graph_creator.create_unified_graph(embedding_path, attack_name,k=k)
 
if __name__ == '__main__':
    ## Note: Custom define the base keywords and variations for the attack in the CrawlerConstants.py file

    #####RUN KG CONSTRUCTION PIPELINE #####
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keywords = [""] # Keywords ot search
    attack_name = "Attack name goes here "
    description = "Attack description goes here" # To eliminate unrelevant results
    
    run_kg_construction_pipeline(attack_name, description, keywords, max_round=3)


