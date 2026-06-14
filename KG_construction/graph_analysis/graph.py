import pandas as pd
import json 
from llm.openai_api import OpenAIAPI
from llm.constants import LLMConstants
from util import Util
import logging
from tqdm import tqdm
from typing import List, Dict, Any, Sequence, Tuple
from .configs import GraphAnalysisConfig
import numpy as np
import json 
import ast
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from .prompts import LabellingPrompts
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram
from matplotlib import pyplot as plt

from scipy.spatial.distance import pdist, squareform
from sklearn.preprocessing import normalize
import hashlib
import os 

"""
This script analyzes different clustering algorithms and aims to identify an algorithm that can achieve the following objectives: 
    1) Maximazing inter-cluster distance between clusters: This is to ensure that semantically different stategies are not to be clustered into one group and also ensure that we endup with as many unique strategies as possible.
    2) Maximazing intra distance between points within the cluster so only 1 or close sample is need to sample from this cluster: This is to ensure that only need to sample a very small subset of features from the group to understand the strategies in this group. 

Problem definition and notation description: 

* Set S = {s₁, s₂, ..., sₙ} where sᵢ ∈ ℝᵈ
* Clustering C = {C₁, C₂, ..., Cₖ} where each Cᵢ is a cluster
We need to find an algorithm that first satififies 1 and then within the identified group satify 2. 
"""

class Graph: 
    CLUSTERING_SEED = 32 # Seed for clustering algorithm

    # The threshold detrmines the cut off when merging strategy groups. 
    # Theshold can be interpreted as dissimilarity between stategy groups e.g. threshold = 0 means that two strategies must be IDENTIFICAL to be merged into the same cluster likewise threshold 1 means that completely different strategies can be merged as one group. 
    # Here we set thershold to 0.45 meaning that we allow MAX 0.45 dissimilarity for merges  
    THRESHOLD = 0.45 # Threshold for stopping the clustering algorithm
    def __init__(self, cache_path:str):
        self.logger = logging.getLogger(__name__)
        self.cache_path = cache_path

    @staticmethod
    def clean_text(text):
        if not isinstance(text, str):
            return text
        try:
            # Remove or replace problematic characters
            cleaned = text.encode('utf-8', errors='ignore').decode('utf-8')
            return cleaned
        except Exception:
            return str(text)
        
    @staticmethod
    def process(input_path: str, attack_name: str)->str:
        output_path = os.getcwd() + "output/step4/" + attack_name + "_transformed.csv"
        Util.check_and_create_path(output_path)
        
        # Read CSV with explicit encoding handling
        df = pd.read_csv(input_path, encoding='utf-8', encoding_errors='replace')
        
        rows = []
        
        for _, row in df.iterrows():
            # Skip NaN and empty strategy rows
            empty_strategy = '{"strategies": []}'
            if pd.isna(row["README Content"]) or row["README Content"] == empty_strategy: 
                continue

            try:
                strategies = ast.literal_eval(row["Repository Graph"])["strategies"]
                
                for strategy in strategies:
                    # Clean the strings before adding to rows
                    cleaned_row = [
                        Graph.clean_text(row["Repository URL"]),
                        Graph.clean_text(strategy["name"]),
                        Graph.clean_text(strategy["description"]),
                        Graph.clean_text(row["README Content"])
                    ]
                    rows.append(cleaned_row)
                    
            except Exception as e:
                print(f"Error processing row: {e}")
                continue

        processed_df = pd.DataFrame(rows, columns=["Repository URL", "Name", "Description", "README Content"])
        
        # Write to CSV with error handling
        try:
            processed_df.to_csv(output_path, index=False, encoding='utf-8', errors='replace')
        except UnicodeEncodeError:
            # Fallback method if the first attempt fails
            processed_df.to_csv(output_path, index=False, encoding='ascii', errors='ignore')
    

        return output_path
    
    @staticmethod
    def get_hash(text: str, algo: str = "sha256") -> str:
        text_bytes = text.encode('utf-8')

        if algo == 'md5':
                hash_obj = hashlib.md5(text_bytes)
        elif algo == 'sha1':
            hash_obj = hashlib.sha1(text_bytes)
        elif algo == 'sha512':
            hash_obj = hashlib.sha512(text_bytes)
        else:  # default to sha256
            hash_obj = hashlib.sha256(text_bytes)
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def add_hash_column(input_path: str, output_path: str, column_name: str = "Hash") -> None:
        df = pd.read_csv(input_path)

        df["Strategy ID"] = df.apply(lambda row: Graph.get_hash(row["Name"] + row["Description"]), axis=1)

    def transfrom_to_embedding(self, graph_data_path:str, attack_name: str, 
                               api: OpenAIAPI, cache_field:str = "Transform embedding", step:str ="step4")->str:
        """
        Transform element descriptions into vector embeddings using the specified model. 
        """
        output_path = os.getcwd() + f"/output/{step}/" + attack_name + "_embedding_data.csv"
        column_name = "Embedding"

        df = Util.prepare_dataframe(column_name, graph_data_path, output_path)
        df[column_name].astype("object") # Ensure the column is of type object, otherwise save will throw an ValueError

        start_index = Util.load_cache(cache_field, self.cache_path, self.logger)    
        self.logger.info(f"Transforming  entities to embeddings using {api.model}.")

        for index, row in tqdm(df.iloc[start_index:].iterrows(), total=len(df) - start_index):
    
            embedding = self._transform_to_embedding(row, api, index)
            embedding = json.dumps(embedding)
            Util.save(self.cache_path, cache_field, column_name, embedding, df, index, output_path)

        return output_path

    def group_strategies(self, graph_data_path:str, output_path: str, save_dendogram: str=None)->None:
        """
        Group strategies based on their embeddings using Hierarchical Agglomerative Clustering (HAC).

        Reasons for HAC:
        - No need to pre-specify number of clusters as in k-means
        - Produces a hierarchical structure that can be cut at different levels
        - Provides trasability of the clustering process
        - Handles varying cluster shapes and sizes

        :param graph_data_path: The path to the graph data. MUST contain an "Embedding" column.
        :param output_path: The path to save the output.
        :param save_dendogram: The path to save the dendogram plot.
        """
        #TODO: Merge changes from analyze.py file 
        Util.check_and_create_path(output_path) 
        graph_df = pd.read_csv(graph_data_path)
        cluster_df = graph_df.copy()
        column_name = "Cluster"

        embeddings = np.vstack(graph_df.Embedding.apply(ast.literal_eval).values)

        distance_matrix = self._get_distance_matrix(embeddings)
        cluster_labels = self._cluster(distance_matrix, graph_df["Name"].values, save_dendogram)

        metrics = self.evaluate_clustering(distance_matrix, cluster_labels)
        self.logger.info(f"Clustering metrics: {metrics}")

        cluster_df[column_name] = cluster_labels
        cluster_df.to_csv(output_path, index=False)
        self.logger.info(f"Strategies grouped based on embeddings. Results saved to {output_path}.")

    def label_groups(self,  attack_name: str, graph_data_path:str, output_path: str, api: OpenAIAPI, score_save_path :str)->None:
        column_name = "Group label"
        cache_field = "Group labelling"
        df = Util.prepare_dataframe(column_name, graph_data_path, output_path)
        start_index = Util.load_cache(cache_field, self.cache_path, self.logger)
        self.logger.info(f"Labelling group using {api.model}.")
        clustering_algo = "k-means++"

        self._cluster(df, clustering_algo, score_save_path, output_path) # TODO: Uncomment for next iteration!!!!!!
        
        df = pd.read_csv(output_path)
        df[column_name].astype("object") # Ensure the column is of type object, otherwise save will throw an ValueError

        types = df.Type.unique()

        # Send the clusters to gpt 4-for labelling
        logging.info("Sending the clusters to gpt 4-for labelling.")

        for element_type in tqdm(types, desc="Labelling clusters"):
            type_df = df[df.Type == element_type]
            numbers = np.array([int(s.split('-')[1]) for s in type_df.Cluster.unique()])

            for i in range(len(numbers)): 

                prefix = self._get_prefix(element_type) + "-" + str(i)
                cluster_description = self._get_cluster_description(type_df[type_df.Cluster == prefix])
                
                cluster_description = f"Attack Label: {attack_name}" + "\n" + cluster_description
            
                splits = self._get_description_splits(cluster_description, api, element_type, attack_name)
                
                group = []
                counter = 0

                for split in splits: 
                    # Please note taht for now we only sample ONE split per cluster to for labelling
                    # The first split is as long as the selected model can handle
                    if counter == 1: 
                        break 

                    # Send the cluster to gpt 4-for labelling
                    user_message = {"role": "user", "content": split }
                    system_prompt = {"role": "system", "content": self._get_label_prompt(element_type)}
                    messages = [system_prompt] + [user_message]

                    response, *http = api.send_chat_completion_request(messages, GraphAnalysisConfig.LABELLING_LLM)
                    response_content = Util.get_response_content(response)
                    group.append(response_content)
                    counter += 1
                    if response_content is None:
                        self._log_grouping_error(http, i)
                        raise Exception("Failed to get label a cluster see log for more information.")
                    
                if counter == 1: 
                    group = group[0]

                # Add the group for all entries in the cluster
                self._save_cluster_label(df, prefix, group, cache_field, column_name, output_path)
                
            self.logger.info("Grouping strategies completed.")


    def _transform_to_embedding(self, row, api :OpenAIAPI, index: int)->List[float]:
        description = self._get_descriptions(row)
        token_length = api.get_token_length_from_text(api.model, description) + LLMConstants.TOKEN_PER_MESSAGE
        
        if token_length > LLMConstants.LIMITS[api.model]["Input"]:
            self.logger.info(f"Strategy at index {index} exceeds the token limit for model {api.model}...trying a larger model text-embedding-3-large.")
            api.set_model("text-embedding-3-large")
            if token_length > LLMConstants.LIMITS[api.model]["Input"]: 
                self.logger.error(f"Strategy at index {index} exceeds the token limit for the large {api.model} model.")
                return None
            
        response = api.send_text_embedding_request(description)

        if response is None:
            self.logger.error(f"Failed to get response for strategy at index {index}.")
            raise Exception("Failed to get response for strategy.")
        
        return response.data[0].embedding
    
    def _get_descriptions(self, row: Dict[str, Any]) -> str:
        return f"Name: {row['Name']}\nDescription: {row['Description']}\n"
    

    def _get_distance_matrix(self, embeddings: np.ndarray, metric: str="cosine")->np.ndarray:
        """
        Get the pairwise distances between embeddings.
        """

        normalized_embeddings = normalize(embeddings)
        distances = pdist(normalized_embeddings, metric=metric) # (1 - cos sim)
        distance_matrix = squareform(distances) # convert to square matrix
        return distance_matrix

    def _find_optimal_k(self, matrix: list[float], range: Sequence[int], model : str="k-means++")->tuple[int, list[float]]:
        """
        Find the optimal number of clusters using the silhouette score.

        :return: The optimal number of clusters and the array silhouette scores.
        """
        scores = []
        for k in range:
            kmeans = KMeans(n_clusters=k, init=model, random_state=self.CLUSTERING_SEED)
            kmeans.fit(matrix)

            labels = kmeans.labels_
            average_score = silhouette_score(matrix, labels)
            scores.append(average_score)
        
        optimal_k = range[np.argmax(scores)]
        return optimal_k, scores
    
    def _add_cluster_labels(self, matrix: List[float], optimal_k: int, df: pd.DataFrame, model: str="k-means++", element_type: str="") -> None:
        """
        Adds cluster labels to dataframe
        """
        kmeans = KMeans(n_clusters=optimal_k, init=model, random_state=self.CLUSTERING_SEED)
        kmeans.fit(matrix)
        
        prefix = self._get_prefix(element_type)

        df["Cluster"] = [f"{prefix}-{label}" for label in kmeans.labels_]

        return df
    
    def _get_prefix(self, type: str)->str:
        if type.lower() in ["relation", "relationship"]:
            prefix = "Rel"
        elif type.lower() == "vulnerability":
            prefix = "Vul"
        else:
            prefix = type[:3].capitalize()
        
        return prefix

    def _get_cluster_description(self, df: pd.DataFrame)->str:
        cluster = ""
        delimiter = "<SEP>\n"
        for index, row in df.iterrows():
            cluster += f'{row["Type"]} {index + 1}:\n'
            cluster += self._get_descriptions(row) + delimiter
        return cluster

    
    def _split_strategies(self, strategies: str, model :OpenAIAPI, attack_name: str) -> List[str]:
        """
        Split the strategies into a list, recursively removing the last strategy if the token limit is exceeded.
        """
        strategies_list = strategies.split("<SEP>")  
        splits = []

        def recursive_split(model: str, strat_list: List[str]) -> None:
            if not strat_list:
                return
            curren_split = "<SEP>\n".join(strat_list)
            total_tokens = OpenAIAPI.get_token_length_from_text(model, curren_split)
            
            if total_tokens <= LLMConstants.LIMITS[model]["Input"]:
                if curren_split != "" and curren_split != "\n":
                    if "Attack Label" not in curren_split:
                        curren_split = f"Attack Label: {attack_name}\n" + curren_split
                    splits.append(curren_split)
            else:
                recursive_split(model, strat_list[:-1]) 
                if strat_list[-1]: 
                    recursive_split(model, [strat_list[-1]])

        recursive_split(model, strategies_list)
        return splits
        
    def _save_cluster_label(self, df: pd.DataFrame, cluster_num: int, 
                            group: str, cache_field: str, column_name :str, output_path :str)->None:
        """
        Save the cluster label to the dataframe.
        """
        df.loc[df.Cluster == cluster_num, column_name] = group
        df.to_csv(output_path, index=False)
        # Util.write_cache(self.cache_path, cache_field, cluster_num+1) # TODO for now do not write to cache, the clusternum is combinatio of type and number

        self.logger.info(f"Group label for cluster {cluster_num} saved to the dataframe.")

    def _get_description_splits(self, cluster_description: str, api: OpenAIAPI, type: str, attack_name: str)->List[str]: # TODO: All openai models needs to replace with ChatCompletionLLM
        user_message = {"role": "user", "content": cluster_description }
        system_mesaage = {"role": "system", "content": self._get_label_prompt(type)}
        messages = [system_mesaage] + [user_message]
        total_token_length = OpenAIAPI.get_token_length_from_messages(api.model, messages)
        splits = [cluster_description]

        if total_token_length > LLMConstants.LIMITS[api.model]["Input"]:
            logging.error(f"Cluster  exceeds the token limit for model {api.model}....spliting the cluster by new line")
            splits = self._split_strategies(cluster_description, api.model, attack_name)
        
        return splits
    
    def _get_label_prompt(self, type: str)->str:
        if type in ["relation", "relationship"]:
            return LabellingPrompts.RELATIONSHIP
        elif type == "Vulnerability":
            return LabellingPrompts.VULNERABILITY
        elif type == "Process":
            return LabellingPrompts.PROCESS
        elif type == "Success":
            return LabellingPrompts.SUCCESS
        elif type == "entity":
            return LabellingPrompts.ENTITY
        elif type == "strategy":
            return LabellingPrompts.STRATEGY
        else: 
            raise ValueError(f"Invalid type {type} for getting label prompt. Function _get_label_prompt")
    
    def plot_dendrogram(model, save_path :str, max_clusters=10, **kwargs)->None:
        """
        Plot a dendogram and show LASTP clusters.
        :param model: Fitted AgglomerativeClustering model
        :param max_clusters: Maximum number of clusters to show. 

        Code source: https://scikit-learn.org/stable/auto_examples/cluster/plot_agglomerative_dendrogram.html

        Note: This function ONLY works with AgglomerativeClustering models and shows truncated dendrograms.
        """
        # Create linkage matrix
        counts = np.zeros(model.children_.shape[0])
        n_samples = len(model.labels_)
        for i, merge in enumerate(model.children_):
            current_count = 0
            for child_idx in merge:
                if child_idx < n_samples:
                    current_count += 1
                else:
                    current_count += counts[child_idx - n_samples]
            counts[i] = current_count

        linkage_matrix = np.column_stack(
            [model.children_, model.distances_, counts]
        ).astype(float)

        fig_width = max(15, max_clusters * 1.5)
        plt.figure(figsize=(fig_width, 10))

        dendrogram(
            linkage_matrix,
            truncate_mode='lastp', 
            p=max_clusters,  
            show_leaf_counts=True,  
            leaf_rotation=90,
            leaf_font_size=8,
            show_contracted=True,  
            **kwargs
        )

        plt.title(f"Hierarchical Clustering Dendrogram (Top {max_clusters} Clusters)")
        plt.xlabel('Cluster Size')
        plt.ylabel('Distance')

        plt.tight_layout()
        plt.savefig(save_path)
        return plt.gcf()
    

    def select_k_representatives(self, embeddings: np.ndarray, 
                                    clusters: np.ndarray,
                                    k: int = 1,
                                    metric: str = 'cosine') -> Tuple[Dict[int, List[Tuple[int, np.ndarray, float]]], List[int]]:
        """
        Labels the most representative strategies for each cluster by populating "Representing column",
        this funtion selects k points that minimizes the sum of distances to all other points in the cluster.
        Meaning that selected points are "sementically close" to all other points in the cluster.

        Note: points that are not selected as representatives are marked with -1 in the "Representing" column.
        
        :param embeddings: Array of embeddings
        :param clusters: Array of cluster assignments
        :param k: Number of representatives to select
        :param metric: Distance metric to use for calculating distances
        :return: Tuple of (cluster_representatives dict, list of representing values)
        """
        cluster_representatives = {}
        representing = [-1] * len(embeddings) 
        
        for cluster_id in np.unique(clusters):
            cluster_mask = clusters == cluster_id
            cluster_indices = np.where(cluster_mask)[0]
            cluster_embeddings = embeddings[cluster_mask]
            
            if len(cluster_embeddings) <= k:
                
                cluster_distances = squareform(pdist(cluster_embeddings, metric=metric))
                sum_distances = np.sum(cluster_distances, axis=1)
                representatives = [(idx, embeddings[idx], sum_distances[i]) 
                                for i, idx in enumerate(cluster_indices)]
                
                for idx, _, _ in representatives:
                    representing[idx] = cluster_id
                cluster_representatives[cluster_id] = representatives
                continue
        
            cluster_distances = self._get_distance_matrix(cluster_embeddings, metric)
            sum_distances = np.sum(cluster_distances, axis=1)
            
            representative_local_indices = np.argsort(sum_distances)[:k]
            
            representatives = [(cluster_indices[local_idx], 
                            cluster_embeddings[local_idx],
                            sum_distances[local_idx]) 
                            for local_idx in representative_local_indices]
            
            for idx, _, _ in representatives:
                representing[idx] = cluster_id
                
            cluster_representatives[cluster_id] = representatives
        
        return cluster_representatives, representing

    def _save_representatives(self, sample: int, embeddings: List[float], clusters: List[int], 
                            embedding_df: pd.DataFrame, output_dir) -> None:
        """
        Save all strategies to a CSV file, marking representatives with their cluster ID
        and non-representatives with -1 in the 'Representing' column.
        """
        _, representing = self.select_k_representatives(embeddings, clusters, k=sample)
        
        output_df = embedding_df.copy()
        output_df['Representing'] = representing
        output_path  = f"{output_dir}/all_strategies_with_representatives.csv"
        # Save to CSV
        output_df.to_csv(output_path, index=False)

        return output_path

    def create_unified_graph(self, embedding_path :str, attack_name :str, threshold: float=None, k: int=5, step: str="step5")->str:
        """
        Create a unified graph from the embeddings of the strategies.
        """
        output_dir = os.getcwd() + f"/output/{step}/" + attack_name 
        self.logger.info("Creating unified graph from embeddings.")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        embedding_df = pd.read_csv(embedding_path)

        embeddings = np.vstack(embedding_df.Embedding.apply(ast.literal_eval).values)
        distance_matrix = self._get_distance_matrix(embeddings)

        if threshold is None:
            threshold = Graph.THRESHOLD

        model = AgglomerativeClustering(
            n_clusters=None,
            distance_threshold= threshold,
            metric='precomputed',
            linkage='complete'
        )

        clusters = model.fit_predict(distance_matrix)
        dendo_path = f"{output_dir}/dendrogram.png"
        graph_path = f"{output_dir}/unified_graph.csv"
        self.logger.info(f"Number of unique clusters: {len(np.unique(clusters))}")

         #Graph.plot_dendrogram(model, dendo_path, max_clusters=10,  labels=embedding_df["Name"].values)

        embedding_df["Cluster ID"] = clusters

        # Sample the first X sample and save to the output directory
        output_file = self._save_representatives(k, embeddings, clusters, embedding_df, output_dir)

        self.logger.info(f"Unified graph created. Saving to {output_dir}/unified_graph.csv.")
        # Save the unified graph
        embedding_df.to_csv(graph_path, index=False)

        return output_file, dendo_path