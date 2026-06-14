

"""
Knowledge Graph Reasoning Module

This module applies reasoning rules to a knowledge graph to extract insights
about attack strategies, their relationships, and detection features.
"""

import networkx as nx
import pandas as pd
import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Union, Set, Any, Optional
from collections import defaultdict
import argparse
import logging
import ast
import pandas as pd
from typing import List, Dict, Tuple
import numpy as np
import json 
import ast
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram
from matplotlib import pyplot as plt

from scipy.spatial.distance import pdist, squareform
from sklearn.preprocessing import normalize


class KnowledgeGraphReasoner:
    
    def __init__(self, graph_file):
        """
        Initialize the Knowledge Graph Reasoner with a GraphML file.

        """
        self.graph = nx.read_graphml(graph_file)
        self.logger = logging.getLogger(__name__)

    
    def atomic_rule(self, attack_name: str) -> List[Dict[str, Any]]:
        """
        Get unique strategies for a given attack.
        """
        attack_id = f"attack:{attack_name}"
        
        if attack_id not in self.graph:
            raise ValueError(f"Attack '{attack_name}' not found in the knowledge graph.")
        
        unique_strategies = []
        for _, element, edge_data in self.graph.out_edges(attack_id, data=True):
            if edge_data.get('relation') == 'hasStrategy':
                # Check if this strategy is a representative
                element_data = self.graph.nodes[element]
                if element_data.get('is_representative') is True:
                    strategy = {
                        "name": element_data.get('name', ''),
                        "description": element_data.get('description', ''),
                        "url": element_data.get('url', ''),
                        "cluster_id": element_data.get('cluster_id', ''),
                        "strategy_id": element
                    }
                    unique_strategies.append(strategy)

        
        return unique_strategies
    
    @staticmethod
    def _no_attack_found_error(attack_name: str):
        """
        Raise an error if the attack is not found in the knowledge graph.
        """
        raise ValueError(f"Attack '{attack_name}' not found in the knowledge graph.")
    
         
    def fin_eval_path(self, attack_name :str): 
        """
        Find evolutionary/combination paths for a given attack.

        :return : Connection path between different strategies
        """

        attack_id = f"attack:{attack_name}"
        if attack_id not in self.graph:
            self._no_attack_found_error(attack_name)
        clusters = set()

        for _, cluster, edge_data in self.graph.out_edges(attack_id, data=True):
            if edge_data.get('relation') == 'hasCluster':
                clusters.add(cluster)
        
        rep = []

        for cluster in clusters:
            for _, element, cluster_edge_data in self.graph.out_edges(cluster, data=True):
                if cluster_edge_data.get('relation') == 'hasElement':
                    element_data = self.graph.nodes[element]
                    if element_data.get('node_class') == 'Strategy' and element_data.get('is_representative'):
                        rep.append(element)
                        break

        if len(clusters) != len(rep):
            raise ValueError(f"Graph data is incosistent. Found {len(clusters)} clusters but {len(rep)} representative strategies.")

        all_paths = {} 

        for strategy in rep:
            path = {}
           

            for _, repo_data, edge_data in self.graph.out_edges(strategy, data=True):
                if edge_data.get('relation') == 'hasSource' and repo_data.get('node_class') == 'Strategy':

                    repo_node = self.graph.nodes[repo_data]
                    cluster_id = self.graph.nodes[repo_data].get('cluster_id')
    
                    path[repo_node] = {}

                    for _, child_data, edge_data in self.graph.out_edges(repo_data, data=True):
                        if edge_data.get('relation') == 'Implements' and element_data.get('node_class') == 'Strategy':
                            strategy_node = self.graph.nodes[child_data]
                            cluster_id = strategy_node.get('cluster_id')

                            path[repo_node][strategy_node] = {} 

                            for _, middle_element, edge_data in self.graph.out_edges(cluster_id, data=True):
                                if edge_data.get('relation') == 'hasElement' and middle_node != child_data and \
                                middle_element != strategy and middle_element.get('node_class') == 'Strategy':
                                    middle_node = self.graph.nodes[middle_element]
                                    path[repo_node][strategy_node][middle_node] = []
                                    repo_id = f"repo:{repo_node['url']}|{attack_name}"

                                    for _, end_element, edge_data in self.graph.out_edges(repo_id, data=True):
                                        if edge_data.get('relation') == 'Implements' and end_element != middle_node and \
                                        end_element.get('node_class') == 'Strategy':
                                            end_node = self.graph.nodes[end_element]
                                            path[repo_node][strategy_node][middle_node].append(end_node)    

            root_node = self.graph.nodes[strategy]
            all_paths[root_node] = path                    



        for strategy, path in all_paths.items():

            direct_path = f"{strategy['name'] } ({strategy['description']}) -> Rep"

            for repo_node, mid_nodes in path.items():
                pass

    def find_evoluationary_paths(self, strategy_ids: List[str], attack_name: str):
        """
        Given a list of common strategies use the transitive inference rule to examine reasoning paths that can indicate
        evolution of strategies.
        """
        
        all_strategies = []
        for common_str_id in strategy_ids:
            evolutionary_path = {}
            common_cluster_id = None
            evolutionary_paths = {}

            for _, cluster, edge_data in self.graph.out_edges(common_str_id, data=True):
                if edge_data.get('relation') == 'belongsTo':
                    common_cluster_id = cluster
                    break

            possible_paths = set()
            
            for _, repo_node, cluster_edge_data in self.graph.out_edges(common_cluster_id, data=True):
                
                if cluster_edge_data.get('relation') == 'isImplementedIn':
                    repo_data = self.graph.nodes[repo_node]
                    repository_id = f"repo:{repo_data['url']}|{attack_name}"
                    possible_paths.add(repository_id)

            attack_clusters = set()
            

            attack_id = f"attack:{attack_name}"
            for _, cluster_id, edge_data in self.graph.out_edges(attack_id, data=True):
               
                if edge_data.get('relation') == 'hasCluster' and "feature" not in cluster_id:
                    if cluster_id != common_cluster_id:
                        attack_clusters.add(cluster_id)
            for cluster_id in attack_clusters:

                cluster_repos = set()
                for _, repo_node, cluster_edge_data in self.graph.out_edges(cluster_id, data=True):
                    if cluster_edge_data.get('relation') == 'isImplementedIn':
                        repo_data = self.graph.nodes[repo_node]
                        repository_id = f"repo:{repo_data['url']}|{attack_name}"
                        cluster_repos.add(repository_id)

                union = possible_paths.intersection(cluster_repos)
                if len(union) > 0:

                    for repo_id in union: 

                        for _, strategy, edge_data in self.graph.out_edges(repo_id, data=True):
                            if edge_data.get('relation') == 'Implements':
                                strategy_data = self.graph.nodes[strategy]

                                cluster_id = f"cluster:{strategy_data.get('cluster_id')}|{attack_name}|strategy"

                                if cluster_id == common_cluster_id or cluster_id in evolutionary_paths:
                                    continue

                                for _, strategy, edge_data in self.graph.out_edges(cluster_id, data=True):
                                    strategy_data = self.graph.nodes[strategy] 
                                    if edge_data.get('relation') == 'hasElement' and strategy_data.get('is_representative'):
                                        rep_strategy = strategy

                                        bridge_strategy = None
                                        break_for = False
                                        for _, strategy, edge_data in self.graph.out_edges(common_cluster_id, data=True):
                                            if edge_data.get('relation') == 'hasElement':
                                                strategy_data = self.graph.nodes[strategy]
                                                if strategy_data.get('node_class') == 'Strategy': 

                                                    for _, repo, edge_data in self.graph.out_edges(strategy, data=True):
                                                        if edge_data.get('relation') == 'hasSource' and repo == repo_id:
                                                            bridge_strategy = strategy
                                                            break_for = True
                                                            break
                                            
                                            if break_for:
                                                break
                                        
                                        if bridge_strategy is None: 
                                            raise ValueError(f"Bridge strategy not found for {repo_id}")
                                        

                                        org_str = self.graph.nodes[common_str_id].get('name')
                                        bridge_str = self.graph.nodes[bridge_strategy].get('name')
                                        evo_node = self.graph.nodes[rep_strategy]
                                        evo_str = evo_node.get('name')
                                        evolutionary_path = {
                                            "path": f"{org_str} - {bridge_str} - {evo_str}", 
                                            "evolution_strategy": {
                                                "name": evo_str,
                                                "url": evo_node.get('url', ''),
                                                "description": evo_node.get('description', '')
                                            }, 
                                            "confidence": len(union) / len(possible_paths)
                                        }

                                        evolutionary_paths[cluster_id] = evolutionary_path
                                        break
          

            all_strategies.append(evolutionary_paths)   
        return all_strategies
    

    def find_evoluationary_paths_1(self, strategy_ids: List[str], attack_name: str):
        """
        Given a list of common strategies use the transitive inference rule to examine reasoning paths that can indicate
        evolution of strategies.
        """
        
        all_strategies = []
        for common_str_id in strategy_ids:
            evolutionary_path = {}
            common_cluster_id = None
            evolutionary_paths = {}
            for _, cluster, edge_data in self.graph.out_edges(common_str_id, data=True):
                if edge_data.get('relation') == 'belongsTo':
                    common_cluster_id = cluster
                    break

            possible_paths = set()
            
            for _, repo_node, cluster_edge_data in self.graph.out_edges(common_cluster_id, data=True):
                
                if cluster_edge_data.get('relation') == 'isImplementedIn':
                    repo_data = self.graph.nodes[repo_node]
                    repository_id = f"repo:{repo_data['url']}|{attack_name}"
                    possible_paths.add(repository_id)

            attack_clusters = set()
            

            attack_id = f"attack:{attack_name}"
            for _, cluster_id, edge_data in self.graph.out_edges(attack_id, data=True):
               
                if edge_data.get('relation') == 'hasCluster' and "feature" not in cluster_id:
                    if cluster_id != common_cluster_id:
                        attack_clusters.add(cluster_id)

            for cluster_id in attack_clusters:
                cluster_repos = set()
                for _, repo_node, cluster_edge_data in self.graph.out_edges(cluster_id, data=True):
                    if cluster_edge_data.get('relation') == 'isImplementedIn':
                        repo_data = self.graph.nodes[repo_node]
                        repository_id = f"repo:{repo_data['url']}|{attack_name}"
                        cluster_repos.add(repository_id)

 
                union = possible_paths.intersection(cluster_repos)
                if len(union) > 0:

                    for repo_id in union: 

                        for _, strategy, edge_data in self.graph.out_edges(repo_id, data=True):
                            if edge_data.get('relation') == 'Implements':
                                strategy_data = self.graph.nodes[strategy]

                                cluster_id = f"cluster:{strategy_data.get('cluster_id')}|{attack_name}|strategy"

                                if cluster_id == common_cluster_id or cluster_id in evolutionary_paths:
                                    continue

                                for _, strategy, edge_data in self.graph.out_edges(cluster_id, data=True):
                                    strategy_data = self.graph.nodes[strategy] 
                                    if edge_data.get('relation') == 'hasElement' and strategy_data.get('is_representative') == True:
                                        rep_strategy = strategy

                                        bridge_strategy = None
                                        break_for = False
                                        for _, strategy, edge_data in self.graph.out_edges(common_cluster_id, data=True):
                                            if edge_data.get('relation') == 'hasElement':
                                                strategy_data = self.graph.nodes[strategy]
                                                if strategy_data.get('node_class') == 'Strategy': 

                                                    for _, repo, edge_data in self.graph.out_edges(strategy, data=True):
                                                        if edge_data.get('relation') == 'hasSource' and repo == repo_id:
                                                            bridge_strategy = strategy
                                                            break_for = True
                                                            break
                                            
                                            if break_for:
                                                break
                                        
                                        if bridge_strategy is None: 
                                            raise ValueError(f"Bridge strategy not found for {repo_id}")

                                        org_str = self.graph.nodes[common_str_id].get('name')
                                        bridge_str = self.graph.nodes[bridge_strategy].get('name')
                                        evo_node = self.graph.nodes[rep_strategy]
                                        evo_str = evo_node.get('name')
                                        evolutionary_path = {
                                            "path": f"{org_str} - {bridge_str} - {evo_str}", 
                                            "evolution_strategy": {
                                                "name": evo_str,
                                                "url": evo_node.get('url', ''),
                                                "description": evo_node.get('description', '')
                                            }, 
                                            "confidence": len(union) / len(possible_paths)
                                        }

                                        evolutionary_paths[cluster_id] = evolutionary_path
                                        break
          

            all_strategies.append(evolutionary_paths)   
        return all_strategies


    def cross_family_rule(self, threshold: float = 0.55) -> List[Dict[str, str]]:

        attacks = self.get_all_attack_nodes()
        total_attacks = len(attacks)

        attack_data = []
        for idx, attack in enumerate(attacks):
            attack_name = self.graph.nodes[attack].get('name', f"Attack {idx}")
            rep_strategies = []
            

            for _, cluster, edge_data in self.graph.out_edges(attack, data=True):
                if edge_data.get('relation') == 'hasCluster':
                    for _, element, cluster_edge_data in self.graph.out_edges(cluster, data=True):
                        if cluster_edge_data.get('relation') == 'hasElement':
                            element_data = self.graph.nodes[element]
                            if element_data.get('node_class') == 'Strategy' and element_data.get('is_representative') is True:

                                embedding = element_data.get('embedding', [])
                                strategy_name = element_data.get('name', 'Unknown')
                                

                                rep_strategies.append({
                                    'node': element,
                                    'name': strategy_name,
                                    'cluster_id': cluster,
                                    'embedding': embedding
                                })
                                break

            attack_data.append({
                'attack_node': attack,
                'attack_name': attack_name,
                'strategies': rep_strategies
            })


        unique_strategy_nodes = set()

        unique_strategies = []

        for i in range(len(attack_data)):
            attack_i = attack_data[i]
            
            for j in range(i+1, len(attack_data)):  
                attack_j = attack_data[j]
                
                
                for strat_i in attack_i['strategies']:
                    for strat_j in attack_j['strategies']:
                     
                        if self.is_similar(strat_i['embedding'], strat_j['embedding'], threshold):
                          
                            if strat_i['node'] not in unique_strategy_nodes:
                                unique_strategy_nodes.add(strat_i['node'])
                                unique_strategies.append({
                                    'name': strat_i['name'],
                                    'description': self.graph.nodes[strat_i['node']].get('description', '')
                                })
                            

                            if strat_j['node'] not in unique_strategy_nodes:
                                unique_strategy_nodes.add(strat_j['node'])
                                unique_strategies.append({
                                    'name': strat_j['name'],
                                    'description': self.graph.nodes[strat_j['node']].get('description', '')
                                })
        
        return unique_strategies


                
    def is_similar(self, embedding1: Union[str, List[str]], 
                embedding2: Union[str, List[str]], 
                threshold: float = 0.8) -> bool:

        embedding1 = ast.literal_eval(embedding1)
        embedding2 = ast.literal_eval(embedding2)
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)
        
        if embedding1 == embedding2:
            return True 
        
        dot_product = np.dot(vec1, vec2)
        norm_a = np.linalg.norm(vec1) 
        norm_b = np.linalg.norm(vec2)
        
        if norm_a == 0 or norm_b == 0:
            return False
        
        similarity = dot_product / (norm_a * norm_b)
        
        return similarity >= threshold

    def get_all_attack_nodes(self) -> List[str]:
        """
        Get all attack nodes from the knowledge graph.
        """
        return [node for node, data in self.graph.nodes(data=True) if data.get('node_class') == 'Attack']


    def infer_feature_coverage(self) -> List[Dict[str, Any]]:
        """
        Infer feature coverage for a given attack and strategy.
        """

        attacks = self.get_all_attack_nodes()

        feature_coverage = {}

        for attack in attacks:
            coverage = {}
            total_features = 0
            attack_name = self.graph.nodes[attack].get('name', 'Unknown')
            attack_id = f"attack:{attack_name}"
            cluster_ids = set()


            for _, cluster, edge_data in self.graph.out_edges(attack_id, data=True):
                if edge_data.get('relation') == 'hasCluster':
                    cluster_data = self.graph.nodes[cluster]

                    if cluster_data["cluster_type"] != "feature":
                        continue
                    cluster_ids.add(cluster)

            for cluster_id in cluster_ids:
                coverage[cluster_id] = {}
                coverage[cluster_id]["elements"] = 0
                representative_feature = None
                for _, element, edge_data in self.graph.out_edges(cluster_id, data=True):
                    if edge_data.get('relation') == 'hasElement':
                        element_data = self.graph.nodes[element]
                        if element_data.get('node_class') == 'Feature':
                            
                            coverage[cluster_id]["elements"] += 1
                            if element_data.get('is_representative') == True and representative_feature is None:
                                coverage[cluster_id]["feature_name"] = element_data['name']
                                coverage[cluster_id]["feature_description"] = element_data['description']
                                coverage[cluster_id]["rationale"] = element_data['rationale']
                                coverage[cluster_id]["code"] = element_data['code']
                                representative_feature = element_data['name']
                                
                total_features += coverage[cluster_id]["elements"]

            for feature in coverage: 
                coverage[feature]["coverage_score"] = coverage[feature]["elements"] / total_features * 100 if total_features > 0 else 0
            feature_coverage[attack_name] = coverage
            
        return feature_coverage


