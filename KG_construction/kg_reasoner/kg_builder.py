"""
Knowledge Graph Construction Module

This module builds a knowledge graph from the output of the Parameter Extraction and Embedding phase
and stores it in an efficient format for later reasoning.

Input:
- strategies.csv: Output from step 1.4 (url, readme, strategy, description, embedding_vector, cluster_id, is_representative)
- features.csv: Output from step 1.5 (feature, code, strategy_id, url)

Output:
- knowledge_graph.graphml: NetworkX GraphML file containing the constructed knowledge graph
- knowledge_graph.pkl: Pickled NetworkX graph for faster loading
"""

import networkx as nx
import pandas as pd
import numpy as np
import pickle
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse
import logging
import hashlib


class KnowledgeGraphBuilder:

    """
    Builds a knowledge graph from strategy and feature data.
    """
    
    def __init__(self, 
                 strategies_file: str, 
                 features_file: Optional[str] = None,
                 output_dir: str = "output"):
        """
        Initialize the KnowledgeGraphBuilder.
        
        :param strategies_file: Path to CSV file with strategies (from step 1.4)
        :param features_file: Path to CSV file with features (from step 1.5)
        :param output_dir: Directory to save the output graph
        
        """
        self.logger = logging.getLogger(__name__)

        self.strategies_file = strategies_file
        self.features_file = features_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.graph = nx.DiGraph(name="Attack Strategy Knowledge Graph")

        self.logger.info(f"Loading strategy data from {strategies_file}")
        self.strategies_df = pd.read_csv(strategies_file)
        
        self.logger.info(f"Loading feature data from {features_file}")
        
        if features_file is not None:
            self.features_df = pd.read_csv(features_file)
            self._rename_feature_df_columns()
        else:
            self.features_df = None
        
        self._rename_strategy_df_columns()
        self._add_strategy_id_column()

        self._extract_metadata() 

    def _rename_strategy_df_columns(self):
        self.strategies_df = self.strategies_df.rename(columns={
            "Cluster ID": "cluster_id",
            "Name": "name",
            "Description": "description",
            "Repository URL": "url",
            "README Content": "readme",
            "Representing": "is_representative",
            "Relevant": "is_relevant", 
            "Embedding": "embedding"
        })
    
    def _rename_feature_df_columns(self):
        self.features_df = self.features_df.rename(columns={
            "Strategy ID": "strategy_id",
            "Name": "name",
            "Description": "description",
            "Code": "code",
            "Rationale": "rationale", 
            "Embedding": "embedding", 
            "Cluster ID": "cluster_id",
            "Representing": "is_representative",
        })

    def _add_strategy_id_column(self)->None:
        self.strategies_df["strategy_id"] = self.strategies_df.apply(
                    lambda row: KnowledgeGraphBuilder.get_hash(row["name"] + row["description"]), axis=1)
    
    def _extract_metadata(self):
        """
        Extract useful metadata about the graph from the data files and summerize it.
        """
        self.num_strategies = len(self.strategies_df)
        
        self.num_features = len(self.features_df) if self.features_df is not None else 0
        
        # Identify a number of semantically unique clusters
        self.strategy_clusters = self.strategies_df['cluster_id'].unique()
        self.num_clusters = len(self.strategy_clusters)
        
        self.urls = self.strategies_df['url'].unique()
        self.num_repos = len(self.urls)
        
        self.logger.info(f"Found {self.num_strategies} strategies in {self.num_clusters} clusters")
        self.logger.info(f"Found {self.num_features} features")
        self.logger.info(f"Found {self.num_repos} repositories")

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

    def _init_graph(self, graph_file: str, attack_family: str):
        """
        Initialize the graph with the attack family and attack name. If existing_graph is provided,
        the new nodes will be added to it.
        """
        if graph_file is not None:
            self.logger.info("Using existing graph as base")
            self.graph = nx.read_graphml(graph_file)
            
            family_node_id = f"family:{attack_family}"
            if family_node_id in self.graph:
                self.logger.info(f"Attack family '{attack_family}' already exists in the graph")
            else:
                self.logger.info(f"Adding new attack family: {attack_family}")
                self._create_family_node(attack_family)
        else:
            self.logger.info("Creating entirely new graph")
            self._create_family_node(attack_family)

    def build_graph(self, attack_family: str, attack_name: str, graph_file: str = None):
        """
        Build the knowledge graph from the loaded data.
                
        The graph will have the following node types:
        - Family: Family that the attack belongs to 
        - Attack: The investigated attack (this is the root node of the following nodes)
        - Repository: URLs where attack strategies are implemented
        - Strategy: Parameters that control attack behavior
        - Feature: Code manifestations of strategies
        - Cluster: Groups of semantically similar strategies
                
        And the following edge types:
        - isImplementedIn: Attack -> Repository
        - hasChild: Family -> Attack
        - belongsToFamily: Attack -> Family
        - hasStrategy: Attack -> Strategy
        - belongsToAttack: Repository -> Attack
        - hasCluster: Attack -> Cluster
        - hasSource: Strategy -> Repository
        - Implements: Repository -> Strategy
        - manifestsAs: Strategy -> Feature
        - hasElement: Cluster -> Feature/Stratgy
        - belongsTo: Strategy/Feature -> Cluster
        """
        self.logger.info(f"Building knowledge graph for attack family: {attack_family}, attack name: {attack_name}")
        
        self._init_graph(graph_file, attack_family)

        # Create attack node and link to family
        # Assume that each builds adds a new attack to the graph
        # Build the tree top down from the attack node
        attack_node_id = f"attack:{attack_name}"
        if attack_node_id in self.graph:
            self.logger.warning(f"Attack '{attack_name}' \
                                already exists in the graph. Will add new data to existing attack." \
                                )
        else:
            self._create_attack_node(attack_name, attack_family)

        self._create_strategy_nodes(attack_name)

        if self.features_df is not None:
            self._create_feature_nodes(attack_name)
    
        self._add_graph_metadata()
        
        self.logger.info(f"Graph built with {len(self.graph.nodes)} nodes and {len(self.graph.edges)} edges")
        return self.graph

    def _create_family_node(self, attack_family: str):
        """Create a family node."""
        self.logger.info(f"Creating family node: {attack_family}")
        
        self.graph.add_node(
            f"family:{attack_family}",
            type="family",
            name=attack_family,
            node_class="Family"
        )
    
    def _create_attack_node(self, attack_name: str, attack_family: str):
        """Create an attack node and link to family."""
        self.logger.info(f"Creating attack node: {attack_name}")
        
        # Add attack node
        self.graph.add_node(
            f"attack:{attack_name}",
            type="attack",
            name=attack_name,
            family=attack_family,
            node_class="Attack"
        )
        
        # Link Attack -> Family
        self.graph.add_edge(
            f"attack:{attack_name}",
            f"family:{attack_family}",
            relation="belongsToFamily",
            weight=1.0
        )

        # Link Family -> Attack
        self.graph.add_edge(
            f"family:{attack_family}",
            f"attack:{attack_name}",
            relation="hasChild",
            weight=1.0
        )
    
    def _create_repository_node(self, url: str, attack_name: str,strategy_id: str, readme: str):
        """
        Create repository node from unique URLs. 
        """
        if not self.graph.has_node(f"repo:{url}|{attack_name}"):
            self.graph.add_node(
                f"repo:{url}|{attack_name}", # Note: It is important to include attack name as one url might immpelment multiple attacks
                type="repository",
                url=url,
                strategy_id=strategy_id,
                attack_name=attack_name,
                readme=readme,
                node_class="Repository"
            )
            
        # Add link Attack -> Repository
        self.graph.add_edge(
            f"attack:{attack_name}",
            f"repo:{url}|{attack_name}",
            relation="isImplementedIn",
            weight=1.0
        )

        # Add link Repository -> Attack
        self.graph.add_edge(
            f"repo:{url}|{attack_name}",
            f"attack:{attack_name}",
            relation="belongsToAttack",
            weight=1.0
        )
    
    def _create_strategy_nodes(self, attack_name: str):
        """Create strategy nodes from the strategies dataframe."""
        self.logger.info(f"Creating {len(self.strategies_df)} strategy nodes...")
        
        for _, row in self.strategies_df.iterrows():
            # Check if strategy node already exists
            strategy_id = f"strategy:{row['strategy_id']}|{attack_name}"

            if not self.graph.has_node(strategy_id):
                # Add strategy node
                representative = True if row['is_representative'] == 1 else False
                self.graph.add_node(
                    strategy_id,
                    type="strategy",
                    name=row['name'],
                    description=row['description'],
                    url=row['url'],
                    cluster_id=row['cluster_id'],
                    is_representative= representative,
                    is_relevant=row['is_relevant'], 
                    embedding=row['embedding'],
                    node_class="Strategy"
                )


            
            repository_id = f"repo:{row['url']}|{attack_name}"
            # Link strategy to attack
            self.graph.add_edge(
                f"attack:{attack_name}",
                strategy_id,
                relation="hasStrategy",
                weight=1.0
            )

            #create repository node
            self._create_repository_node(row['url'], attack_name, strategy_id, row['readme'])
            # Add link Strategy -> Repository
            self.graph.add_edge(
                strategy_id,
                repository_id,
                relation="hasSource",
                weight=1.0
            )

            # Add link Repository -> Strategy
            self.graph.add_edge(
                repository_id,
                strategy_id,
                relation="Implements",
                weight=1.0
            )

            # create cluster node and link to strategy
            # Note: Entity type is required here as both  Strategy and Feature have their own cluster
            u_of_c = f"cluster:{row['cluster_id']}|{attack_name}|strategy" # Declare unique node id
            self._create_cluster_node(u_of_c, attack_name, row['name'], strategy_id)
  
            # Add link Cluster-> Repository 
            self.graph.add_edge(
                u_of_c,
                repository_id,
                relation="isImplementedIn",
                weight=1.0
            )

    def _create_cluster_node(self, u_of_c: str, attack_name: str, 
                             strategy: str, element_id : str, cluster_type: str = "strategy"):
        """
        Create cluster node to group similar strategies.
        """
        if not self.graph.has_node(f"cluster:{u_of_c}"):
            self.graph.add_node(
                u_of_c,
                type="cluster",
                belong_to=strategy,
                attack_name=attack_name,
                cluster_type=cluster_type,
                node_class="Cluster"
            )

            # Add link Attack -> Cluster
            self.graph.add_edge(
                f"attack:{attack_name}",
                u_of_c,
                relation="hasCluster",
                weight=1.0
            )

        # Add link Cluster -> Element
        self.graph.add_edge(
            u_of_c,
            element_id,
            relation="hasElement",
            weight=1.0
        )

        # Add link Element -> Cluster
        self.graph.add_edge(
            element_id,
            u_of_c,
            relation="belongsTo",
            weight=1.0
        )


    def _create_feature_nodes(self, attack_name: str):
        """
        Create feature nodes from the features dataframe.
        """
        self.logger.info(f"Creating {len(self.features_df)} feature nodes...")
        
        for _, row in self.features_df.iterrows():
            # Note that features must be 
            feature_id = f"feature:{row['strategy_id']}|{attack_name}"
            
            # Check if feature node already exists
            if not self.graph.has_node(feature_id):
                representative = True if row['is_representative'] == 1 else False
                strategy_id = f"strategy:{row['strategy_id']}|{attack_name}"
                # Add feature node
                self.graph.add_node(
                    feature_id,
                    type="feature",
                    name=row['name'],
                    description=row['description'],
                    strategy_id=row['strategy_id'],
                    code=row.get('code', ''),
                    rationale=row.get('rationale', ''),
                    embedding=row.get('embedding', None),
                    is_representative=representative, 
                    cluseter_id = row['cluster_id'],
                    node_class="Feature"
                )
                
                # Add link Strategy -> Feature
                self.graph.add_edge(
                   strategy_id,
                    feature_id,
                    relation="manifestsAs",
                    weight=1.0
                )

                #create cluster node and link to feature
                u_of_c = f"cluster:{row['cluster_id']}|{attack_name}|feature" # Declare unique node id
                self._create_cluster_node(u_of_c, attack_name, row['name'], feature_id, cluster_type="feature")
                
                # Add Attack-> Feature Cluster
                self.graph.add_edge(
                    f"attack:{attack_name}",
                    u_of_c,
                    relation="hasCluster",
                    weight=1.0
                )
    
    
    def _add_graph_metadata(self):
        """Add global metadata to the graph."""
        metadata = {
            "num_strategies": self.num_strategies,
            "num_features": self.num_features,
            "num_clusters": self.num_clusters,
            "num_repositories": self.num_repos,
            "creation_date": pd.Timestamp.now().isoformat()
        }
        
        # Add metadata as graph attributes
        for key, value in metadata.items():
            self.graph.graph[key] = value
    
    def save_graph(self, formats=None):
        """
        Save the knowledge graph in multiple formats.
        
        Args:
            formats: List of formats to save in. Options: 'graphml', 'pkl', 'json', 'csv'.
                    Defaults to ['graphml', 'pkl'].
        """
        if formats is None:
            formats = ['graphml', 'pkl']
        
        for fmt in formats:
            if fmt == 'graphml':
                self._save_graphml()
            elif fmt == 'pkl':
                self._save_pickle()
            elif fmt == 'json':
                self._save_json()
            elif fmt == 'csv':
                self._save_csv()
            else:
                self.logger.warning(f"Unsupported format: {fmt}")
        
        self.logger.info(f"Graph saved in formats: {formats}, into directory: {self.output_dir}")

    def _prepare_graph_for_serialization(self):
        """Prepare the graph for serialization (handle embeddings)."""
        cleaned_graph = self.graph.copy()
        
        # Convert embeddings to strings for serialization
        for node in cleaned_graph.nodes():
            if 'embedding' in cleaned_graph.nodes[node] and cleaned_graph.nodes[node]['embedding'] is not None:
                if isinstance(cleaned_graph.nodes[node]['embedding'], list):
                    cleaned_graph.nodes[node]['embedding'] = json.dumps(cleaned_graph.nodes[node]['embedding'])
        
        return cleaned_graph

    def _save_graphml(self):
        """Save the graph in GraphML format."""
        # Handle embeddings that can't be serialized
        cleaned_graph = self._prepare_graph_for_serialization()
        
        output_path = self.output_dir / "knowledge_graph.graphml"
        self.logger.info(f"Saving graph in GraphML format to {output_path}")
        nx.write_graphml(cleaned_graph, output_path)
    
    def _save_pickle(self):
        """Save the graph in pickle format for fast loading."""
        output_path = self.output_dir / "knowledge_graph.pkl"
        self.logger.info(f"Saving graph in pickle format to {output_path}")
        with open(output_path, 'wb') as f:
            pickle.dump(self.graph, f)
    
    def _save_json(self):
        """Save the graph in JSON format."""
        # Handle embeddings that can't be serialized
        cleaned_graph = self._prepare_graph_for_serialization()
        
        output_path = self.output_dir / "knowledge_graph.json"
        self.logger.info(f"Saving graph in JSON format to {output_path}")
        graph_data = nx.node_link_data(cleaned_graph)
        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2)
    
    def _save_csv(self):
        """Save the graph as CSV files (nodes and edges)."""
        # Create nodes dataframe
        nodes_data = []
        for node, attrs in self.graph.nodes(data=True):
            node_data = {"id": node, **attrs}
            # Handle embeddings
            if "embedding" in node_data and node_data["embedding"] is not None:
                if isinstance(node_data["embedding"], list):
                    node_data["embedding"] = json.dumps(node_data["embedding"])
            nodes_data.append(node_data)
        
        nodes_df = pd.DataFrame(nodes_data)
        nodes_path = self.output_dir / "knowledge_graph_nodes.csv"
        self.logger.info(f"Saving nodes to {nodes_path}")
        nodes_df.to_csv(nodes_path, index=False)
        
        # Create edges dataframe
        edges_data = []
        for source, target, attrs in self.graph.edges(data=True):
            edge_data = {"source": source, "target": target, **attrs}
            edges_data.append(edge_data)
        
        edges_df = pd.DataFrame(edges_data)
        edges_path = self.output_dir / "knowledge_graph_edges.csv"
        self.logger.info(f"Saving edges to {edges_path}")
        edges_df.to_csv(edges_path, index=False)
    
        
    def build_and_save_graph(self, attack_family: str, attack_name: str, graph_file:str = None, formats=None):
        """
        Build the knowledge graph and save it in multiple formats.
        """
        self.build_graph(attack_family, attack_name, graph_file)
        self.save_graph(formats)
        
if __name__ == "__main__":

    output_dir = os.path.join(os.getcwd(), "output")
    strategy_file =""
    feature_file = "" # OPTIONAL
    kg_builder = KnowledgeGraphBuilder(strategy_file, feature_file, output_dir)
    attack_family = ""
    attack_name = ""
    graph_file = ""
    kg_builder.build_and_save_graph(attack_family, attack_name, graph_file)