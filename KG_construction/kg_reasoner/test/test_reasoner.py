import unittest
import networkx as nx
import logging
import tempfile
import os
import json
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)
sys.path.append('../../')

from kg_symbolic_reasoner import KnowledgeGraphReasoner
from kg_builder import KnowledgeGraphBuilder

class TestKnowledgeGraphReasoner(unittest.TestCase):
    # Assume that the dummy files were for the "Test Family" and "Test Attack"
    ATTACK_FAMILY = "Test Family"
    ATTACK_NAME = "Test Attack"

    def test_frequency_rule(self):
        #graph_file = os.path.join(os.getcwd() + "/test rule 1", "knowledge_graph.graphml")
        strategy_file = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 1/strategy_file.csv"
        feature_file = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 1/features_file.csv"

        output_dir = os.getcwd() + "/test cases/test rule 1"
        kg_builder = KnowledgeGraphBuilder(strategy_file, feature_file, output_dir)
        kg_builder.build_and_save_graph(TestKnowledgeGraphReasoner.ATTACK_FAMILY, TestKnowledgeGraphReasoner.ATTACK_NAME)
        
        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")
        
        self.graph = nx.read_graphml(graph_file)
        self.reasoner = KnowledgeGraphReasoner(graph_file)
        results = self.reasoner.frequency_rule(TestKnowledgeGraphReasoner.ATTACK_NAME)
        
        print(f"Frequency rule results: {json.dumps(results, indent=2)}")
        
        self.assertEqual(len(results), 3, "Should have 3 strategies with coverage > 0")
        
        # Check first strategy (highest coverage)
        self.assertEqual(results[0]["name"], "Strategy0")
        self.assertEqual(results[0]["url"], "URL0")
        self.assertAlmostEqual(results[0]["coverage_score"], float((4/7)*100), delta=0.01)
        
        # Check second strategy
        self.assertEqual(results[1]["name"], "Strategy4")
        self.assertEqual(results[1]["url"], "URL4")
        self.assertAlmostEqual(results[1]["coverage_score"], float((2/7)*100), delta=0.01)
        
        # Verify Strategy6 is not included (0 coverage)
        self.assertEqual(results[2]["name"], "Strategy6")
        self.assertEqual(results[2]["url"], "URL6")
        self.assertAlmostEqual(results[2]["coverage_score"], float((1/7)*100), delta=0.01)

    
    def test_transitive_rule(self):
        strategy_file = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 2/strategy_file.csv"
        feature_file = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 2/features_file.csv"

        output_dir = os.getcwd() + "/test cases/test rule 2"
        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")

        kg_builder = KnowledgeGraphBuilder(strategy_file, feature_file, output_dir)

        kg_builder.build_and_save_graph(TestKnowledgeGraphReasoner.ATTACK_FAMILY, TestKnowledgeGraphReasoner.ATTACK_NAME)
                                        
        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")

        self.graph = nx.read_graphml(graph_file)
        self.reasoner = KnowledgeGraphReasoner(graph_file)

        strategy_ids = ["strategy:ddf024d2e5c8275294ae7581c1c58f5c4513087dff350494fb4c698fe517d7f4|Test Attack"]

        results = self.reasoner.find_evoluationary_paths(strategy_ids, TestKnowledgeGraphReasoner.ATTACK_NAME)
        print(f"Transitive inference results: {json.dumps(results, indent=2)}")

        assert isinstance(results, list), "Results should be a list"
        assert len(results) == 1, "Should have 1 result item"
        
        # Validate the first result item
        result_item = results[0]
        assert isinstance(result_item, dict), "Result item should be a dictionary"
        assert len(result_item) == 2, "Result item should have 2 clusters"
        
        assert "cluster:1|Test Attack|strategy" in result_item, "Cluster 1 should be present"
        assert "cluster:2|Test Attack|strategy" in result_item, "Cluster 2 should be present"
        
        cluster1 = result_item["cluster:1|Test Attack|strategy"]
        assert (cluster1["path"] == "Strategy0 - Strategy2 - Strategy4" or cluster1["path"] == "Strategy0 - Strategy1 - Strategy4"), "Cluster 1 path is incorrect"
        assert cluster1["confidence"] == 0.5, "Cluster 1 confidence should be 0.5"
        assert cluster1["evolution_strategy"]["name"] == "Strategy4", "Cluster 1 evolution strategy name is incorrect"
        assert cluster1["evolution_strategy"]["url"] == "URL1", "Cluster 1 evolution strategy URL is incorrect"
        assert cluster1["evolution_strategy"]["description"] == "Description4", "Cluster 1 evolution strategy description is incorrect"
        
        cluster2 = result_item["cluster:2|Test Attack|strategy"]
        assert cluster2["path"] == "Strategy0 - Strategy3 - Strategy7", "Cluster 2 path is incorrect"
        assert cluster2["confidence"] == 0.25, "Cluster 2 confidence should be 0.25"
        assert cluster2["evolution_strategy"]["name"] == "Strategy7", "Cluster 2 evolution strategy name is incorrect"
        assert cluster2["evolution_strategy"]["url"] == "URL6", "Cluster 2 evolution strategy URL is incorrect"
        assert cluster2["evolution_strategy"]["description"] == "Description7", "Cluster 2 evolution strategy description is incorrect"
    
    def _create_dummy_graph_3(self):
        attack_family = "Test Family1"
        attack_name = "Test Attack1"

        attack_family2 = "Test Family2"
        attack_name2 = "Test Attack2"

        attack_family3 = "Test Family3"
        attack_name3 = "Test Attack3"

        strategy_file1 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 3/strategy_file_1.csv"
        strategy_file2 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 3/strategy_file_2.csv"
        strategy_file3 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 3/strategy_file_3.csv"

        output_dir = os.getcwd() + "/test cases/test rule 3"
        kg_builder = KnowledgeGraphBuilder(strategy_file1, output_dir=output_dir)
        kg_builder.build_and_save_graph(attack_family, attack_name)
        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")

        kg_builder = KnowledgeGraphBuilder(strategy_file2, output_dir=output_dir)
        kg_builder.build_and_save_graph(attack_family2, attack_name2, graph_file)

        kg_builder = KnowledgeGraphBuilder(strategy_file3, output_dir=output_dir)
        kg_builder.build_and_save_graph(attack_family3, attack_name3, graph_file)

    def test_cross_family_rule(self):
        self._create_dummy_graph_3()
        output_dir = os.getcwd() + "/test cases/test rule 3"

        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")
        self.graph = nx.read_graphml(graph_file)
        kg_reasoner = KnowledgeGraphReasoner(graph_file)

        results = kg_reasoner.cross_family_rule()
        print(f"Cross-family inference results: {json.dumps(results, indent=2)}")

        self.assertIn("common_strategies", results)
        self.assertIsInstance(results["common_strategies"], list)
        self.assertEqual(len(results["common_strategies"]), 2)
        
        first_group = results["common_strategies"][0]
        self.assertIn("strategies", first_group)
        self.assertIn("discriminative_score", first_group)
        self.assertIsInstance(first_group["strategies"], list)
        self.assertEqual(len(first_group["strategies"]), 3)
        self.assertEqual(first_group["discriminative_score"], 1.0)
        
        # expected_strategies1 = [
        #     "Strategy0|Test Attack1",
        #     "Strategy0|Test Attack2",
        #     "Strategy0|Test Attack3"
        # ]


        expected_strategies1 = [
            "Test Attack1|Strategy0",
            "Test Attack2|Strategy0",
            "Test Attack3|Strategy0"
        ]


        self.assertListEqual(first_group["strategies"], expected_strategies1)
        
        second_group = results["common_strategies"][1]
        self.assertIn("strategies", second_group)
        self.assertIn("discriminative_score", second_group)
        self.assertIsInstance(second_group["strategies"], list)
        self.assertEqual(len(second_group["strategies"]), 2)
        self.assertEqual(second_group["discriminative_score"], 0.67)
        
        # Validate specific strategy strings
        # expected_strategies2 = [
        #     "Strategy4|Test Attack1",
        #     "Strategy4|Test Attack3"
        # ]

        expected_strategies2 = [
            "Test Attack1|Strategy4",
            "Test Attack3|Strategy4"
        ]

        self.assertListEqual(second_group["strategies"], expected_strategies2)

    def _create_dummy_graph_4(self):
        attack_family = "Test Family1"
        attack_name = "Test Attack1"

        attack_family2 = "Test Family2"
        attack_name2 = "Test Attack2"

        strategy_file1 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 4/strategy_file_1.csv"
        strategy_file2 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 4/strategy_file_2.csv"
        feature_file1 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 4/features_file_1.csv"
        feature_file2 = "/home/ubuntu/Xin Fan/SecNIDS/Contextual KG/kg reasoner/test/test cases/test rule 4/features_file_2.csv"
        

        output_dir = os.getcwd() + "/test cases/test rule 4"
        kg_builder = KnowledgeGraphBuilder(strategy_file1,feature_file1, output_dir=output_dir)
        kg_builder.build_and_save_graph(attack_family, attack_name)
        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")

        kg_builder = KnowledgeGraphBuilder(strategy_file2, feature_file2, output_dir=output_dir)
        kg_builder.build_and_save_graph(attack_family2, attack_name2, graph_file)

    def test_feature_covegence(self): 
        self._create_dummy_graph_4()
        output_dir = os.getcwd() + "/test cases/test rule 4"

        graph_file = os.path.join(output_dir, "knowledge_graph.graphml")
        self.graph = nx.read_graphml(graph_file)
        
        kg_reasoner = KnowledgeGraphReasoner(graph_file)
        results = kg_reasoner.infer_feature_coverage()
        print(f"Feature coverage inference results: {json.dumps(results, indent=2)}")

            
        # Feature coverage inference results: {
        # "Test Attack1": {
        #     "cluster:0|Test Attack1|feature": {
        #     "elements": 3,
        #     "feature_name": "feature1",
        #     "feature_description": "description1",
        #     "rationale": "rationale1",
        #     "code": "code1",
        #     "coverage_score": 42.857142857142854
        #     },
        #     "cluster:1|Test Attack1|feature": {
        #     "elements": 4,
        #     "feature_name": "feature5",
        #     "feature_description": "description5",
        #     "rationale": "rationale5",
        #     "code": "code5",
        #     "coverage_score": 57.14285714285714
        #     }
        # },
        # "Test Attack2": {
        #     "cluster:1|Test Attack2|feature": {
        #     "elements": 1,
        #     "coverage_score": 33.33333333333333
        #     },
        #     "cluster:0|Test Attack2|feature": {
        #     "elements": 2,
        #     "feature_name": "feature2",
        #     "feature_description": "description2",
        #     "rationale": "rationale2",
        #     "code": "code2",
        #     "coverage_score": 66.66666666666666
        #     }
        # }
        # }

        self.assertIn("Test Attack1", results)
        self.assertIn("Test Attack2", results)

        # Test Attack1
        attack1_results = results["Test Attack1"]
        self.assertIn("cluster:0|Test Attack1|feature", attack1_results)
        self.assertIn("cluster:1|Test Attack1|feature", attack1_results)
        self.assertEqual(attack1_results["cluster:0|Test Attack1|feature"]["elements"], 3)
        self.assertEqual(attack1_results["cluster:0|Test Attack1|feature"]["coverage_score"], float(3/7)*100)
        self.assertEqual(attack1_results["cluster:1|Test Attack1|feature"]["elements"], 4)
        self.assertEqual(attack1_results["cluster:1|Test Attack1|feature"]["coverage_score"], float(4/7)*100)

        # Test Attack2
        attack2_results = results["Test Attack2"]
        self.assertIn("cluster:0|Test Attack2|feature", attack2_results)
        self.assertIn("cluster:1|Test Attack2|feature", attack2_results)
        self.assertEqual(attack2_results["cluster:0|Test Attack2|feature"]["elements"], 2)
        self.assertEqual(attack2_results["cluster:0|Test Attack2|feature"]["coverage_score"], float(2/3)*100)
        self.assertEqual(attack2_results["cluster:1|Test Attack2|feature"]["elements"], 1)
        self.assertEqual(attack2_results["cluster:1|Test Attack2|feature"]["coverage_score"], float(1/3)*100)

if __name__ == "__main__":
    unittest.main()