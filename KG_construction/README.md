
# KG Construction

This repository provides a **pipeline** for constructing and reasoning over **attack strategy knowledge graphs**.
It extracts attack parameters from GitHub repositories, builds semantic relationships, and applies symbolic reasoning to derive insights about attack patterns.

---

## Pipeline Overview

```
┌─────────────────────────────────────────┐
│     PARAMETER EXTRACTION & EMBEDDING    │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│      KNOWLEDGE GRAPH CONSTRUCTION       │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         REASONING OVER GRAPH    │
└─────────────────────────────────────────┘
```

---

## 1. Parameter Extraction & Embedding

Extracts attack parameters and their descriptions from GitHub repos, embeds them semantically, and identifies unique strategies & manifestations.

```
1. PARAMETER EXTRACTION & EMBEDDING
   │
   ├── 1.1 Data Retrieval
   │   ├── Fetch all GitHub URLs implementing attack
   │   └── Extract README.md documentation
   │
   ├── 1.2 Strategy Extraction (NER / GPT-4o-mini)
   │   ├── Identify parameter mentions + descriptions
   │   └── Store parameter-description pairs with metadata
   │
   ├── 1.3 Semantic Embedding
   │   ├── Generate embeddings for parameter-description pairs
   │   └── Store embeddings
   │
   ├── 1.4 Strategy Clustering
   │   ├── Apply HAC to group similar strategies
   │   └── Select representative strategies per cluster
   │
   └── 1.5 Manifestation Identification
       ├── Analyze code to map strategies → features
       └── Repeat embeddings to cover multi-strategy observations
```

### Input / Output Overview

| **Step**                    | **Input**                              | **Output**                                             |
| --------------------------- | -------------------------------------- | ------------------------------------------------------ |
| **1.1 GitHub Retrieval**    | Attack name (string)                   | `urls.csv (url, readme)`                               |
| **1.2 Strategy Extraction** | Attack name + description + `urls.csv` | `strategies.csv (url, readme, strategy, description)`  |
| **1.3 Embeddings**          | `strategies.csv`                       | `embeddings.csv (url, readme, strategy, desc, vector)` |
| **1.4 Clustering**          | `embeddings.csv`                       | `clusters.csv (cluster_id, representative_flag)`       |
| **1.5 Manifestation**       | `embeddings.csv`                       | `manifestations.csv (feature, strategy_id, url)`       |

---

## 2. Knowledge Graph Construction

Constructs a graph representation of attack strategies, their relationships, and sources.

```
2. KNOWLEDGE GRAPH CONSTRUCTION
   │
   ├── 2.1 Node Creation
   │   ├── Entities: strategies, features, families, sources
   │   └── Attributes: {name, description, source, attack, family}
   │
   └── 2.2 Edge Creation
       ├── Semantic similarity edges (cluster ID)
       ├── Same-source edges
       └── Family-based edges
```

---

## 3. Symbolic Reasoning Over Graph

Applies inference rules to extract insights about attack strategies & interconnections.

```
3. SYMBOLIC REASONING
   │
   ├── 3.1 Atomic Rule
   │   └── Enumerate all strategies
   │
   ├── 3.2 Evolution Path Analysis
   │   └── Identify composite/sequential strategies
   │
   └── 3.3 Cross-Family Analysis
       └── Detect invariant strategies
```

---

## Running the Pipeline

1. Open **`run_pipeline.py`** and configure:

   * **Attack keywords** → pulls relevant repos from GitHub
     (see `./crawler/CrawlerConstants` and `generate_keyword_combinations`)
   * **Attack description** → recommended: CAPEC description (filters irrelevant repos)

2. Set environment variables in **`.env`**:

   * `GITHUB_PERSONAL_FINE_GRAINED_ACCESS_TOKEN=XXXX`
     (see `/crawler/README.md` for setup)
   * `OPENAI_API_KEY=XXXX`

---

##  Output & Logs

| **Stage**                              | **Output Folder**                                              |
| -------------------------------------- | -------------------------------------------------------------- |
| Step 1 – Extracted URLs                | `./output/step1/`                                              |
| Step 2 – Cloned README.md              | `./output/step2/`                                              |
| Step 3 – Strategy NER                  | `./output/step3/`                                              |
| Step 4 – Embeddings                    | `./output/step4/`                                              |
| Step 5 – HAC Clustering                | `./output/output5/` <br> dendrogram: `step4/dendrogram.png` |
| Step 6 – Feature Derivation (optional) | `./output/output6/`                                            |

Logs → `./output/logs/`
Cache → `./cache/cache.json` ( must be cleared for each new attack run)


---

# Symbolic Reasoning

Symbolic reasoning is applied on top of the constructed knowledge graph to derive **insights, patterns, and invariants** from attack strategies.

---

## Running the Reasoner

1. Run **`kg_builder.py`**

   * Input:

     * **Graph file** (optional, if merging graphs)
     * **Strategy file** (from KG construction)
   * Output:

     * A reasoning-ready graph (`.graphml`) saved in `./output/`

2. Visualize the graph by providing the **`.graphml`** file under the **`kg_reasoner`** folder.

---

## Testing

Unit tests are available under:

```
./kg_reasoner/test
```

Run these to validate reasoning modules and rule implementations.


