
---

# Feature Extractor

The **Feature Extractor (FE)** module transforms raw network traffic into structured flow records for **machine learning training and evaluation**.

It is designed for **extensibility** and follows the **IETF Data Model (RFC 3917)** for flow-based data representation.

---

## Design

Flow records (units of data) are created and terminated according to the criteria defined in **RFC 5102**.

### Connection-Oriented Protocols

* Flow ends when termination is detected (graceful or abrupt).

### Connectionless Protocols

* **Idle timeout**
* **Active timeout**
* **Lack of resources**
* **Forced termination**

Reference: [RFC 3917](https://datatracker.ietf.org/doc/html/rfc3917)

---

## Run Code

**Inputs:**

* `--input` → Path to `.pcap` file for processing
* `--store` → Output directory for storing extracted features

**Example:**

```bash
python feature_extractor.py --input <pcap_file_path> --store <store_path>
```

**Post-Processing:**
If running in **offline settings**, process the extracted file with:

```bash
python process_dataset.py
```

---

## Testing

To avoid pitfalls highlighted in
 *“Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study”*
the FE module is extensively tested:

1. **Updates** → verify feature extraction with latest datasets
2. **Flow Establishment** → ensure proper session creation
3. **Flow Termination** → validate correct closure per RFC rules

* For more refer to `./Test/README.md`


