# ADR 0003: ML Approach - Hybrid Unsupervised + Supervised

## Status
Accepted

## Context
Network anomaly detection faces:
- Limited labeled attack data (expensive to obtain)
- Evolving attack patterns (zero-day)
- High false positive sensitivity in SOC environments
- Need for explainability in alerts

## Decision
**Hybrid approach:**
1. **Phase 1 - Unsupervised Pre-training**: LSTM Autoencoder on "normal" traffic only
   - Learns compressed representation of benign behavior
   - Reconstruction error = anomaly score
   - No labels required, uses abundant normal traffic
   
2. **Phase 2 - Supervised Fine-tuning**: XGBoost / TabTransformer on labeled data
   - Uses reconstruction error + raw features as input
   - Trained on CICIDS2017, UNSW-NB15, CSE-CIC-IDS2018 + custom labels
   - Outputs calibrated probability + attack type classification

3. **Phase 3 (Optional) - Graph Neural Network**: Topology-aware detection
   - Models network as graph (nodes=hosts, edges=flows)
   - GNN propagates anomaly scores across topology
   - Detects lateral movement, C2 beaconing, DDoS

## Model Serving
- **Fast Path**: Export Isolation Forest + lightweight XGBoost to ONNX → ONNX Runtime (C++ backend, ~1ms inference)
- **Deep Path**: Full PyTorch models served via Triton Inference Server or TorchServe

## Data Strategy
- **Normal traffic**: Capture from lab environment, home network, public datasets (MAWI, CAIDA)
- **Attack traffic**: Public datasets + synthetic generation (adversarial, mutation)
- **Labeling**: Semi-automated via Sigma rules + manual review

## Consequences
- Requires MLflow + DVC for experiment tracking
- Need GPU for deep path training (use Colab/Kaggle free tiers + local CPU fallback)
- Model versioning critical for rollback