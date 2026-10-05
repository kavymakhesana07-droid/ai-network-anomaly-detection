# Model Training Guide

This guide covers training, evaluating, and deploying ML models for the anomaly detection system.

## Overview

The system uses a hybrid ML approach:

1. Unsupervised Pre-training (LSTM Autoencoder) - learns normal traffic patterns
2. Supervised Fine-tuning (XGBoost) - learns attack patterns from labeled data
3. Optional - Graph Neural Networks for topology-aware detection

---

## Data Preparation

### Datasets

| Dataset | Type | Size | Use Case |
|---------|------|------|----------|
| CICIDS2017 | Labeled | 2.8M flows | Supervised training |
| UNSW-NB15 | Labeled | 2.5M flows | Supervised training |
| CSE-CIC-IDS2018 | Labeled | 16M flows | Supervised training |
| MAWI | Unlabeled | 100M+ flows | Unsupervised pre-training |
| CAIDA | Unlabeled | 50M+ flows | Unsupervised pre-training |
| Custom | Labeled | Variable | Organization-specific |

### Data Format

All datasets must be converted to the standard flow format:

```json
{
  "flow_key": "192.168.1.1:12345-10.0.0.1:80-tcp",
  "timestamp": 1699123456.789,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 12345,
  "dst_port": 80,
  "protocol": 6,
  "features": {
    "duration": 1.5,
    "fwd_packets": 10,
    "bwd_packets": 8,
    "fwd_bytes": 1500,
    "bwd_bytes": 1200,
    ...
  },
  "label": 1
}
```

### Data Pipeline

```bash
# 1. Download datasets
python scripts/download_datasets.py --datasets cicids2017,unsw-nb15

# 2. Convert to standard format
python scripts/convert_datasets.py --input data/raw --output data/processed

# 3. Extract features
python scripts/extract_features.py --input data/processed --output data/features

# 4. Split train/val/test
python scripts/split_data.py --input data/features --train 0.8 --val 0.1 --test 0.1
```

---

## Model Training

### 1. LSTM Autoencoder (Deep Path)

#### Prerequisites
```bash
pip install -r requirements/detect_deep.txt
```

#### Training
```bash
# Basic training
python -m detection.deep_path.main train \
  --flows data/features/train.json \
  --output /models/deep_path \
  --epochs 50 \
  --batch-size 256 \
  --sequence-length 10

# With MLflow tracking
python -m detection.deep_path.main train \
  --flows data/features/train.json \
  --output /models/deep_path \
  --epochs 50 \
  --mlflow-tracking-uri http://mlflow:5000 \
  --mlflow-experiment-name deep-path-lstm-ae
```

#### Key Hyperparameters
| Parameter | Default | Range |
|-----------|---------|-------|
| input_dim | 51 | Fixed |
| hidden_dim | 128 | 64-256 |
| latent_dim | 32 | 16-64 |
| num_layers | 2 | 1-4 |
| dropout | 0.2 | 0.1-0.5 |
| learning_rate | 1e-3 | 1e-4 to 1e-2 |
| batch_size | 256 | 64-512 |
| sequence_length | 10 | 5-50 |
| anomaly_threshold_percentile | 95 | 90-99 |

#### Training Output
```
/models/deep_path/
├── lstm_ae.pt
├── lstm_ae.onnx
├── threshold.json
├── normalization.json
├── model_version.json
└── mlflow_run_id.txt
```

### 2. XGBoost Supervised (Fast Path Alternative)

#### Training
```bash
python -m detection.xgboost.main train \
  --input data/features/train.json \
  --output /models/xgboost \
  --epochs 500 \
  --threshold 0.5
```

#### Hyperparameters
```python
params = {
    "objective": "binary:logistic",
    "eval_metric": "auc",
    "tree_method": "hist",
    "n_estimators": 500,
    "max_depth": 8,
    "learning_rate": 0.05,
    "subsample": 0.9,
    "colsample_bytree": 0.8,
    "min_child_weight": 3,
    "reg_alpha": 0.1,
    "reg_lambda": 1.0,
    "early_stopping_rounds": 50,
}
```

#### Output
```
/models/xgboost/
├── xgboost_anomaly.json
├── xgboost_anomaly.onnx
├── threshold.json
├── model_version.json
└── feature_importance.json
```

---

## Model Evaluation

### Metrics

| Metric | Fast Path | Deep Path | XGBoost |
|--------|-----------|-----------|---------|
| AUC-ROC | N/A | 0.94 | 0.96 |
| Precision | 0.89 | 0.85 | 0.91 |
| Recall | 0.87 | 0.82 | 0.89 |
| F1 | 0.88 | 0.84 | 0.90 |
| FPR @ 95% TPR | 0.05 | 0.08 | 0.03 |

### Evaluation Script
```bash
python scripts/evaluate_models.py \
  --models /models/fast_path,/models/deep_path,/models/xgboost \
  --data data/features/test.json \
  --output evaluation_report.json
```

---

## Model Registry (MLflow)

### Register Model
```python
import mlflow
import mlflow.pyfunc

mlflow.set_tracking_uri("http://mlflow:5000")
mlflow.set_experiment("anomaly-detection")

with mlflow.start_run() as run:
    mlflow.log_params(params)
    mlflow.log_metrics(metrics)
    mlflow.log_artifacts("/models/deep_path")

    mlflow.register_model(f"runs:/{run.info.run_id}/model", "deep-path-lstm-ae")
```

### Model Stages
None -> Staging -> Production -> Archived

### Promotion Criteria
| Stage | Criteria |
|-------|----------|
| Staging | AUC > 0.85, passes CI tests |
| Production | AUC > 0.85, passes staging 1+ days, approved |
| Archived | Superseded by newer version |

### Promotion Script
```bash
# Promote to staging
python scripts/promote_model.py \
  --model deep-path-lstm-ae \
  --version 1.2.0 \
  --stage Staging

# Promote to production (requires approval)
python scripts/promote_model.py \
  --model deep-path-lstm-ae \
  --version 1.2.0 \
  --stage Production \
  --approver security-team
```

---

## Model Serving

### Fast Path (ONNX Runtime)
```python
import onnxruntime as ort

session = onnxruntime.InferenceSession("models/fast_path/isolation_forest.onnx")
input_name = session.get_inputs()[0].name

pred = session.run(None, {input_name: features_array})
anomaly_score = pred[0][0]
```

### Deep Path (Triton - Optional)
```yaml
name: "deep_path"
backend: "pytorch"
max_batch_size: 32
input [
  { name: "input", data_type: TYPE_FP32, dims: [10, 51] }
]
output [
  { name: "reconstruction", data_type: TYPE_FP32, dims: [10, 51] }
]
```

### XGBoost (FastAPI)
```python
import xgboost as xgb

model = xgb.Booster()
model.load_model("models/xgboost/xgboost_anomaly.json")

dmatrix = xgb.DMatrix(features)
prob = model.predict(dmatrix)[0]
```

---

## Experiment Tracking (MLflow)

### Key Metrics to Log
```python
mlflow.log_params({
    "model_type": "lstm_ae",
    "input_dim": 51,
    "hidden_dim": 128,
    "latent_dim": 32,
    "num_layers": 2,
    "dropout": 0.2,
    "learning_rate": 1e-3,
    "batch_size": 256,
    "sequence_length": 10,
    "max_epochs": 50,
    "early_stopping_rounds": 5,
})

mlflow.log_metrics({
    "train_loss": train_loss,
    "val_loss": val_loss,
    "val_auc": val_auc,
    "test_auc": test_auc,
    "threshold": threshold,
    "best_iteration": best_iteration,
})

mlflow.log_artifacts("/models/deep_path")
```

### Artifacts to Save
/models/deep_path/
├── lstm_ae.pt
├── lstm_ae.onnx
├── threshold.json
├── normalization.json
├── model_version.json

---

## CI/CD Integration

### Training Pipeline
```yaml
# .github/workflows/train.yml
name: Train Models

on:
  schedule:
    - cron: '0 2 * * 0'
  workflow_dispatch:

jobs:
  train-deep-path:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install -r requirements/detect_deep.txt
      - name: Train
        run: |
          python -m detection.deep_path.main train \
            --flows data/features/train.json \
            --output /models/deep_path \
            --epochs 50 \
            --mlflow-tracking-uri ${MLFLOW_URI}
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: deep-path-model
          path: /models/deep_path/

  train-xgboost:
    # Similar structure
```

---

## Model Monitoring

### Drift Detection
```python
from evidently.report import Report
from evidently.metric_preset import DataDriftPreset

report = Report(metrics=[DataDriftPreset()])
report.run(reference_data=train_data, current_data=production_data)
report.save_html("drift_report.html")

# Feature drift
from evidently.metric_preset import DataDriftPreset

# Concept drift (performance)
# Monitor AUC decay over time
```

### Retraining Triggers
| Trigger | Threshold | Action |
|---------|-----------|--------|
| AUC drop | < 0.85 | Retrain |
| Data drift | PSI > 0.25 | Investigate |
| Concept drift | AUC decay > 5%/month | Retrain |
| New attack type | New label in data | Add to training |

---

## Best Practices

1. Version Everything - Data, code, models, config
2. Reproducible Training - Fixed seeds, pinned deps
3. Automate Evaluation - CI/CD gates on metrics
3. Monitor in Production - Drift, latency, errors
4. Version Models - Semantic versioning (MAJOR.MINOR.PATCH)
5. Document Decisions - ADRs for architectural choices

---

## Troubleshooting

| Issue | Diagnosis | Fix |
|-------|-----------|-----|
| OOM in training | Reduce batch_size, use gradient accumulation | batch_size=128, accumulate_grad_batches=2 |
| Slow training | Check GPU utilization | nvidia-smi, enable mixed precision |
| Poor convergence | Check LR, data quality | LR finder, check data balance |
| Overfitting | Train loss << Val loss | Increase dropout, early stopping |
| Export fails | ONNX opset version | Use opset 17, check custom ops |