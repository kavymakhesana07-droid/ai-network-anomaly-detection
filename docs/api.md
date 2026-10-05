# API Specification

The AI Network Anomaly Detection System exposes a REST API for alert querying, statistics, and model management.

## Base URL

```
Production:  https://api.anomaly-detection.example.com/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

### API Key (Header)
```
Authorization: Bearer <api_key>
X-API-Key: <api_key>
```

### JWT (Optional)
```
Authorization: Bearer <jwt_token>
```

## Endpoints

### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-10-05T12:34:56Z",
  "version": "1.0.0",
  "components": {
    "redis": "healthy",
    "elasticsearch": "healthy",
    "api": "healthy"
  }
}
```

---

### List Alerts
```http
GET /api/v1/alerts
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `alert_type` | string | Filter by detector type |
| `severity` | string | Filter by severity (debug, info, notice, warning, error, critical, alert, emergency) |
| `is_anomaly` | boolean | Filter by anomaly flag |
| `src_ip` | string | Source IP filter |
| `dst_ip` | string | Destination IP filter |
| `flow_key` | string | Exact flow key match |
| `start_time` | float | Start timestamp (epoch) |
| `end_time` | float | End timestamp (epoch) |
| `limit` | integer | Max results (1-1000, default: 100) |
| `offset` | integer | Pagination offset (default: 0) |
| `sort_by` | string | Sort field (default: timestamp) |
| `sort_order` | string | asc/desc (default: desc) |

**Response:**
```json
{
  "alerts": [
    {
      "alert_type": "fast_path",
      "flow_key": "192.168.1.1:1234-10.0.0.1:80-tcp",
      "timestamp": 1699123456.789,
      "is_anomaly": true,
      "severity": "critical",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "src_port": 12345,
      "dst_port": 80,
      "protocol": 6,
      "anomaly_score": 0.95,
      "model_version": "fast_path_v1.2.0",
      "inference_time_ms": 2.3,
      "enrichment": {
        "src_ip_enrichment": { "asn": 15169, "country": "US" },
        "dst_ip_enrichment": { "asn": 15169, "country": "US" }
      }
    }
  ],
  "total": 1234,
  "limit": 100,
  "offset": 0
}
```

---

### Get Alert by ID
```http
GET /api/v1/alerts/{alert_id}
```

**Response:**
```json
{
  "alert_type": "fast_path",
  "flow_key": "192.168.1.100:12345-10.0.0.1:80-tcp",
  "timestamp": 1699123456.789,
  "is_anomaly": true,
  "severity": "critical",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 12345,
  "dst_port": 80,
  "protocol": 6,
  "anomaly_score": 0.95,
  "reconstruction_error": null,
  "anomaly_probability": 0.95,
  "model_version": "fast_path_v1.2.0",
  "inference_time_ms": 2.3,
  "enrichment": {
    "src_ip_enrichment": { "asn": 15169, "country": "US" },
    "dst_ip_enrichment": { "asn": 15169, "country": "US" },
    "stix_indicators": [{"type": "indicator", "pattern": "[ipv4-addr:value = '192.168.1.100']"}],
    "correlated_alerts": ["alert-uuid-1", "alert-uuid-2"],
    "correlation_score": 0.85
  }
}
```

---

### Alert Statistics
```http
GET /api/v1/alerts/stats/summary
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | float | Start timestamp (epoch) |
| `end_time` | float | End timestamp (epoch) |

**Response:**
```json
{
  "total": 15420,
  "by_severity": {
    "critical": 234,
    "error": 1567,
    "warning": 8921,
    "notice": 3421,
    "info": 2345,
    "debug": 120
  },
  "by_type": {
    "fast_path": 12000,
    "deep_path": 3100,
    "xgboost_supervised": 320
  },
  "by_anomaly": {
    "anomaly": 1542,
    "normal": 13878
  }
}
```

---

### Get Single Alert
```http
GET /api/v1/alerts/{alert_id}
```

**Response:**
```json
{
  "alert_type": "fast_path",
  "flow_key": "192.168.1.100:12345-10.0.0.1:80-tcp",
  "timestamp": 1699123456.789,
  "is_anomaly": true,
  "severity": "critical",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 12345,
  "dst_port": 80,
  "protocol": 6,
  "anomaly_score": 0.95,
  "model_version": "fast_path_v1.2.0",
  "inference_time_ms": 2.3
}
```

---

### Alert Statistics
```http
GET /api/v1/alerts/stats/summary
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | float | Start timestamp (epoch) |
| `end_time` | float | End timestamp (epoch) |

**Response:**
```json
{
  "total": 15420,
  "by_severity": {
    "critical": 234,
    "error": 1567,
    "warning": 8921,
    "notice": 3421,
    "info": 2345,
    "debug": 120
  },
  "by_type": {
    "fast_path": 12000,
    "deep_path": 3100,
    "xgboost_supervised": 320
  },
  "by_anomaly": {
    "anomaly": 1542,
    "normal": 13878
  }
}
```

---

### Models
```http
GET /api/v1/models
```

**Response:**
```json
{
  "models": [
    {
      "name": "fast_path",
      "version": "1.2.0",
      "stage": "Production",
      "detector_type": "fast_path",
      "created_at": "2026-10-01T12:00:00Z",
      "metrics": {
        "test_auc": 0.92,
        "precision": 0.89,
        "recall": 0.87
      }
    }
  ],
  "total": 3
}
```

---

### Metrics
```http
GET /metrics
```

**Response:**
```
# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{endpoint="/health",method="GET"} 1234
# HELP alerts_received_total Total alerts received
# TYPE alerts_received_total counter
alerts_received_total 15420
# HELP alerts_received_total Total alerts received
# TYPE alerts_received_total counter
alerts_received_total{detector="fast_path"} 12000
# HELP alerts_received_total Total alerts received
# TYPE alerts_received_total counter
alerts_received_total{detector="deep_path"} 3100
```

---

## Error Responses

| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 422 | Validation Error |
| 429 | Rate Limited |
| 500 | Internal Server Error |

**Error Format:**
```json
{
  "detail": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2026-10-05T12:34:56Z"
}
```

---

## Rate Limiting

| Tier | Requests/Window |
|------|-----------------|
| Anonymous | 60/min |
| Authenticated | 1000/min |
| Admin | 10000/min |

Headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1699123456
```

---

## Webhooks

### Alert Webhook
```http
POST /webhooks/alerts
```

**Payload:**
```json
{
  "alert": { ... },
  "enrichment": { ... },
  "correlation": { ... }
}
```

---

## SDK Examples

### Python
```python
import httpx

async with httpx.AsyncClient(base_url="http://localhost:8000/api/v1") as client:
    # List alerts
    resp = await client.get("/alerts", params={"limit": 10, "severity": "critical"})
    alerts = resp.json()["alerts"]
    
    # Get stats
    stats = await client.get("/api/v1/alerts/stats/summary")
    print(stats.json())
```

### cURL
```bash
# List alerts
curl -H "X-API-Key: your-key" "http://localhost:8000/api/v1/alerts?limit=10&severity=critical"

# Get stats
curl -H "X-API-Key: your-key" "http://localhost:8000/api/v1/alerts/stats/summary"
```