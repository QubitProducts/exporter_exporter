# Yahoo Quotes exporter for Prometheus

This is a toy exporter that demonstrates how to write exporters that take
arguments. This pattern is used in the Blackbox and SNMP exporters.

The exporter has two endpoints.

- /price: requires one or more sym parameters which should be
  stock market symbols present in Yahoo Finance
- /metrics: this exposes the metrics for the collector itself.

## Configuration

```
scrape_configs:
  - job_name: 'yquotes exporter'
    scrape_interval: 1s
    static_configs:
      - targets: ['localhost:9666']
  - job_name: 'yquotes'
    scrape_interval: 5s
    metrics_path: /price
    params:
      sym:
        - AAPL
        - MSFT
        - GOOG
    static_configs:
      - targets: ['localhost:9666']
```
