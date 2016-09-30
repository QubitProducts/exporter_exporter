# Exporter Exporter - prometheus exporter proxy

```   "you mean apache/nginx" - bbrazil ```

This is in a very alpha state, and is largely untested at this time.

The exporter has two endpoints.

- /proxy: which takes the following parameters
  - module: the name of the module from the configuration to execute
  - args (optional): arguments to pass to the module
  - params (optional): named parameter to pass to the module (either as CLI args, or http parameters)
- /metrics: this exposes the metrics for the collector itself.

The exporter has 3 modes of operation:

- A reverse proxy, passing requests to another exporter (typically on the local
  machine), that parses the returned metrics for verification, and then serves
  them back to the caller
- Reverse proxy without verification
- Pass on the output of a locally run commnad exectuted when the scrape
  is requested.

TODO:
- TLS with client CA verification
- Proxy to TLS
- Pass params and args to downstream exporter
- process supervisor to start/run exporters
- Include relabeling in prom config

## Configuration

In expexp.yaml

```
modules:
  node:
    method: http
    http:
       port: 9100

  mtail:
    method: http
    http:
       port: 3903

  cadvisor:
    verify: false
    method: http
    http:
       port: 4194

  somescript:
    method: exec
    timeout: 1s
    exec:
      command: /tmp/myscript.sh
      args:
        - "myarg1"
        - "myarg2"
      env:
        THING: "1"
        THING2: "2"

```

In your prometheus configuration
```
scrape_configs:
  - job_name: 'expexp_metrics'
    scrape_interval: 1s
    static_configs:
      - targets: ['host:9999']
  - job_name: 'cadvisor'
    scrape_interval: 5s
    metrics_path: /proxy
    params:
      module:
        - cadvisor
    static_configs:
      - targets: ['host:9999']
  - job_name: 'mtail'
    scrape_interval: 5s
    metrics_path: /proxy
    params:
      module:
        - mtail
    static_configs:
      - targets: ['host:9999']
  - job_name: 'somescript'
    scrape_interval: 5s
    metrics_path: /proxy
    params:
      module:
        - somescript
    static_configs:
      - targets: ['host:9999']
```
