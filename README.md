# Exporter Exporter - prometheus exporter proxy

```   "you mean apache/nginx" - bbrazil ```

This provides a simple reverse proxy for prometheus exporters. It is intended as a
single binary alternative to nginx/apache for use in environments where opening multiple
TCP ports to all servers might be difficult (technically or politically)

The advantages are:

- A single port can be used to query multiple exporters (to ease firewall configuration concerns).
- Can provide TLS with optional client certificate authentication.
- Provides verification that the target is serving prometheus metrics.
- Can be used to execute scripts that produce prometheus metrics.
- _up_ behaviour is the same as for querying individual collectors.
- Small code size, minimcal external depedencies, easily auditable

The exporter has two endpoints.

- /proxy: which takes the following parameters
  - module: the name of the module from the configuration to execute
  - args (optional): arguments to pass to the module
  - params (optional): named parameter to pass to the module (either as CLI args, or http parameters)
- /metrics: this exposes the metrics for the collector itself.

Features that will NOT be included:

- merging of module outputs into one query (this would break _up_ behaviour)

TODO:

- Config reload on HUP (or POST, or config file change?)
- route to a docker/rocket container by name

## Configuration

In expexp.yaml list each exporter listening on localhost with its known
port.

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
