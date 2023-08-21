Exporter Exporter Extended Labels 
----------------------------------
# Background to this fork
This is a fork of [exporter_exporter](https://github.com/QubitProducts/exporter_exporter) that 
include additional support to add additional labels to the metrics fetched through the proxy. 
This label enrichment was proposed as 
[PR](https://github.com/QubitProducts/exporter_exporter/pull/95)
to the exporter_exporter project, but was considered out of scope. 
This fork is compatible with exporter_exporter 
[0.5.0](https://github.com/QubitProducts/exporter_exporter/releases/tag/v0.5.0).

The documentation for the extended labels is in the end of this README in the section called 
"Extended Labels".


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
- Small code size, minimal external depedencies, easily auditable.

The exporter has three endpoints.

- /: displays a list of all exporters with links to their metrics.
  - Returns JSON if the header "Accept: application/json" is passed

- /proxy: which takes the following parameters:
  - *module*: the name of the module from the configuration to execute. (a default
    module can be selected using the defaultModule config option)
  - *args*: (only for exec modules): additional arguments to the backend command.
  - all other query string parameters are passed on to any http backend module.
    (excluding the first *module* parameter value).

- /metrics: this exposes the metrics for the collector itself.

Features that will NOT be included:

- merging of module outputs into one query (this would break _up_ behaviour)

## Installation

You can build directly using a plain ```go get github.com/QubitProducts/exporter_exporter```.
The provided Makefile is primarily used for releases.

Pre-built binaries and a debian package are available on the [GitHub release page](https://github.com/QubitProducts/exporter_exporter/releases).

An ansible recipe as also [available](https://github.com/umanit/ansible-prometheus_exporter_exporter) (kindly provided by one of our users).

TODO:

- Config reload on HUP (or POST, or config file change?)
- route to a docker/rocket container by name

### Windows Service

The binary can be installed as a Windows service by supplying the `-winsvc install` arg.
All other arguments passed along with `-winsvc install` will be added to the service startup 
and can only be changed by uninstalling/installing it again (or modifying the Windows registry directly).

## Configuration

In expexp.yaml list each exporter listening on localhost with its known port.

```
defaultModule: node # called if "module" param is not supplied
modules:
  node:
    method: http
    http:
       port: 9100

  mtail:
    method: http
    http:
       port: 3903
       headers:
          foo: bar

  cadvisor:
    method: http
    http:
       verify: false
       port: 4194

  netdata:
    method: http
    http:
       port: 19999
       path: '/api/v1/allmetrics?format=prometheus'

  blackbox:
    method: http
    http:
       port: 9115
       path: '/probe'

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

  somefile:
    method: file
    file:
      path: /tmp/myfile.prometheus.txt
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
  - job_name: 'blackbox'
    metrics_path: /proxy
    params:
      module:
        - blackbox
        - icmp_example
    static_configs:
      - targets:
        - 8.8.8.8
        - 8.8.4.4
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: host:9999
```

### Blackbox Exporter

The blackbox exporter also uses the "module" query string parameter. To query it via
exporter_exporter we rely on the stripping of the initial "module" parameter. For example
 
```
curl http://localhost:9999/proxy\?module\=blackbox\&module\=icmp_example\&target\=8.8.8.8
```

Will query the icmp_example module in your blackbox configuration.


## Directory-based configuration

You can also specify `-config.dirs` to break the configuration into separate
files.  The module name is taken from the name of the file (minus the
yml/yaml extension), and the configuration for that module goes in at the
top level.

Note that if you want to use *only* this configuration method and not the file-based 
configuration (`-config.file` option), you must provide an empty string for the file
option : `./exporter_exporter -config.file "" -config.dirs "/etc/exporter_exporter/"`

```
==> expexp.yaml <==
modules: {}

==> expexp.d/node.yaml <==
method: http
http:
   port: 9100

==> expexp.d/mtail.yaml <==
method: http
http:
   port: 3903
```

## TLS configuration

You can use exporter_exporter with TLS to encrypt the traffic, and at the
same time enforce strong mutual authentication between the nodes and the
prometheus server.

Note that `-web.tls.verify` will accept *any* certificate signed by the
`-web.tls.ca`, so you need to create a separate CA for this purpose - or use
a self-signed certificate, which acts as its own CA.

Here is a simple configuration example, using one key/cert for the
prometheus server and one key/cert shared between all the remote nodes.
Firstly, create the keys and certs:

```
openssl req -x509 -newkey rsa:2048 -keyout prom_node_key.pem -out prom_node_cert.pem -days 29220 -nodes -subj /commonName=prom_node/ -addext "subjectAltName=DNS:prom_node"
openssl req -x509 -newkey rsa:2048 -keyout prometheus_key.pem -out prometheus_cert.pem -days 29220 -nodes -subj /commonName=prometheus/ -addext "subjectAltName=DNS:prometheus"
```

Create an `/etc/prometheus/ssl/` directory on the prometheus server and all
the remote nodes.  Install both cert.pem files everywhere.  It is safe for
them to be world-readable.

Install `prom_node_key.pem` only on the nodes, and set file permissions to
protect it so that only exporter_exporter can read it.  Similarly, install
`prometheus_key.pem` only on the prometheus server, and set permissions so
that only the prometheus process can read it.

Configuration for exporter_exporter on the nodes (here it also disables
plain HTTP):

```
EXPEXP_FLAGS='-web.listen-address= -web.tls.listen-address=:9998
 -web.tls.cert=/etc/prometheus/ssl/prom_node_cert.pem
 -web.tls.key=/etc/prometheus/ssl/prom_node_key.pem
 -web.tls.ca=/etc/prometheus/ssl/prometheus_cert.pem
 -web.tls.verify'
```

To test, use `curl` to make a scrape, replacing x.x.x.x with the IP address
of the target:

```
curl --cert /etc/prometheus/ssl/prometheus_cert.pem \
     --key /etc/prometheus/ssl/prometheus_key.pem \
     --cacert /etc/prometheus/ssl/prom_node_cert.pem \
     --resolve prom_node:9998:x.x.x.x \
     -v https://prom_node:9998/proxy?module=node
```

When this is working, configure your prometheus server to use https. Example:

```
  - job_name: node
    scrape_interval: 1m
    scrape_timeout: 50s
    file_sd_configs:
      - files:
        - /etc/prometheus/targets.d/node_targets.yml
    scheme: https
    tls_config:
      # Verifying remote identity
      ca_file: /etc/prometheus/ssl/prom_node_cert.pem
      server_name: prom_node
      # Asserting our identity
      cert_file: /etc/prometheus/ssl/prometheus_cert.pem
      key_file: /etc/prometheus/ssl/prometheus_key.pem
    metrics_path: /proxy
    params:
      module: [ node ]
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
      - source_labels: [__address__]
        regex: '([^:]+)'
        target_label: __address__
        replacement: '${1}:9998'
```

Example `/etc/prometheus/targets.d/node_targets.yml`:

```
- labels: []
  targets:
  - 192.0.2.1
  - 192.0.2.2
```

# Extended labels
When metrics are proxy through the exporter_exporter it is possible to appended labels based
on target and original labels and label value. A possible use case would be for the 
snmp-exporter for interfaces where it is a need to add labels to specific interfaces 
on specific targets. This can be information that is based on data from a network management 
system where for example some interface have specific attributes, like interface is a trunk
and have neighbours. For trunk interface additional monitoring and alerting is required.
Solving this with relabeling is not feasible since it would require Prometheus job configuration
per target.
With extended labels enabled the metrics payload returned from the exporter, e.g. snmp-exporter,
will be match against target, metrics name and label name and label value. If matched, the 
additional configured labels are added to the metric.

## Configuration 
To enable extended labels the following 3 attributes must be added to the `expexp.yaml`.

```yaml
defaultModule: snmp
modules:
  snmp:
    method: http
    http:
      port: 9116
      path: /snmp
      # Enable extended labels
      label_extend: true
      # The url parameter identify the target 
      label_extend_target_url_identity: target
      # The path to the file for the specific extended label configuration 
      label_extend_path: /tmp/interfaces.yaml
```
`label_extend` set to true just enable the feature for the module. 
The second , `label_extend_target_url_identity`, define what target the extended labels 
should be match against. For the snmp-exporter the url parameter target define the host that 
snmp should be executed against. The third, `label_extend_path`, define the path to the 
extended labels configuration, typical created by automation, for example extract lldp based 
neighbor information from Cisco Prime that result in labels as trunk and neighbor.

The configuration, defined by label_extend_path has the following format, using an example 
that is applicable, but not limited, to the snmp-exporter use case:
```yaml
targets:
  foo.bar.org:
    labels:
    -
      label_key_name: "ifIndex"
      extended_labels:
        -
          metric_match: ifOperStatus
          match_label_key_values:
            "*":
          default_label_pairs:
            type: l2switch
        -
          metric_match: if(Admin|Oper)Status
          match_label_key_values:
            "370":
              label_pairs:
                 trunk: true
                 endpoint: 172.25.1.19:13
            "371":
              label_pairs:
                trunk: true
                endpoint: 172.25.1.13:45
    -
      label_key_name: "iftype"
      extended_labels:
        - match_label_key_values:
            "mpls":
              label_pairs:
                external: true
  abc.xyz.org:
    labels:
     .......
```
The `targets` attribute include a map of targets, in the above example a host name. 
The entry is matched against the value of the url query parameter defined by 
`label_extend_target_url_identity`. 
So if a metrics has a label named `ifIndex`, defined by `label_key_name`, 
the logic will evaluate against what is configured in the `extended_labels`. 
First it will validate if this is only applicable to specific named metrics, 
for example `ifOperStatus`. The metric_match value is a regular expression 
and default to .* if not defined. 
The `match_label_key_values` define what label value to match against. 
In the first entry the match is done against all values, `*` of `ifIndex` and a label 
called type with value `l2switch` is added. In the second entry, 
both the metrics named `ifOperStatus` and `ifAdminStatus` is matched, but labels, 
trunk and endpoint, are only added for metrics where ifIndex has the value of `370` or `371`.
