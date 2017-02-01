FROM alpine
ADD .build/linux-amd64/exporter_exporter /usr/bin/exporter_exporter

ENTRYPOINT ["/usr/bin/exporter_exporter"]
