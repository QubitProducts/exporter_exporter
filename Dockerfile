#syntax=docker/dockerfile:1.5.1

FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /go/src/exporter_exporter
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go mod download ;\
    go build -trimpath

FROM cgr.dev/chainguard/static:latest AS runtime
COPY --from=build /go/src/exporter_exporter/exporter_exporter /exporter_exporter
ENTRYPOINT [ "/exporter_exporter" ]
