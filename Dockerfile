#syntax=docker/dockerfile:1.5.1

FROM golang:1.20-alpine AS build
WORKDIR /go/src/exporter_exporter
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go mod download ;\
    go build -trimpath

FROM gcr.io/distroless/static:latest AS runtime
COPY --from=build /go/src/exporter_exporter/exporter_exporter /exporter_exporter
ENTRYPOINT [ "/exporter_exporter" ]
