#syntax=docker/dockerfile:1.4.2

FROM golang:1.19-alpine AS build
WORKDIR /go/src/
COPY . .
RUN go mod download ;\
    go build

FROM alpine:latest AS runtime
COPY --from=build /go/src/exporter_exporter /usr/local/bin/
ENTRYPOINT ["exporter_exporter"]
