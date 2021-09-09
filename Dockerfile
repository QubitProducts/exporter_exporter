FROM golang:1.16-alpine AS build

RUN mkdir /src
WORKDIR /src

COPY go.mod go.sum /src/
RUN go mod download

COPY *.go /src/
RUN go build .

FROM alpine:latest
COPY --from=build /src/exporter_exporter /usr/bin/
ENTRYPOINT ["/usr/bin/exporter_exporter"]
