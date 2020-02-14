FROM golang:1.13.8-alpine AS build
RUN mkdir /src
WORKDIR /src
COPY *.go go.mod go.sum /src/
RUN apk add git
RUN go build .

FROM alpine
COPY --from=build /src/exporter_exporter /usr/bin/
ENTRYPOINT ["/usr/bin/exporter_exporter"]
