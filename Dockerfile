FROM golang:1.12.4 AS builder
WORKDIR /
COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./

RUN CGO_ENABLED=0 go build \
    -installsuffix 'static' \
    -o /social-auth-service .

FROM debian:stretch-slim
COPY --from=builder /social-auth-service /social-auth-service

RUN apt-get update && apt-get install -y ca-certificates openssl

ENTRYPOINT ["/social-auth-service"]