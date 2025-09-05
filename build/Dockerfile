FROM --platform=$BUILDPLATFORM golang:1.24-alpine3.21 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /go-app

ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
ENV GOMODCACHE=/gomod-cache
ENV GOCACHE=/go-cache

# Install dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod,target=/gomod-cache \
    go env -w GOMODCACHE=/gomod-cache \
    && go env -w GOCACHE=/go-cache \
    && go mod download

COPY "./cmd" "./cmd"
COPY ./internal /go-app/internal


RUN --mount=type=cache,id=gomod,target=/gomod-cache \
    --mount=type=cache,id=gocache,target=/go-cache \
    go build -ldflags="-s -w" -o ./bin/main "./cmd" \
    && chmod +x ./bin/main

# Final image
FROM alpine:3.21 AS output
WORKDIR /go-app
COPY --from=builder /go-app/bin/main /go-app/main
ENTRYPOINT ["/go-app/main"]
