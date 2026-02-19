FROM golang:1.23-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates
COPY go.mod ./
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/service ./cmd/main.go

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata
RUN adduser -D -g '' appuser
COPY --from=builder /bin/service /bin/service
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["/bin/service"]
