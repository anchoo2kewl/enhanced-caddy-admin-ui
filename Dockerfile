FROM golang:1.25.0-alpine AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY main.go usermgmt.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o caddy-admin main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o usermgmt usermgmt.go

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /app/caddy-admin .
COPY --from=builder /app/usermgmt .
COPY html/ ./html/

# Create data directory for SQLite database
RUN mkdir -p /root/data

CMD ["./caddy-admin"]
