FROM golang:1.25.0-alpine AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod init caddy-admin || true
RUN go get github.com/gorilla/sessions@v1.2.1
RUN go get golang.org/x/crypto@v0.19.0

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o caddy-admin main.go

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/caddy-admin .
COPY html/ ./html/

CMD ["./caddy-admin"]
