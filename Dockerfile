FROM golang:1.25.6-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /banking ./cmd/server

FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /banking /app/banking

ENV APP_PORT=8080

EXPOSE 8080

ENTRYPOINT ["/app/banking"]

