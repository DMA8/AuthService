FROM golang:1.17-buster as builder
EXPOSE 3000
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o application -v cmd/main.go

FROM alpine:3.15.4
COPY --from=builder /app/application /app/application
COPY --from=builder /app/config /app/config

WORKDIR /app
CMD ["/app/application"]
