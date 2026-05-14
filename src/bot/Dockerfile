# bot/Dockerfile
FROM golang:1.25.10 as builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o discordbot main.go

CMD ["./discordbot"]