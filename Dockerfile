FROM golang:1.19-alpine3.16
WORKDIR /bin
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o ./dsv main.go
RUN rm -rf ./go.mod ./main.go
WORKDIR /app