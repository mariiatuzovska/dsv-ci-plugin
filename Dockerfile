FROM golang:1.19-alpine3.16
WORKDIR /bin
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o ./vault main.go
RUN rm -rf ./go.mod ./main.go
WORKDIR /app

# FROM scratch
# COPY --from=builder /bin/app /bin/app
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# ENTRYPOINT ["app"]