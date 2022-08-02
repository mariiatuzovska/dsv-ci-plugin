FROM golang:1.18.3-alpine3.16 AS builder
WORKDIR /app
COPY ./ ./
RUN CGO_ENABLED=0 go build -o /bin/app main.go

FROM scratch
COPY --from=builder /bin/app /bin/app
ENTRYPOINT ["app"]