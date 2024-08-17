FROM docker.arvancloud.ir/golang:1.22-alpine as build

WORKDIR /build

ENV GOPROXY=https://proxy.golang.org,direct

COPY go.mod go.sum ./

RUN go mod tidy

COPY . .

RUN go build -o /build/main ./cmd

FROM docker.arvancloud.ir/alpine:latest as runtime

WORKDIR /app

COPY --from=build /build/main . 

EXPOSE 50051
EXPOSE 3000

CMD ["./main"]