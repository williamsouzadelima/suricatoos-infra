FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /control-plane ./cmd/control-plane/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /control-plane /usr/local/bin/control-plane
ENTRYPOINT ["control-plane"]
