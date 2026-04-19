FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/gh-proxy ./cmd/gh-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gh-proxy /usr/local/bin/gh-proxy
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gh-proxy"]
CMD ["serve"]
