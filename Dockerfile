# static binary, no shell, runs as non-root: tiny attack surface
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /netprobe ./cmd/netprobe

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /netprobe /netprobe
USER nonroot:nonroot
EXPOSE 9115
ENTRYPOINT ["/netprobe"]
CMD ["serve", "-listen", ":9115", "-f", "/config/targets.txt"]
