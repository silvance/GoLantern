# Goreleaser builds the binary and runs `docker build` with the binary
# already in the context, so this Dockerfile only assembles the image.
# Distroless is safe because modernc.org/sqlite is pure Go — the binary
# is statically linked with CGO_ENABLED=0.
FROM gcr.io/distroless/static-debian12:nonroot

COPY golantern /usr/local/bin/golantern

EXPOSE 8000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/golantern"]
CMD ["-addr", "0.0.0.0:8000"]
