# Runtime-only image: the static musl binary is cross-compiled outside
# (`cross build --release --target x86_64-unknown-linux-musl`) so the build
# needs no access to the private git dependencies. Mirrors the warren-api
# distroless convention.
FROM gcr.io/distroless/static-debian12:nonroot
COPY target/x86_64-unknown-linux-musl/release/warren-connect /usr/local/bin/warren-connect
USER nonroot
EXPOSE 8095
ENTRYPOINT ["/usr/local/bin/warren-connect"]
