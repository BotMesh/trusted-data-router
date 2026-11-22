# Minimal build context: Dockerfile and the release trusted-data-router binary.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 router
COPY --chmod=755 trusted-data-router /usr/local/bin/trusted-data-router
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/trusted-data-router"]
