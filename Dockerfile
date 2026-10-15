FROM debian:bookworm-slim

WORKDIR /workspace

ARG HUGO_VERSION=0.156.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && wget -O /tmp/hugo.deb "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-amd64.deb" \
    && apt-get install -y --no-install-recommends /tmp/hugo.deb \
    && rm -f /tmp/hugo.deb \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 1313
CMD ["hugo", "server", "--bind", "0.0.0.0"]
