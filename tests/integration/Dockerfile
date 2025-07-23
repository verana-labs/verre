# --- Stage 1: Builder ---
FROM golang:1.22.11-alpine AS builder

RUN apk add --no-cache git make gcc musl-dev linux-headers libusb-dev curl

# Clone repo
WORKDIR /src
RUN git clone https://github.com/verana-labs/verana-blockchain.git
WORKDIR /src/verana-blockchain

RUN make install

# --- Stage 2 ---
FROM alpine:latest

RUN apk add --no-cache bash

COPY --from=builder /go/bin/veranad /usr/local/bin/veranad
COPY --from=builder /src/verana-blockchain/scripts /app/scripts
COPY ./tests/integration/init.sh /app/init.sh

WORKDIR /app

CMD ["bash", "./scripts/setup_primary_validator.sh"]