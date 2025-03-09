FROM rust:1.85 AS builder

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM rust:1.85-slim
RUN apt-get update && apt-get install -y ca-certificates curl sudo libpq5 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/lava-testing /usr/local/bin/lava-testing

CMD ["lava-testing"]
