# Lava Testing

An automated testing tool for the [Lava Loans](https://lava.xyz) protocol. This tool runs as an HTTP server that allows you to trigger end-to-end tests of the Lava borrowing process.

## Features

- Automates the complete loan lifecycle: setup, borrowing, repaying, and closing
- Fetches test BTC from the Mutinynet faucet
- Fetches test Lava USD from the Lava faucet
- Downloads and configures the Lava loans borrower CLI
- Provides an HTTP server with endpoints for running tests
- Returns funds to faucets when tests complete

## Requirements

- Rust 1.85 or higher
- For local development:
  - macOS: Homebrew with libpq installed
  - Linux: libpq-dev package
- For deployment:
  - Docker

## Quick Start with Docker

```bash
# Build and start the container
docker-compose up -d

# Check logs
docker logs lava-testing

# Run a test (can take a few minutes)
curl http://localhost:3000/run-test

# Check the server's health
curl http://localhost:3000/health
```

## API Endpoints

- `GET /run-test` - Runs a complete loan lifecycle test (can take a few minutes)
- `GET /health` - Health check endpoint
