# TapChat

A User-Provisioned Transport Layer for Censorship-Resistant and Metadata-Private Messaging.

## Overview

TapChat is a decentralized instant messaging system where each user owns their own infrastructure components. The architecture consists of:

- **Client**: Local core managing state, encryption/decryption (only handles plaintext)
- **Inbox**: Message queue and index source of truth
- **Storage**: Blob service for attachments and large messages
- **Wakeup**: Notification component (optional for desktop)

All components are user-provisioned, meaning no central server holds your messages or metadata.

## Features

- End-to-end encryption using OpenMLS (MLS protocol, RFC 9420)
- Decentralized architecture - each user owns their infrastructure
- Metadata-private messaging
- Real-time WebSocket subscriptions
- Cross-device identity with BIP39/BIP32 key derivation

## Project Structure

```
src/                     # Rust core library
  identity/              # BIP39 identity system
  mls_adapter/           # OpenMLS integration
  model/                 # Core data structures
  ffi_api/               # FFI interface for platform bindings

services/cloudflare/     # Reference backend implementation
  inbox/                 # Inbox Durable Object
  storage/               # R2 blob storage

app/desktop/             # Tauri desktop application
  src/                   # React frontend
  src-tauri/             # Rust backend bindings
```

## Current Status

**v0.1.0-alpha** - 1-to-1 private chat working with real-world testing.

## Quick Start

### Prerequisites

- Rust 1.70+
- Node.js 18+
- Cloudflare account (for backend deployment)

### Build

```bash
# Build Rust core
cargo build

# Build desktop app
cd app/desktop
npm install
npm run tauri:dev
```


## License

MIT