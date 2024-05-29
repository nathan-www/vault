#!/bin/bash
deno compile -o ./compiled/vault-macos-ARM --target aarch64-apple-darwin ./src/app.ts
deno compile -o ./compiled/vault-macos-x64 --target x86_64-apple-darwin ./src/app.ts
deno compile -o ./compiled/vault-windows-x64 --target x86_64-pc-windows-msvc ./src/app.ts
deno compile -o ./compiled/vault-linux-x64 --target x86_64-unknown-linux-gnu ./src/app.ts