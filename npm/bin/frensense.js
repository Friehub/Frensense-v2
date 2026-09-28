#!/usr/bin/env node

"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const platform = os.platform();
const arch = os.arch();

let binaryName;
if (platform === "linux" && arch === "x64") {
  binaryName = "frensense-linux-x64";
} else if (platform === "darwin" && arch === "x64") {
  binaryName = "frensense-macos-x64";
} else if (platform === "darwin" && arch === "arm64") {
  binaryName = "frensense-macos-arm64";
} else if (platform === "win32" && arch === "x64") {
  binaryName = "frensense-windows-x64.exe";
} else {
  console.error(
    `[frensense] Unsupported platform or architecture: ${platform}-${arch}.\n` +
      `Frensense prebuilt binaries are available for linux-x64, macos-x64, macos-arm64, and windows-x64.\n` +
      `You can build from source using Cargo: cargo install frensense`
  );
  process.exit(1);
}

const binaryPath = path.join(__dirname, "..", "dist", "binaries", binaryName);

if (!fs.existsSync(binaryPath)) {
  console.error(
    `[frensense] Binary not found at: ${binaryPath}\n` +
      `Please ensure @friehub/frensense was installed completely.`
  );
  process.exit(1);
}

// Ensure execution permission on Unix systems
if (platform !== "win32") {
  try {
    fs.accessSync(binaryPath, fs.constants.X_OK);
  } catch {
    try {
      fs.chmodSync(binaryPath, 0o755);
    } catch (err) {
      console.warn(`[frensense] Warning: could not set executable permissions on ${binaryPath}:`, err);
    }
  }
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

child.on("error", (err) => {
  console.error(`[frensense] Failed to execute binary:`, err);
  process.exit(1);
});

child.on("close", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 0);
  }
});
