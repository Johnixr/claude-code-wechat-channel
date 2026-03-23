#!/usr/bin/env node

/**
 * Claude Code WeChat Channel — CLI entry point
 *
 * Usage:
 *   npx claude-code-wechat-channel setup   — WeChat QR login
 *   npx claude-code-wechat-channel start   — Start channel server (used by .mcp.json)
 *   npx claude-code-wechat-channel install — Write .mcp.json to current directory
 */

import { execSync, spawnSync } from "node:child_process";
import { existsSync, writeFileSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST_DIR = resolve(__dirname, "dist");

function getBunPath() {
  try {
    return execSync("which bun", { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function getNodePath() {
  return process.execPath;
}

function runScript(script, args = []) {
  const scriptPath = resolve(DIST_DIR, script);
  if (!existsSync(scriptPath)) {
    console.error(`Error: ${scriptPath} not found. Package may be corrupted.`);
    process.exit(1);
  }

  // Prefer bun for performance, fall back to node
  const bun = getBunPath();
  const runtime = bun || getNodePath();
  const result = spawnSync(runtime, [scriptPath, ...args], {
    stdio: "inherit",
    env: process.env,
  });
  process.exit(result.status ?? 1);
}

function install() {
  const mcpConfig = {
    mcpServers: {
      wechat: {
        command: "npx",
        args: ["-y", "claude-code-wechat-channel", "start"],
      },
    },
  };

  const mcpPath = resolve(process.cwd(), ".mcp.json");

  if (existsSync(mcpPath)) {
    try {
      const existing = JSON.parse(readFileSync(mcpPath, "utf-8"));
      existing.mcpServers = existing.mcpServers || {};
      existing.mcpServers.wechat = mcpConfig.mcpServers.wechat;
      writeFileSync(mcpPath, JSON.stringify(existing, null, 2) + "\n", "utf-8");
      console.log(`Updated: ${mcpPath}`);
    } catch {
      writeFileSync(mcpPath, JSON.stringify(mcpConfig, null, 2) + "\n", "utf-8");
      console.log(`Created: ${mcpPath}`);
    }
  } else {
    writeFileSync(mcpPath, JSON.stringify(mcpConfig, null, 2) + "\n", "utf-8");
    console.log(`Created: ${mcpPath}`);
  }

  console.log(`
Next steps:
  1. Run: npx claude-code-wechat-channel setup
  2. Then: claude --dangerously-load-development-channels server:wechat
`);
}

function help() {
  console.log(`
  Claude Code WeChat Channel

  Usage: npx claude-code-wechat-channel <command>

  Commands:
    setup     WeChat QR login (scan to authenticate)
    start     Start the channel MCP server
    install   Write .mcp.json to current directory
    help      Show this help message
`);
}

const command = process.argv[2];

switch (command) {
  case "setup":
    runScript("setup.js");
    break;
  case "start":
    runScript("wechat-channel.js");
    break;
  case "install":
    install();
    break;
  case "help":
  case "--help":
  case "-h":
    help();
    break;
  default:
    if (command) {
      console.error(`Unknown command: ${command}`);
    }
    help();
    process.exit(command ? 1 : 0);
}
