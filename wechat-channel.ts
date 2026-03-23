#!/usr/bin/env bun
/**
 * Claude Code WeChat Channel Plugin — with full media support
 *
 * Bridges WeChat messages (text, image, voice, file, video) into a Claude Code
 * session via the Channels MCP protocol.
 *
 * Uses the official WeChat ClawBot ilink API (same protocol as @tencent-weixin/openclaw-weixin).
 */

import crypto from "node:crypto";
import { createCipheriv, createDecipheriv } from "node:crypto";
import fs from "node:fs";
import fsP from "node:fs/promises";
import path from "node:path";
import os from "node:os";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ────────────────────────────────────────────────────────────────────

const CHANNEL_NAME = "wechat";
const CHANNEL_VERSION = "0.2.0";
const DEFAULT_BASE_URL = "https://ilinkai.weixin.qq.com";
const CDN_BASE_URL = "https://novac2c.cdn.weixin.qq.com/c2c";
const BOT_TYPE = "3";
const CREDENTIALS_FILE = process.env.WECHAT_CREDENTIALS_FILE
  ? path.resolve(process.env.WECHAT_CREDENTIALS_FILE)
  : path.join(os.homedir(), ".claude", "channels", "wechat", "account.json");
const CREDENTIALS_DIR = path.dirname(CREDENTIALS_FILE);
const MEDIA_DIR = path.join(CREDENTIALS_DIR, "media");

const LONG_POLL_TIMEOUT_MS = 35_000;
const MAX_CONSECUTIVE_FAILURES = 3;
const BACKOFF_DELAY_MS = 30_000;
const RETRY_DELAY_MS = 2_000;

// ── Logging (stderr only — stdout is MCP stdio) ─────────────────────────────

function log(msg: string) {
  process.stderr.write(`[wechat-channel] ${msg}\n`);
}

function logError(msg: string) {
  process.stderr.write(`[wechat-channel] ERROR: ${msg}\n`);
}

// ── AES-128-ECB ──────────────────────────────────────────────────────────────

function encryptAesEcb(plaintext: Buffer, key: Buffer): Buffer {
  const cipher = createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function decryptAesEcb(ciphertext: Buffer, key: Buffer): Buffer {
  const decipher = createDecipheriv("aes-128-ecb", key, null);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function aesEcbPaddedSize(plaintextSize: number): number {
  return Math.ceil((plaintextSize + 1) / 16) * 16;
}

/**
 * Parse aes_key from API into raw 16-byte key.
 * Two encodings: base64(raw 16 bytes) or base64(hex string of 16 bytes).
 */
function parseAesKey(aesKeyBase64: string): Buffer {
  const decoded = Buffer.from(aesKeyBase64, "base64");
  if (decoded.length === 16) return decoded;
  if (decoded.length === 32 && /^[0-9a-fA-F]{32}$/.test(decoded.toString("ascii"))) {
    return Buffer.from(decoded.toString("ascii"), "hex");
  }
  throw new Error(`invalid aes_key: decoded ${decoded.length} bytes`);
}

// ── MIME helpers ──────────────────────────────────────────────────────────────

const EXT_TO_MIME: Record<string, string> = {
  ".pdf": "application/pdf", ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".txt": "text/plain", ".csv": "text/csv", ".zip": "application/zip",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".webp": "image/webp", ".mp4": "video/mp4",
  ".mp3": "audio/mpeg", ".wav": "audio/wav",
};

function getMimeFromFilename(filename: string): string {
  return EXT_TO_MIME[path.extname(filename).toLowerCase()] ?? "application/octet-stream";
}

// ── Credentials ──────────────────────────────────────────────────────────────

type AccountData = {
  token: string;
  baseUrl: string;
  accountId: string;
  userId?: string;
  savedAt: string;
};

function loadCredentials(): AccountData | null {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE)) return null;
    return JSON.parse(fs.readFileSync(CREDENTIALS_FILE, "utf-8"));
  } catch { return null; }
}

function saveCredentials(data: AccountData): void {
  fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), "utf-8");
  try { fs.chmodSync(CREDENTIALS_FILE, 0o600); } catch { /* best-effort */ }
}

// ── WeChat ilink API ─────────────────────────────────────────────────────────

function randomWechatUin(): string {
  const uint32 = crypto.randomBytes(4).readUInt32BE(0);
  return Buffer.from(String(uint32), "utf-8").toString("base64");
}

function buildHeaders(token?: string, body?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    AuthorizationType: "ilink_bot_token",
    "X-WECHAT-UIN": randomWechatUin(),
  };
  if (body) headers["Content-Length"] = String(Buffer.byteLength(body, "utf-8"));
  if (token?.trim()) headers.Authorization = `Bearer ${token.trim()}`;
  return headers;
}

async function apiFetch(params: {
  baseUrl: string; endpoint: string; body: string; token?: string; timeoutMs: number;
}): Promise<string> {
  const base = params.baseUrl.endsWith("/") ? params.baseUrl : `${params.baseUrl}/`;
  const url = new URL(params.endpoint, base).toString();
  const headers = buildHeaders(params.token, params.body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await fetch(url, { method: "POST", headers, body: params.body, signal: controller.signal });
    clearTimeout(timer);
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text}`);
    // Check JSON ret/errcode (WeChat API returns HTTP 200 with ret != 0 or errcode != 0 on failure)
    try {
      const json = JSON.parse(text);
      if (json.ret && json.ret !== 0) {
        throw new Error(`API ret=${json.ret} errcode=${json.errcode ?? 0}: ${json.errmsg ?? text}`);
      }
      if (json.errcode && json.errcode !== 0) {
        throw new Error(`API errcode ${json.errcode}: ${json.errmsg ?? text}`);
      }
    } catch (e) {
      if (e instanceof Error && (e.message.startsWith("API ret=") || e.message.startsWith("API errcode"))) throw e;
      // Not JSON or no error field — that's fine, return as-is
    }
    return text;
  } catch (err) { clearTimeout(timer); throw err; }
}

// ── CDN Download ─────────────────────────────────────────────────────────────

function buildCdnDownloadUrl(encryptedQueryParam: string): string {
  return `${CDN_BASE_URL}/download?encrypted_query_param=${encodeURIComponent(encryptedQueryParam)}`;
}

async function downloadAndDecrypt(encryptedQueryParam: string, aesKeyBase64: string): Promise<Buffer> {
  const key = parseAesKey(aesKeyBase64);
  const url = buildCdnDownloadUrl(encryptedQueryParam);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`CDN download ${res.status}`);
  const encrypted = Buffer.from(await res.arrayBuffer());
  return decryptAesEcb(encrypted, key);
}

async function saveMediaToFile(buf: Buffer, ext: string, subdir: string): Promise<string> {
  const dir = path.join(MEDIA_DIR, subdir);
  fs.mkdirSync(dir, { recursive: true });
  const name = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`;
  const filePath = path.join(dir, name);
  await fsP.writeFile(filePath, buf);
  return filePath;
}

// ── CDN Upload ───────────────────────────────────────────────────────────────

const UPLOAD_MEDIA_TYPE = { IMAGE: 1, VIDEO: 2, FILE: 3, VOICE: 4 } as const;

interface GetUploadUrlResp { upload_param?: string; thumb_upload_param?: string; }

async function getUploadUrl(params: {
  baseUrl: string; token?: string; filekey: string; media_type: number;
  to_user_id: string; rawsize: number; rawfilemd5: string; filesize: number; aeskey: string;
}): Promise<GetUploadUrlResp> {
  const raw = await apiFetch({
    baseUrl: params.baseUrl, endpoint: "ilink/bot/getuploadurl",
    body: JSON.stringify({
      filekey: params.filekey, media_type: params.media_type, to_user_id: params.to_user_id,
      rawsize: params.rawsize, rawfilemd5: params.rawfilemd5, filesize: params.filesize,
      no_need_thumb: true, aeskey: params.aeskey, base_info: { channel_version: CHANNEL_VERSION },
    }),
    token: params.token, timeoutMs: 15_000,
  });
  return JSON.parse(raw) as GetUploadUrlResp;
}

function buildCdnUploadUrl(uploadParam: string, filekey: string): string {
  return `${CDN_BASE_URL}/upload?encrypted_query_param=${encodeURIComponent(uploadParam)}&filekey=${encodeURIComponent(filekey)}`;
}

async function uploadBufferToCdn(buf: Buffer, uploadParam: string, filekey: string, aeskey: Buffer): Promise<string> {
  const ciphertext = encryptAesEcb(buf, aeskey);
  const cdnUrl = buildCdnUploadUrl(uploadParam, filekey);
  const maxRetries = 3;
  let lastErr: Error | null = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const res = await fetch(cdnUrl, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: ciphertext,
      });
      // Consume body before checking headers (matches cc-connect behavior)
      await res.arrayBuffer();
      if (res.status >= 400 && res.status < 500) {
        const errMsg = res.headers.get("x-error-message") ?? `status ${res.status}`;
        throw new Error(`CDN upload client error ${res.status}: ${errMsg}`);
      }
      if (!res.ok) {
        const errMsg = res.headers.get("x-error-message") ?? `status ${res.status}`;
        lastErr = new Error(`CDN upload server error: ${errMsg}`);
        log(`CDN upload attempt ${attempt}/${maxRetries} failed: ${lastErr.message}`);
        if (attempt < maxRetries) { await new Promise(r => setTimeout(r, 1000)); continue; }
        throw lastErr;
      }
      const downloadParam = res.headers.get("x-encrypted-param");
      if (!downloadParam) {
        lastErr = new Error("CDN response missing x-encrypted-param");
        log(`CDN upload attempt ${attempt}/${maxRetries}: missing header`);
        if (attempt < maxRetries) { await new Promise(r => setTimeout(r, 1000)); continue; }
        throw lastErr;
      }
      return downloadParam;
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("CDN upload client error")) throw err;
      lastErr = err instanceof Error ? err : new Error(String(err));
      log(`CDN upload attempt ${attempt}/${maxRetries} error: ${lastErr.message}`);
      if (attempt < maxRetries) { await new Promise(r => setTimeout(r, 1000)); continue; }
    }
  }
  throw lastErr ?? new Error(`CDN upload failed after ${maxRetries} attempts`);
}

type UploadedFileInfo = {
  filekey: string; downloadEncryptedQueryParam: string;
  aeskey: string; fileSize: number; fileSizeCiphertext: number;
};

async function uploadMediaFile(filePath: string, toUserId: string, baseUrl: string, token: string, mediaType: number): Promise<UploadedFileInfo> {
  const plaintext = await fsP.readFile(filePath);
  const rawsize = plaintext.length;
  const rawfilemd5 = crypto.createHash("md5").update(plaintext).digest("hex");
  const filesize = aesEcbPaddedSize(rawsize);
  const filekey = crypto.randomBytes(16).toString("hex");
  const aeskey = crypto.randomBytes(16);

  log(`getUploadUrl: filekey=${filekey} media_type=${mediaType} rawsize=${rawsize} filesize=${filesize}`);
  const resp = await getUploadUrl({
    baseUrl, token, filekey, media_type: mediaType, to_user_id: toUserId,
    rawsize, rawfilemd5, filesize, aeskey: aeskey.toString("hex"),
  });
  log(`getUploadUrl 响应: upload_param=${resp.upload_param ? "有" : "无"}`);
  if (!resp.upload_param) throw new Error("getUploadUrl returned no upload_param");

  const downloadEncryptedQueryParam = await uploadBufferToCdn(plaintext, resp.upload_param, filekey, aeskey);
  return { filekey, downloadEncryptedQueryParam, aeskey: aeskey.toString("hex"), fileSize: rawsize, fileSizeCiphertext: filesize };
}

// ── Send media messages ──────────────────────────────────────────────────────

const MSG_TYPE_BOT = 2;
const MSG_STATE_FINISH = 2;
const MSG_ITEM_TEXT = 1;
const MSG_ITEM_IMAGE = 2;
const MSG_ITEM_FILE = 4;
const MSG_ITEM_VIDEO = 5;

async function sendMediaMessage(baseUrl: string, token: string, to: string, text: string, filePath: string, contextToken: string): Promise<string> {
  const mime = getMimeFromFilename(filePath);
  let mediaType: number;
  if (mime.startsWith("image/")) mediaType = UPLOAD_MEDIA_TYPE.IMAGE;
  else if (mime.startsWith("video/")) mediaType = UPLOAD_MEDIA_TYPE.VIDEO;
  else mediaType = UPLOAD_MEDIA_TYPE.FILE;

  log(`上传媒体: ${filePath} (${mime}) type=${mediaType}`);
  const uploaded = await uploadMediaFile(filePath, to, baseUrl, token, mediaType);
  log(`上传成功: filekey=${uploaded.filekey} size=${uploaded.fileSize}`);

  // aeskey is a 32-char hex string; base64-encode the hex string directly (matches official SDK)
  const aesKeyBase64 = Buffer.from(uploaded.aeskey).toString("base64");
  const mediaRef = { encrypt_query_param: uploaded.downloadEncryptedQueryParam, aes_key: aesKeyBase64, encrypt_type: 1 };

  let mediaItem: any;
  if (mime.startsWith("image/")) {
    mediaItem = { type: MSG_ITEM_IMAGE, image_item: { media: mediaRef, mid_size: uploaded.fileSizeCiphertext } };
  } else if (mime.startsWith("video/")) {
    mediaItem = { type: MSG_ITEM_VIDEO, video_item: { media: mediaRef, video_size: uploaded.fileSizeCiphertext } };
  } else {
    mediaItem = { type: MSG_ITEM_FILE, file_item: { media: mediaRef, file_name: path.basename(filePath), len: String(uploaded.fileSize) } };
  }

  // Send each item as a separate request (official SDK sends one item per call)
  let lastClientId = "";
  const itemsToSend: any[] = [];
  if (text) itemsToSend.push({ type: MSG_ITEM_TEXT, text_item: { text } });
  itemsToSend.push(mediaItem);

  for (const item of itemsToSend) {
    lastClientId = generateClientId();
    const payload = {
      msg: { from_user_id: "", to_user_id: to, client_id: lastClientId, message_type: MSG_TYPE_BOT, message_state: MSG_STATE_FINISH, item_list: [item], context_token: contextToken },
      base_info: { channel_version: CHANNEL_VERSION },
    };
    log(`发送媒体消息: to=${to} item_type=${item.type} aes_key_len=${aesKeyBase64.length}`);
    const resp = await apiFetch({
      baseUrl, endpoint: "ilink/bot/sendmessage",
      body: JSON.stringify(payload),
      token, timeoutMs: 30_000,
    });
    log(`发送媒体响应: ${resp}`);
  }
  return lastClientId;
}

// ── QR Login ─────────────────────────────────────────────────────────────────

interface QRCodeResponse { qrcode: string; qrcode_img_content: string; }
interface QRStatusResponse { status: "wait" | "scaned" | "confirmed" | "expired"; bot_token?: string; ilink_bot_id?: string; baseurl?: string; ilink_user_id?: string; }

async function fetchQRCode(baseUrl: string): Promise<QRCodeResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const res = await fetch(`${base}ilink/bot/get_bot_qrcode?bot_type=${BOT_TYPE}`);
  if (!res.ok) throw new Error(`QR fetch failed: ${res.status}`);
  return (await res.json()) as QRCodeResponse;
}

async function pollQRStatus(baseUrl: string, qrcode: string): Promise<QRStatusResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 35_000);
  try {
    const res = await fetch(`${base}ilink/bot/get_qrcode_status?qrcode=${encodeURIComponent(qrcode)}`, { headers: { "iLink-App-ClientVersion": "1" }, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`QR status failed: ${res.status}`);
    return (await res.json()) as QRStatusResponse;
  } catch (err) { clearTimeout(timer); if (err instanceof Error && err.name === "AbortError") return { status: "wait" }; throw err; }
}

async function doQRLogin(baseUrl: string): Promise<AccountData | null> {
  log("正在获取微信登录二维码...");
  const qrResp = await fetchQRCode(baseUrl);
  log("\n请使用微信扫描以下二维码：\n");
  try {
    const qrterm = await import("qrcode-terminal");
    await new Promise<void>((resolve) => { qrterm.default.generate(qrResp.qrcode_img_content, { small: true }, (qr: string) => { process.stderr.write(qr + "\n"); resolve(); }); });
  } catch { log(`二维码链接: ${qrResp.qrcode_img_content}`); }
  log("等待扫码...");
  const deadline = Date.now() + 480_000;
  let scannedPrinted = false;
  while (Date.now() < deadline) {
    const status = await pollQRStatus(baseUrl, qrResp.qrcode);
    switch (status.status) {
      case "wait": break;
      case "scaned": if (!scannedPrinted) { log("已扫码，请在微信中确认..."); scannedPrinted = true; } break;
      case "expired": log("二维码已过期"); return null;
      case "confirmed": {
        if (!status.ilink_bot_id || !status.bot_token) { logError("登录未返回 bot 信息"); return null; }
        const account: AccountData = { token: status.bot_token, baseUrl: status.baseurl || baseUrl, accountId: status.ilink_bot_id, userId: status.ilink_user_id, savedAt: new Date().toISOString() };
        saveCredentials(account);
        log("微信连接成功！");
        return account;
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  log("登录超时");
  return null;
}

// ── WeChat Message Types ─────────────────────────────────────────────────────

interface CDNMedia { encrypt_query_param?: string; aes_key?: string; encrypt_type?: number; }
interface ImageItem { media?: CDNMedia; aeskey?: string; mid_size?: number; }
interface VoiceItem { media?: CDNMedia; text?: string; encode_type?: number; }
interface FileItem { media?: CDNMedia; file_name?: string; len?: string; }
interface VideoItem { media?: CDNMedia; video_size?: number; }
interface RefMessage { message_item?: MessageItem; title?: string; }
interface TextItemType { text?: string; }

interface MessageItem {
  type?: number;
  text_item?: TextItemType;
  image_item?: ImageItem;
  voice_item?: VoiceItem;
  file_item?: FileItem;
  video_item?: VideoItem;
  ref_msg?: RefMessage;
}

interface WeixinMessage {
  from_user_id?: string; to_user_id?: string; client_id?: string;
  session_id?: string; message_type?: number; message_state?: number;
  item_list?: MessageItem[]; context_token?: string; create_time_ms?: number;
}

interface GetUpdatesResp {
  ret?: number; errcode?: number; errmsg?: string;
  msgs?: WeixinMessage[]; get_updates_buf?: string; longpolling_timeout_ms?: number;
}

const MSG_TYPE_USER = 1;
const MSG_ITEM_VOICE = 3;

// ── Inbound message processing ───────────────────────────────────────────────

function extractTextFromMessage(msg: WeixinMessage): string {
  if (!msg.item_list?.length) return "";
  for (const item of msg.item_list) {
    if (item.type === MSG_ITEM_TEXT && item.text_item?.text) {
      const text = item.text_item.text;
      const ref = item.ref_msg;
      if (!ref) return text;
      const parts: string[] = [];
      if (ref.title) parts.push(ref.title);
      if (!parts.length) return text;
      return `[引用: ${parts.join(" | ")}]\n${text}`;
    }
    if (item.type === MSG_ITEM_VOICE && item.voice_item?.text) {
      return item.voice_item.text;
    }
  }
  return "";
}

/** Download media from inbound message items. Returns { text, mediaPath, mediaType }. */
async function processInboundMedia(msg: WeixinMessage): Promise<{ text: string; mediaPath?: string; mediaType?: string }> {
  const text = extractTextFromMessage(msg);
  if (!msg.item_list?.length) return { text };

  for (const item of msg.item_list) {
    // Image
    if (item.type === MSG_ITEM_IMAGE && item.image_item?.media?.encrypt_query_param) {
      const img = item.image_item;
      const aesKeyBase64 = img.aeskey
        ? Buffer.from(img.aeskey, "hex").toString("base64")
        : img.media?.aes_key;
      if (aesKeyBase64 && img.media?.encrypt_query_param) {
        try {
          const buf = await downloadAndDecrypt(img.media.encrypt_query_param, aesKeyBase64);
          const filePath = await saveMediaToFile(buf, ".jpg", "inbound");
          log(`图片已保存: ${filePath} (${buf.length} bytes)`);
          return { text: text || "[图片]", mediaPath: filePath, mediaType: "image" };
        } catch (err) { logError(`图片下载失败: ${err}`); }
      }
      return { text: text || "[图片-无法下载]" };
    }

    // Voice (keep text transcription, skip raw audio download for simplicity)
    if (item.type === MSG_ITEM_VOICE) {
      const voiceText = item.voice_item?.text;
      if (voiceText) return { text: `[语音转文字] ${voiceText}` };
      return { text: text || "[语音消息]" };
    }

    // File
    if (item.type === MSG_ITEM_FILE && item.file_item?.media?.encrypt_query_param && item.file_item?.media?.aes_key) {
      const fileItem = item.file_item;
      try {
        const buf = await downloadAndDecrypt(fileItem.media!.encrypt_query_param!, fileItem.media!.aes_key!);
        const ext = path.extname(fileItem.file_name ?? ".bin") || ".bin";
        const filePath = await saveMediaToFile(buf, ext, "inbound");
        log(`文件已保存: ${filePath} name=${fileItem.file_name} (${buf.length} bytes)`);
        return { text: text || `[文件: ${fileItem.file_name ?? "unknown"}]`, mediaPath: filePath, mediaType: "file" };
      } catch (err) { logError(`文件下载失败: ${err}`); }
      return { text: text || `[文件: ${fileItem.file_name ?? "unknown"} - 下载失败]` };
    }

    // Video
    if (item.type === MSG_ITEM_VIDEO && item.video_item?.media?.encrypt_query_param && item.video_item?.media?.aes_key) {
      const videoItem = item.video_item;
      try {
        const buf = await downloadAndDecrypt(videoItem.media!.encrypt_query_param!, videoItem.media!.aes_key!);
        const filePath = await saveMediaToFile(buf, ".mp4", "inbound");
        log(`视频已保存: ${filePath} (${buf.length} bytes)`);
        return { text: text || "[视频]", mediaPath: filePath, mediaType: "video" };
      } catch (err) { logError(`视频下载失败: ${err}`); }
      return { text: text || "[视频-下载失败]" };
    }
  }

  return { text };
}

// ── Context Token & Typing Ticket Cache ──────────────────────────────────────

const contextTokenCache = new Map<string, string>();
function cacheContextToken(userId: string, token: string): void { contextTokenCache.set(userId, token); }
function getCachedContextToken(userId: string): string | undefined { return contextTokenCache.get(userId); }

const typingTicketCache = new Map<string, string>();

async function fetchAndCacheTypingTicket(baseUrl: string, token: string, userId: string, contextToken: string): Promise<string | undefined> {
  try {
    const raw = await apiFetch({
      baseUrl, endpoint: "ilink/bot/getconfig",
      body: JSON.stringify({ ilink_user_id: userId, context_token: contextToken, base_info: { channel_version: CHANNEL_VERSION } }),
      token, timeoutMs: 10_000,
    });
    const resp = JSON.parse(raw) as { typing_ticket?: string };
    if (resp.typing_ticket) {
      typingTicketCache.set(userId, resp.typing_ticket);
      return resp.typing_ticket;
    }
  } catch (err) { log(`getConfig failed for ${userId}: ${err}`); }
  return typingTicketCache.get(userId);
}

async function sendTypingIndicator(baseUrl: string, token: string, userId: string, status: 1 | 2 = 1): Promise<void> {
  const ticket = typingTicketCache.get(userId);
  if (!ticket) return;
  try {
    await apiFetch({
      baseUrl, endpoint: "ilink/bot/sendtyping",
      body: JSON.stringify({ ilink_user_id: userId, typing_ticket: ticket, status, base_info: { channel_version: CHANNEL_VERSION } }),
      token, timeoutMs: 5_000,
    });
  } catch { /* best-effort, ignore */ }
}

// ── Typing keepalive ─────────────────────────────────────────────────────────

const TYPING_KEEPALIVE_MS = 4_000;
const typingTimers = new Map<string, ReturnType<typeof setInterval>>();

function startTypingKeepalive(baseUrl: string, token: string, userId: string): void {
  stopTypingKeepalive(userId);
  sendTypingIndicator(baseUrl, token, userId).catch(() => {});
  const timer = setInterval(() => {
    sendTypingIndicator(baseUrl, token, userId).catch(() => {});
  }, TYPING_KEEPALIVE_MS);
  typingTimers.set(userId, timer);
}

function stopTypingKeepalive(userId: string): void {
  const timer = typingTimers.get(userId);
  if (timer) { clearInterval(timer); typingTimers.delete(userId); }
}

// ── Text splitting for long replies ──────────────────────────────────────────

const MAX_CHUNK_LENGTH = 2000;
const SPLIT_DELAY_MS = 800;

function splitTextIntoChunks(text: string): string[] {
  if (text.length <= MAX_CHUNK_LENGTH) return [text];
  const chunks: string[] = [];
  // Try splitting by double newline (paragraphs), then single newline, then by length
  const paragraphs = text.split(/\n\n+/);
  let current = "";
  for (const para of paragraphs) {
    if (current && (current.length + para.length + 2) > MAX_CHUNK_LENGTH) {
      chunks.push(current.trim());
      current = para;
    } else {
      current = current ? `${current}\n\n${para}` : para;
    }
    // If a single paragraph is too long, split by lines
    if (current.length > MAX_CHUNK_LENGTH) {
      const lines = current.split(/\n/);
      current = "";
      for (const line of lines) {
        if (current && (current.length + line.length + 1) > MAX_CHUNK_LENGTH) {
          chunks.push(current.trim());
          current = line;
        } else {
          current = current ? `${current}\n${line}` : line;
        }
        // Hard split if single line exceeds limit
        while (current.length > MAX_CHUNK_LENGTH) {
          chunks.push(current.slice(0, MAX_CHUNK_LENGTH));
          current = current.slice(MAX_CHUNK_LENGTH);
        }
      }
    }
  }
  if (current.trim()) chunks.push(current.trim());
  return chunks;
}

// ── getUpdates / sendTextMessage ─────────────────────────────────────────────

async function getUpdates(baseUrl: string, token: string, getUpdatesBuf: string): Promise<GetUpdatesResp> {
  try {
    const raw = await apiFetch({
      baseUrl, endpoint: "ilink/bot/getupdates",
      body: JSON.stringify({ get_updates_buf: getUpdatesBuf, base_info: { channel_version: CHANNEL_VERSION } }),
      token, timeoutMs: LONG_POLL_TIMEOUT_MS,
    });
    return JSON.parse(raw) as GetUpdatesResp;
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") return { ret: 0, msgs: [], get_updates_buf: getUpdatesBuf };
    throw err;
  }
}

function generateClientId(): string {
  return `claude-code-wechat:${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

const MSG_STATE_GENERATING = 1;

async function sendTextMessage(baseUrl: string, token: string, to: string, text: string, contextToken: string, opts?: { clientId?: string; generating?: boolean }): Promise<string> {
  const clientId = opts?.clientId ?? generateClientId();
  const messageState = opts?.generating ? MSG_STATE_GENERATING : MSG_STATE_FINISH;
  await apiFetch({
    baseUrl, endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: { from_user_id: "", to_user_id: to, client_id: clientId, message_type: MSG_TYPE_BOT, message_state: messageState, item_list: [{ type: MSG_ITEM_TEXT, text_item: { text } }], context_token: contextToken },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token, timeoutMs: 15_000,
  });
  return clientId;
}

// ── MCP Channel Server ──────────────────────────────────────────────────────

const mcp = new Server(
  { name: CHANNEL_NAME, version: CHANNEL_VERSION },
  {
    capabilities: {
      experimental: { "claude/channel": {} },
      tools: {},
    },
    instructions: [
      `Messages from WeChat users arrive as <channel source="wechat" sender="..." sender_id="..." media_type="..." media_path="...">`,
      "Reply using the wechat_reply tool. You MUST pass the sender_id from the inbound tag.",
      "To send an image, file, or video, use the wechat_send_file tool with an absolute file path.",
      "When media_path is present in the inbound tag, the file has been downloaded locally — you can Read it.",
      "Messages are from real WeChat users via the WeChat ClawBot interface.",
      "Respond naturally in Chinese unless the user writes in another language.",
      "Keep replies concise. Strip markdown formatting (WeChat doesn't render it).",
      "",
      "INTERACTION PATTERN for complex requests:",
      "1. When a request requires tool calls, FIRST call wechat_thinking with a short status (e.g. '正在阅读文件...'). This shows a status message and starts a typing indicator.",
      "2. Perform the tool calls.",
      "3. Call wechat_reply to send the final answer. The thinking message stays as a separate status record.",
      "NOTE: The WeChat ilink bot API does not support in-place message updates. Thinking and reply are separate messages.",
    ].join("\n"),
  },
);

let activeAccount: AccountData | null = null;

// Tools
mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "wechat_thinking",
      description: "Send a 'thinking/processing' status message and start a typing indicator. Use before tool calls so the user sees progress.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: { type: "string", description: "The sender_id (xxx@im.wechat)" },
          text: { type: "string", description: "Short status text, e.g. '正在阅读文件...' or '正在检索文献...'" },
        },
        required: ["sender_id", "text"],
      },
    },
    {
      name: "wechat_reply",
      description: "Send the final text reply. Long messages are automatically split into multiple parts.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: { type: "string", description: "The sender_id from the inbound <channel> tag (xxx@im.wechat)" },
          text: { type: "string", description: "Plain-text message to send (no markdown)" },
        },
        required: ["sender_id", "text"],
      },
    },
    {
      name: "wechat_send_file",
      description: "Send an image, file, or video to the WeChat user. Use absolute file path.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: { type: "string", description: "The sender_id (xxx@im.wechat)" },
          file_path: { type: "string", description: "Absolute path to the local file to send" },
          caption: { type: "string", description: "Optional text caption to include with the file" },
        },
        required: ["sender_id", "file_path"],
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (!activeAccount) {
    return { content: [{ type: "text" as const, text: "error: not logged in" }] };
  }

  if (req.params.name === "wechat_thinking") {
    const { sender_id, text } = req.params.arguments as { sender_id: string; text: string };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) return { content: [{ type: "text" as const, text: `error: no context_token for ${sender_id}` }] };
    try {
      // Always send as a new FINISH message — iLink client_id is idempotency key, reuse is silently dropped
      const clientId = await sendTextMessage(activeAccount.baseUrl, activeAccount.token, sender_id, text, contextToken);
      // Start keepalive: sends "正在输入..." every 4s until wechat_reply stops it
      startTypingKeepalive(activeAccount.baseUrl, activeAccount.token, sender_id);
      return { content: [{ type: "text" as const, text: `reply_id:${clientId}` }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `thinking send failed: ${String(err)}` }] };
    }
  }

  if (req.params.name === "wechat_reply") {
    const { sender_id, text } = req.params.arguments as { sender_id: string; text: string };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) return { content: [{ type: "text" as const, text: `error: no context_token for ${sender_id}` }] };
    try {
      // Stop typing keepalive and cancel indicator before sending final reply
      stopTypingKeepalive(sender_id);
      sendTypingIndicator(activeAccount.baseUrl, activeAccount.token, sender_id, 2).catch(() => {});
      const chunks = splitTextIntoChunks(text);
      for (let i = 0; i < chunks.length; i++) {
        if (i > 0) await new Promise((r) => setTimeout(r, SPLIT_DELAY_MS));
        await sendTextMessage(activeAccount.baseUrl, activeAccount.token, sender_id, chunks[i], contextToken);
      }
      return { content: [{ type: "text" as const, text: chunks.length > 1 ? `sent (${chunks.length} parts)` : "sent" }] };
    } catch (err) {
      stopTypingKeepalive(sender_id);
      return { content: [{ type: "text" as const, text: `send failed: ${String(err)}` }] };
    }
  }

  if (req.params.name === "wechat_send_file") {
    const { sender_id, file_path, caption } = req.params.arguments as { sender_id: string; file_path: string; caption?: string };
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) return { content: [{ type: "text" as const, text: `error: no context_token for ${sender_id}` }] };
    if (!fs.existsSync(file_path)) return { content: [{ type: "text" as const, text: `error: file not found: ${file_path}` }] };
    try {
      await sendMediaMessage(activeAccount.baseUrl, activeAccount.token, sender_id, caption ?? "", file_path, contextToken);
      return { content: [{ type: "text" as const, text: `sent: ${path.basename(file_path)}` }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `send file failed: ${String(err)}` }] };
    }
  }

  throw new Error(`unknown tool: ${req.params.name}`);
});

// ── Long-poll loop ──────────────────────────────────────────────────────────

async function startPolling(account: AccountData): Promise<never> {
  const { baseUrl, token } = account;
  let getUpdatesBuf = "";
  let consecutiveFailures = 0;

  const syncBufFile = path.join(CREDENTIALS_DIR, "sync_buf.txt");
  try {
    if (fs.existsSync(syncBufFile)) {
      getUpdatesBuf = fs.readFileSync(syncBufFile, "utf-8");
      log(`恢复上次同步状态 (${getUpdatesBuf.length} bytes)`);
    }
  } catch { /* ignore */ }

  log("开始监听微信消息...");

  while (true) {
    try {
      const resp = await getUpdates(baseUrl, token, getUpdatesBuf);

      const isError = (resp.ret !== undefined && resp.ret !== 0) || (resp.errcode !== undefined && resp.errcode !== 0);
      if (isError) {
        consecutiveFailures++;
        logError(`getUpdates 失败: ret=${resp.ret} errcode=${resp.errcode} errmsg=${resp.errmsg ?? ""}`);
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
          consecutiveFailures = 0;
          await new Promise((r) => setTimeout(r, BACKOFF_DELAY_MS));
        } else {
          await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        }
        continue;
      }

      consecutiveFailures = 0;
      if (resp.get_updates_buf) {
        getUpdatesBuf = resp.get_updates_buf;
        try { fs.writeFileSync(syncBufFile, getUpdatesBuf, "utf-8"); } catch { /* ignore */ }
      }

      for (const msg of resp.msgs ?? []) {
        if (msg.message_type !== MSG_TYPE_USER) continue;

        const senderId = msg.from_user_id ?? "unknown";
        if (msg.context_token) cacheContextToken(senderId, msg.context_token);

        // Fetch typing ticket + send typing indicator (fire-and-forget)
        if (msg.context_token && senderId !== "unknown") {
          fetchAndCacheTypingTicket(baseUrl, token, senderId, msg.context_token)
            .then(() => sendTypingIndicator(baseUrl, token, senderId))
            .catch(() => { /* ignore */ });
        }

        // Process media + text
        const { text, mediaPath, mediaType } = await processInboundMedia(msg);
        if (!text && !mediaPath) continue;

        log(`收到消息: from=${senderId} text=${(text ?? "").slice(0, 50)} media=${mediaType ?? "none"}`);

        const meta: Record<string, string> = {
          sender: senderId.split("@")[0] || senderId,
          sender_id: senderId,
        };
        if (mediaType) meta.media_type = mediaType;
        if (mediaPath) meta.media_path = mediaPath;

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: text || `[${mediaType}]`, meta },
        });
      }
    } catch (err) {
      consecutiveFailures++;
      logError(`轮询异常: ${String(err)}`);
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        consecutiveFailures = 0;
        await new Promise((r) => setTimeout(r, BACKOFF_DELAY_MS));
      } else {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      }
    }
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  await mcp.connect(new StdioServerTransport());
  log("MCP 连接就绪");

  let account = loadCredentials();
  if (!account) {
    log("未找到凭据，启动微信扫码登录...");
    account = await doQRLogin(DEFAULT_BASE_URL);
    if (!account) { logError("登录失败"); process.exit(1); }
  } else {
    log(`使用已保存账号: ${account.accountId}`);
  }

  activeAccount = account;
  await startPolling(account);
}

main().catch((err) => { logError(`Fatal: ${String(err)}`); process.exit(1); });
