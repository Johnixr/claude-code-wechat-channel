#!/usr/bin/env bun
/**
 * Claude Code WeChat Channel Plugin
 *
 * Bridges WeChat messages into a Claude Code session via the Channels MCP protocol.
 * Uses the official WeChat ClawBot ilink API (same as @tencent-weixin/openclaw-weixin).
 *
 * Flow:
 *   1. QR login via ilink/bot/get_bot_qrcode + get_qrcode_status
 *   2. Long-poll ilink/bot/getupdates for incoming WeChat messages
 *   3. Forward messages to Claude Code as <channel> events
 *   4. Expose a reply tool so Claude can send messages back via ilink/bot/sendmessage
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ────────────────────────────────────────────────────────────────────

const CHANNEL_NAME = "wechat";
const CHANNEL_VERSION = "0.1.0";
const DEFAULT_BASE_URL = "https://ilinkai.weixin.qq.com";
const BOT_TYPE = "3";
const CREDENTIALS_DIR = path.join(
  process.env.HOME || "~",
  ".claude",
  "channels",
  "wechat",
);
const CREDENTIALS_FILE = path.join(CREDENTIALS_DIR, "account.json");

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
  } catch {
    return null;
  }
}

function saveCredentials(data: AccountData): void {
  fs.mkdirSync(CREDENTIALS_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(data, null, 2), "utf-8");
  try {
    fs.chmodSync(CREDENTIALS_FILE, 0o600);
  } catch {
    // best-effort
  }
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
  if (body) {
    headers["Content-Length"] = String(Buffer.byteLength(body, "utf-8"));
  }
  if (token?.trim()) {
    headers.Authorization = `Bearer ${token.trim()}`;
  }
  return headers;
}

async function apiFetch(params: {
  baseUrl: string;
  endpoint: string;
  body: string;
  token?: string;
  timeoutMs: number;
}): Promise<string> {
  const base = params.baseUrl.endsWith("/")
    ? params.baseUrl
    : `${params.baseUrl}/`;
  const url = new URL(params.endpoint, base).toString();
  const headers = buildHeaders(params.token, params.body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: params.body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text}`);
    return text;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ── QR Login ─────────────────────────────────────────────────────────────────

interface QRCodeResponse {
  qrcode: string;
  qrcode_img_content: string;
}

interface QRStatusResponse {
  status: "wait" | "scaned" | "confirmed" | "expired";
  bot_token?: string;
  ilink_bot_id?: string;
  baseurl?: string;
  ilink_user_id?: string;
}

async function fetchQRCode(baseUrl: string): Promise<QRCodeResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const url = new URL(
    `ilink/bot/get_bot_qrcode?bot_type=${encodeURIComponent(BOT_TYPE)}`,
    base,
  );
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`QR fetch failed: ${res.status}`);
  return (await res.json()) as QRCodeResponse;
}

async function pollQRStatus(
  baseUrl: string,
  qrcode: string,
): Promise<QRStatusResponse> {
  const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const url = new URL(
    `ilink/bot/get_qrcode_status?qrcode=${encodeURIComponent(qrcode)}`,
    base,
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 35_000);
  try {
    const res = await fetch(url.toString(), {
      headers: { "iLink-App-ClientVersion": "1" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`QR status failed: ${res.status}`);
    return (await res.json()) as QRStatusResponse;
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return { status: "wait" };
    }
    throw err;
  }
}

async function doQRLogin(
  baseUrl: string,
): Promise<AccountData | null> {
  log("正在获取微信登录二维码...");
  const qrResp = await fetchQRCode(baseUrl);

  log("\n请使用微信扫描以下二维码：\n");
  try {
    const qrterm = await import("qrcode-terminal");
    await new Promise<void>((resolve) => {
      qrterm.default.generate(
        qrResp.qrcode_img_content,
        { small: true },
        (qr: string) => {
          process.stderr.write(qr + "\n");
          resolve();
        },
      );
    });
  } catch {
    log(`二维码链接: ${qrResp.qrcode_img_content}`);
  }

  log("等待扫码...");
  const deadline = Date.now() + 480_000;
  let scannedPrinted = false;

  while (Date.now() < deadline) {
    const status = await pollQRStatus(baseUrl, qrResp.qrcode);

    switch (status.status) {
      case "wait":
        break;
      case "scaned":
        if (!scannedPrinted) {
          log("👀 已扫码，请在微信中确认...");
          scannedPrinted = true;
        }
        break;
      case "expired":
        log("二维码已过期，请重新启动。");
        return null;
      case "confirmed": {
        if (!status.ilink_bot_id || !status.bot_token) {
          logError("登录确认但未返回 bot 信息");
          return null;
        }
        const account: AccountData = {
          token: status.bot_token,
          baseUrl: status.baseurl || baseUrl,
          accountId: status.ilink_bot_id,
          userId: status.ilink_user_id,
          savedAt: new Date().toISOString(),
        };
        saveCredentials(account);
        log("✅ 微信连接成功！");
        return account;
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }

  log("登录超时");
  return null;
}

// ── WeChat Message Types ─────────────────────────────────────────────────────

interface TextItem {
  text?: string;
}

interface RefMessage {
  message_item?: MessageItem;
  title?: string;
}

interface MediaField {
  encrypt_query_param?: string;
  aes_key?: string; // base64-encoded hex key
}

interface ImageItem {
  url?: string;
  aeskey?: string; // hex-encoded
  media?: MediaField;
  mid_size?: number;
  thumb_size?: number;
  thumb_height?: number;
  thumb_width?: number;
  hd_size?: number;
}

interface VideoItem {
  media?: MediaField;
  video_size?: number;
  play_length?: number;
  video_md5?: string;
  thumb_media?: MediaField;
  thumb_size?: number;
  thumb_height?: number;
  thumb_width?: number;
}

interface VoiceItemFull {
  text?: string;
  media?: MediaField;
  playtime?: number;
}

interface FileItem {
  media?: MediaField;
  file_name?: string;
  md5?: string;
  len?: number;
}

interface MessageItem {
  type?: number;
  text_item?: TextItem;
  voice_item?: VoiceItemFull;
  image_item?: ImageItem;
  video_item?: VideoItem;
  file_item?: FileItem;
  ref_msg?: RefMessage;
}

interface WeixinMessage {
  from_user_id?: string;
  to_user_id?: string;
  client_id?: string;
  session_id?: string;
  message_type?: number;
  message_state?: number;
  item_list?: MessageItem[];
  context_token?: string;
  create_time_ms?: number;
}

interface GetUpdatesResp {
  ret?: number;
  errcode?: number;
  errmsg?: string;
  msgs?: WeixinMessage[];
  get_updates_buf?: string;
  longpolling_timeout_ms?: number;
}

// Message type constants
const MSG_TYPE_USER = 1;
const MSG_ITEM_TEXT = 1;
const MSG_ITEM_IMAGE = 2;
const MSG_ITEM_VOICE = 3;
const MSG_ITEM_FILE = 4;
const MSG_ITEM_VIDEO = 5;
const MSG_TYPE_BOT = 2;
const MSG_STATE_FINISH = 2;

// Media download config
const MEDIA_DIR = path.join(CREDENTIALS_DIR, "media");
const CDN_BASE_URL = "https://novac2c.cdn.weixin.qq.com/c2c/download";

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

// ── Media Download & Decrypt ─────────────────────────────────────────────────

async function downloadAndDecryptMedia(
  encryptQueryParam: string,
  aesKeyInput: string,
  aesKeyEncoding: "hex" | "base64",
  ext: string,
): Promise<string> {
  fs.mkdirSync(MEDIA_DIR, { recursive: true });

  const url = `${CDN_BASE_URL}?encrypted_query_param=${encodeURIComponent(encryptQueryParam)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Media download failed: HTTP ${res.status}`);
  const encrypted = Buffer.from(await res.arrayBuffer());

  // Normalize AES key to 16-byte Buffer
  let key: Buffer;
  if (aesKeyEncoding === "base64") {
    // base64 encodes the hex string, so decode base64 first to get hex, then hex to bytes
    const hexKey = Buffer.from(aesKeyInput, "base64").toString("utf-8");
    key = Buffer.from(hexKey, "hex");
  } else {
    key = Buffer.from(aesKeyInput, "hex");
  }

  const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  const filename = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}.${ext}`;
  const filepath = path.join(MEDIA_DIR, filename);
  fs.writeFileSync(filepath, decrypted);

  return filepath;
}

interface MediaResult {
  mediaType: "image" | "video" | "voice" | "file";
  filePath: string;
  metadata: Record<string, string | number>;
}

async function extractMediaFromItem(item: MessageItem): Promise<MediaResult | null> {
  if (item.type === MSG_ITEM_IMAGE && item.image_item) {
    const img = item.image_item;
    const eqp = img.media?.encrypt_query_param;
    const key = img.media?.aes_key || img.aeskey;
    const encoding: "hex" | "base64" = img.media?.aes_key ? "base64" : "hex";
    if (!eqp || !key) return null;
    const fp = await downloadAndDecryptMedia(eqp, key, encoding, "jpg");
    return { mediaType: "image", filePath: fp, metadata: {} };
  }

  if (item.type === MSG_ITEM_VIDEO && item.video_item) {
    const vid = item.video_item;
    const eqp = vid.media?.encrypt_query_param;
    const key = vid.media?.aes_key;
    if (!eqp || !key) return null;
    const fp = await downloadAndDecryptMedia(eqp, key, "base64", "mp4");
    return {
      mediaType: "video",
      filePath: fp,
      metadata: {
        duration: vid.play_length ?? 0,
        size: vid.video_size ?? 0,
      },
    };
  }

  if (item.type === MSG_ITEM_VOICE && item.voice_item?.media) {
    const voice = item.voice_item;
    const eqp = voice.media?.encrypt_query_param;
    const key = voice.media?.aes_key;
    if (!eqp || !key) return null;
    const fp = await downloadAndDecryptMedia(eqp, key, "base64", "silk");
    return {
      mediaType: "voice",
      filePath: fp,
      metadata: {
        transcription: voice.text ?? "",
      },
    };
  }

  if (item.type === MSG_ITEM_FILE && item.file_item) {
    const file = item.file_item;
    const eqp = file.media?.encrypt_query_param;
    const key = file.media?.aes_key;
    if (!eqp || !key) return null;
    const ext = file.file_name?.split(".").pop() ?? "bin";
    const fp = await downloadAndDecryptMedia(eqp, key, "base64", ext);
    return {
      mediaType: "file",
      filePath: fp,
      metadata: {
        fileName: file.file_name ?? "unknown",
      },
    };
  }

  return null;
}

// ── Context Token Cache ──────────────────────────────────────────────────────

const contextTokenCache = new Map<string, string>();

function cacheContextToken(userId: string, token: string): void {
  contextTokenCache.set(userId, token);
}

function getCachedContextToken(userId: string): string | undefined {
  return contextTokenCache.get(userId);
}

// ── getUpdates / sendMessage ─────────────────────────────────────────────────

async function getUpdates(
  baseUrl: string,
  token: string,
  getUpdatesBuf: string,
): Promise<GetUpdatesResp> {
  try {
    const raw = await apiFetch({
      baseUrl,
      endpoint: "ilink/bot/getupdates",
      body: JSON.stringify({
        get_updates_buf: getUpdatesBuf,
        base_info: { channel_version: CHANNEL_VERSION },
      }),
      token,
      timeoutMs: LONG_POLL_TIMEOUT_MS,
    });
    return JSON.parse(raw) as GetUpdatesResp;
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      return { ret: 0, msgs: [], get_updates_buf: getUpdatesBuf };
    }
    throw err;
  }
}

function generateClientId(): string {
  return `claude-code-wechat:${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

async function sendTextMessage(
  baseUrl: string,
  token: string,
  to: string,
  text: string,
  contextToken: string,
): Promise<string> {
  const clientId = generateClientId();
  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: clientId,
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{ type: MSG_ITEM_TEXT, text_item: { text } }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 15_000,
  });
  return clientId;
}

// ── Media Upload & Send ──────────────────────────────────────────────────────

const CDN_UPLOAD_URL = "https://novac2c.cdn.weixin.qq.com/c2c/upload";

interface UploadUrlResponse {
  ret?: number;
  errcode?: number;
  errmsg?: string;
  encrypted_query_param?: string;
}

async function getUploadUrl(
  baseUrl: string,
  token: string,
  params: {
    filekey: string;
    media_type: number; // 1=image, 2=video, 3=file, 4=voice
    to_user_id: string;
    rawsize: number;
    rawfilemd5: string;
    filesize: number;
    aeskey: string;
    no_need_thumb?: boolean;
  },
): Promise<string> {
  const raw = await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/getuploadurl",
    body: JSON.stringify({
      ...params,
      no_need_thumb: params.no_need_thumb ?? true,
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 15_000,
  });
  const resp = JSON.parse(raw) as UploadUrlResponse;
  if (!resp.encrypted_query_param) {
    throw new Error(`getuploadurl failed: ${raw}`);
  }
  return resp.encrypted_query_param;
}

function md5Hash(data: Buffer): string {
  return crypto.createHash("md5").update(data).digest("hex");
}

function aesEncrypt(data: Buffer, key: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

async function uploadAndSendMedia(
  baseUrl: string,
  token: string,
  to: string,
  contextToken: string,
  filePath: string,
  mediaType: "image" | "video" | "file",
): Promise<string> {
  const rawData = fs.readFileSync(filePath);
  const rawMd5 = md5Hash(rawData);

  // Generate AES key and filekey
  const aesKeyBytes = crypto.randomBytes(16);
  const aesKeyHex = aesKeyBytes.toString("hex");
  const filekey = crypto.randomBytes(16).toString("hex");

  // Encrypt file
  const encrypted = aesEncrypt(rawData, aesKeyBytes);

  // Map media type to API constant
  const mediaTypeMap = { image: 1, video: 2, file: 3 } as const;
  const apiMediaType = mediaTypeMap[mediaType];

  // Get upload URL
  const uploadEqp = await getUploadUrl(baseUrl, token, {
    filekey,
    media_type: apiMediaType,
    to_user_id: to,
    rawsize: rawData.length,
    rawfilemd5: rawMd5,
    filesize: encrypted.length,
    aeskey: aesKeyHex,
  });

  // Upload encrypted file to CDN
  const uploadUrl = `${CDN_UPLOAD_URL}?encrypted_query_param=${encodeURIComponent(uploadEqp)}&filekey=${encodeURIComponent(filekey)}`;
  const uploadRes = await fetch(uploadUrl, {
    method: "POST",
    body: encrypted,
    headers: { "Content-Type": "application/octet-stream" },
  });
  if (!uploadRes.ok) {
    throw new Error(`CDN upload failed: HTTP ${uploadRes.status}`);
  }

  // Get download param from response header
  const downloadEqp = uploadRes.headers.get("x-encrypted-param");
  if (!downloadEqp) {
    throw new Error("CDN upload did not return x-encrypted-param header");
  }

  // Build media item
  const aesKeyBase64 = Buffer.from(aesKeyHex, "utf-8").toString("base64");
  const mediaField: MediaField = {
    encrypt_query_param: downloadEqp,
    aes_key: aesKeyBase64,
  };

  let itemType: number;
  let itemPayload: Record<string, unknown>;

  if (mediaType === "image") {
    itemType = MSG_ITEM_IMAGE;
    itemPayload = {
      image_item: { media: mediaField, aeskey: aesKeyHex },
    };
  } else if (mediaType === "video") {
    itemType = MSG_ITEM_VIDEO;
    itemPayload = {
      video_item: {
        media: mediaField,
        video_size: rawData.length,
        video_md5: rawMd5,
      },
    };
  } else {
    itemType = MSG_ITEM_FILE;
    itemPayload = {
      file_item: {
        media: mediaField,
        file_name: path.basename(filePath),
        md5: rawMd5,
        len: rawData.length,
      },
    };
  }

  const clientId = generateClientId();
  await apiFetch({
    baseUrl,
    endpoint: "ilink/bot/sendmessage",
    body: JSON.stringify({
      msg: {
        from_user_id: "",
        to_user_id: to,
        client_id: clientId,
        message_type: MSG_TYPE_BOT,
        message_state: MSG_STATE_FINISH,
        item_list: [{ type: itemType, ...itemPayload }],
        context_token: contextToken,
      },
      base_info: { channel_version: CHANNEL_VERSION },
    }),
    token,
    timeoutMs: 30_000,
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
      `Messages from WeChat users arrive as <channel source="wechat" sender="..." sender_id="...">`,
      "Reply using the wechat_reply tool. You MUST pass the sender_id from the inbound tag.",
      "Messages are from real WeChat users via the WeChat ClawBot interface.",
      "Respond naturally in Chinese unless the user writes in another language.",
      "Keep replies concise — WeChat is a chat app, not an essay platform.",
      "Strip markdown formatting (WeChat doesn't render it). Use plain text.",
      "Media messages arrive as [image: /path], [video: /path], [voice: /path], [file: /path]. Use the Read tool to view images.",
      "To send media back, use wechat_send_media with a local file path and media_type (image/video/file).",
    ].join("\n"),
  },
);

// Tool: reply to WeChat
mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "wechat_reply",
      description: "Send a text reply back to the WeChat user",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description:
              "The sender_id from the inbound <channel> tag (xxx@im.wechat format)",
          },
          text: {
            type: "string",
            description: "The plain-text message to send (no markdown)",
          },
        },
        required: ["sender_id", "text"],
      },
    },
    {
      name: "wechat_send_media",
      description:
        "Send an image, video, or file to the WeChat user. Provide an absolute local file path.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender_id: {
            type: "string",
            description:
              "The sender_id from the inbound <channel> tag (xxx@im.wechat format)",
          },
          file_path: {
            type: "string",
            description:
              "Absolute path to the local file to send",
          },
          media_type: {
            type: "string",
            enum: ["image", "video", "file"],
            description:
              "Type of media: image (jpg/png/gif), video (mp4), or file (any)",
          },
        },
        required: ["sender_id", "file_path", "media_type"],
      },
    },
  ],
}));

let activeAccount: AccountData | null = null;

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "wechat_reply") {
    const { sender_id, text } = req.params.arguments as {
      sender_id: string;
      text: string;
    };
    if (!activeAccount) {
      return {
        content: [{ type: "text" as const, text: "error: not logged in" }],
      };
    }
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [
          {
            type: "text" as const,
            text: `error: no context_token for ${sender_id}. The user may need to send a message first.`,
          },
        ],
      };
    }
    try {
      await sendTextMessage(
        activeAccount.baseUrl,
        activeAccount.token,
        sender_id,
        text,
        contextToken,
      );
      return { content: [{ type: "text" as const, text: "sent" }] };
    } catch (err) {
      return {
        content: [
          { type: "text" as const, text: `send failed: ${String(err)}` },
        ],
      };
    }
  }
  if (req.params.name === "wechat_send_media") {
    const { sender_id, file_path: filePath, media_type } = req.params.arguments as {
      sender_id: string;
      file_path: string;
      media_type: "image" | "video" | "file";
    };
    if (!activeAccount) {
      return {
        content: [{ type: "text" as const, text: "error: not logged in" }],
      };
    }
    const contextToken = getCachedContextToken(sender_id);
    if (!contextToken) {
      return {
        content: [
          {
            type: "text" as const,
            text: `error: no context_token for ${sender_id}. The user may need to send a message first.`,
          },
        ],
      };
    }
    if (!fs.existsSync(filePath)) {
      return {
        content: [
          { type: "text" as const, text: `error: file not found: ${filePath}` },
        ],
      };
    }
    try {
      await uploadAndSendMedia(
        activeAccount.baseUrl,
        activeAccount.token,
        sender_id,
        contextToken,
        filePath,
        media_type,
      );
      return { content: [{ type: "text" as const, text: "media sent" }] };
    } catch (err) {
      return {
        content: [
          { type: "text" as const, text: `send media failed: ${String(err)}` },
        ],
      };
    }
  }

  throw new Error(`unknown tool: ${req.params.name}`);
});

// ── Long-poll loop ──────────────────────────────────────────────────────────

async function startPolling(account: AccountData): Promise<never> {
  const { baseUrl, token } = account;
  let getUpdatesBuf = "";
  let consecutiveFailures = 0;

  // Load cached sync buf if available
  const syncBufFile = path.join(CREDENTIALS_DIR, "sync_buf.txt");
  try {
    if (fs.existsSync(syncBufFile)) {
      getUpdatesBuf = fs.readFileSync(syncBufFile, "utf-8");
      log(`恢复上次同步状态 (${getUpdatesBuf.length} bytes)`);
    }
  } catch {
    // ignore
  }

  log("开始监听微信消息...");

  while (true) {
    try {
      const resp = await getUpdates(baseUrl, token, getUpdatesBuf);

      // Handle API errors
      const isError =
        (resp.ret !== undefined && resp.ret !== 0) ||
        (resp.errcode !== undefined && resp.errcode !== 0);
      if (isError) {
        consecutiveFailures++;
        logError(
          `getUpdates 失败: ret=${resp.ret} errcode=${resp.errcode} errmsg=${resp.errmsg ?? ""}`,
        );
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
          logError(
            `连续失败 ${MAX_CONSECUTIVE_FAILURES} 次，等待 ${BACKOFF_DELAY_MS / 1000}s`,
          );
          consecutiveFailures = 0;
          await new Promise((r) => setTimeout(r, BACKOFF_DELAY_MS));
        } else {
          await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        }
        continue;
      }

      consecutiveFailures = 0;

      // Save sync buf
      if (resp.get_updates_buf) {
        getUpdatesBuf = resp.get_updates_buf;
        try {
          fs.writeFileSync(syncBufFile, getUpdatesBuf, "utf-8");
        } catch {
          // ignore
        }
      }

      // Process messages
      for (const msg of resp.msgs ?? []) {
        // Only process user messages (not bot messages)
        if (msg.message_type !== MSG_TYPE_USER) continue;

        const senderId = msg.from_user_id ?? "unknown";

        // Cache context token for reply
        if (msg.context_token) {
          cacheContextToken(senderId, msg.context_token);
        }

        const text = extractTextFromMessage(msg);

        // Extract media from all items
        const mediaResults: MediaResult[] = [];
        for (const item of msg.item_list ?? []) {
          try {
            const media = await extractMediaFromItem(item);
            if (media) mediaResults.push(media);
          } catch (err) {
            logError(`媒体下载失败: ${String(err)}`);
          }
        }

        // Skip if nothing extracted
        if (!text && mediaResults.length === 0) continue;

        // Build content string
        const parts: string[] = [];
        if (text) parts.push(text);
        for (const m of mediaResults) {
          const metaEntries = Object.entries(m.metadata)
            .filter(([, v]) => v !== "" && v !== 0)
            .map(([k, v]) => `${k}=${v}`);
          const metaStr = metaEntries.length ? ` (${metaEntries.join(", ")})` : "";
          parts.push(`[${m.mediaType}: ${m.filePath}${metaStr}]`);
        }

        const content = parts.join("\n");
        log(`收到消息: from=${senderId} content=${content.slice(0, 80)}...`);

        // Push to Claude Code session
        await mcp.notification({
          method: "notifications/claude/channel",
          params: {
            content,
            meta: {
              sender: senderId.split("@")[0] || senderId,
              sender_id: senderId,
            },
          },
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
  // Connect MCP transport first (Claude Code expects stdio handshake)
  await mcp.connect(new StdioServerTransport());
  log("MCP 连接就绪");

  // Check for saved credentials
  let account = loadCredentials();

  if (!account) {
    log("未找到已保存的凭据，启动微信扫码登录...");
    account = await doQRLogin(DEFAULT_BASE_URL);
    if (!account) {
      logError("登录失败，退出。");
      process.exit(1);
    }
  } else {
    log(`使用已保存账号: ${account.accountId}`);
  }

  activeAccount = account;

  // Start long-poll (runs forever)
  await startPolling(account);
}

main().catch((err) => {
  logError(`Fatal: ${String(err)}`);
  process.exit(1);
});
