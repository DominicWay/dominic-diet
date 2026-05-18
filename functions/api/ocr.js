/**
 * Cloudflare Pages Function — 腾讯云 OCR 代理
 *
 * 用途：将前端发来的 base64 图片转发给腾讯云 GeneralAccurateOCR，
 *       API 密钥通过 Cloudflare 环境变量注入，不暴露给前端。
 *
 * 部署后访问路径：POST /api/ocr
 *
 * 环境变量（在 Cloudflare Dashboard → Pages → Settings → Environment Variables 中设置）：
 *   TENCENT_SECRET_ID  — 腾讯云 SecretId
 *   TENCENT_SECRET_KEY — 腾讯云 SecretKey
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  // ── CORS & 限流 ──
  const origin = request.headers.get('Origin') || '';
  const myOrigin = new URL(request.url).origin;
  const corsHeaders = {
    'Access-Control-Allow-Origin': origin === myOrigin ? origin : '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const SECRET_ID  = env.TENCENT_SECRET_ID;
  const SECRET_KEY = env.TENCENT_SECRET_KEY;

  if (!SECRET_ID || !SECRET_KEY) {
    return jsonResponse({ error: 'OCR 服务未配置，请在 Cloudflare Pages 环境变量中设置 TENCENT_SECRET_ID 和 TENCENT_SECRET_KEY' }, 500, corsHeaders);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: '请求格式错误' }, 400, corsHeaders);
  }

  const { image: imageBase64 } = body;
  if (!imageBase64 || typeof imageBase64 !== 'string') {
    return jsonResponse({ error: '缺少 image 字段（base64 编码的图片）' }, 400, corsHeaders);
  }

  try {
    const result = await callTencentOCR(SECRET_ID, SECRET_KEY, imageBase64);
    return jsonResponse(result, 200, corsHeaders);
  } catch (err) {
    console.error('OCR proxy error:', err);
    return jsonResponse({ error: 'OCR 调用失败: ' + err.message }, 500, corsHeaders);
  }
}

// ══════════════════════════════════════════════════
//  腾讯云 OCR API 调用（TC3-HMAC-SHA256 签名）
// ══════════════════════════════════════════════════
async function callTencentOCR(secretId, secretKey, imageBase64) {
  const service   = 'ocr';
  const host      = 'ocr.tencentcloudapi.com';
  const action    = 'GeneralAccurateOCR';
  const version   = '2018-11-19';
  const region    = 'ap-guangzhou';
  const timestamp = Math.floor(Date.now() / 1000);

  // 日期字符串 YYYYMMDD
  const dateStr = new Date(timestamp * 1000)
    .toISOString()
    .split('T')[0]
    .replace(/-/g, '');

  const payload = JSON.stringify({ ImageBase64: imageBase64 });

  // ── 1. 计算 Canonical Request 的哈希 ──
  const httpMethod      = 'POST';
  const canonicalUri     = '/';
  const canonicalQuery   = '';
  const contentType      = 'application/json; charset=utf-8';
  const canonicalHeaders = `content-type:${contentType}\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders    = 'content-type;host;x-tc-action';
  const hashedPayload    = await sha256Hex(payload);
  const canonicalRequest = `${httpMethod}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;

  // ── 2. 计算 String to Sign ──
  const credentialScope     = `${dateStr}/${service}/tc3_request`;
  const hashedCanonicalReq  = await sha256Hex(canonicalRequest);
  const stringToSign = `TC3-HMAC-SHA256\n${timestamp}\n${credentialScope}\n${hashedCanonicalReq}`;

  // ── 3. 计算签名密钥 ──
  const secretDate    = await hmacSha256(new TextEncoder().encode(`TC3${secretKey}`), dateStr);
  const secretService = await hmacSha256(secretDate, service);
  const secretSigning = await hmacSha256(secretService, 'tc3_request');
  const signature     = await hmacSha256Hex(secretSigning, stringToSign);

  // ── 4. 构建 Authorization ──
  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // ── 5. 发送请求 ──
  const response = await fetch(`https://${host}`, {
    method: 'POST',
    headers: {
      'Content-Type':   contentType,
      'Host':           host,
      'X-TC-Action':    action,
      'X-TC-Version':   version,
      'X-TC-Region':    region,
      'X-TC-Timestamp': String(timestamp),
      'Authorization':  authorization,
    },
    body: payload,
  });

  const result = await response.json();

  if (result.Response && result.Response.Error) {
    throw new Error(`${result.Response.Error.Code}: ${result.Response.Error.Message}`);
  }

  return result.Response;
}

// ══════════════════════════════════════════════════
//  加密工具函数（Web Crypto API）
// ══════════════════════════════════════════════════
async function sha256Hex(data) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return bufToHex(hash);
}

async function hmacSha256(key, data) {
  // key: Uint8Array, data: string → returns Uint8Array
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data)));
}

async function hmacSha256Hex(key, data) {
  return bufToHex(await hmacSha256(key, data));
}

function bufToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── JSON 响应工具 ──
function jsonResponse(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}
