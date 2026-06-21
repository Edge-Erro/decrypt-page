// ============================================================
// 完整 Worker：加密 + 解密，支持 CORS
// 加密端点 /encrypt （公开，无需鉴权）
// 解密端点 /decrypt （需要 X-API-Key 验证）
// 环境变量：ENCRYPTION_KEY（32位字符串）, API_KEY（解密用）
// ============================================================

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname;

        // ---------- 处理 CORS 预检请求 ----------
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
                },
            });
        }

        // 只允许 POST
        if (request.method !== "POST") {
            return new Response(JSON.stringify({ error: "Method not allowed" }), {
                status: 405,
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
            });
        }

        // ---------- 路由 ----------
        if (path === "/encrypt") {
            // 加密：任何人都可以调用，但只能得到密文
            return handleEncrypt(request, env);
        } else if (path === "/decrypt") {
            // 解密：必须提供正确的 API Key
            const apiKey = request.headers.get("X-API-Key");
            if (!apiKey || apiKey !== env.API_KEY) {
                return new Response(JSON.stringify({ error: "Unauthorized" }), {
                    status: 401,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            }
            return handleDecrypt(request, env);
        } else {
            return new Response(JSON.stringify({ error: "Not found" }), {
                status: 404,
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
            });
        }
    },
};

// ---------- 加密处理函数 ----------
async function handleEncrypt(request, env) {
    try {
        const body = await request.json();
        const text = body.text;
        if (!text) {
            return jsonResponse({ error: "Missing 'text' field" }, 400);
        }

        // 从环境变量获取加密密钥
        const encoder = new TextEncoder();
        const keyData = encoder.encode(env.ENCRYPTION_KEY);
        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );

        // 生成随机 IV（12字节）
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedText = encoder.encode(text);

        // 加密
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encodedText
        );

        // 将 IV 和密文拼接，然后转为 Base64
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        const base64 = btoa(String.fromCharCode(...combined));

        return jsonResponse({ success: true, encrypted: base64 }, 200);
    } catch (e) {
        return jsonResponse({ success: false, error: e.message }, 500);
    }
}

// ---------- 解密处理函数 ----------
async function handleDecrypt(request, env) {
    try {
        const body = await request.json();
        const encryptedBase64 = body.encrypted;
        if (!encryptedBase64) {
            return jsonResponse({ error: "Missing 'encrypted' field" }, 400);
        }

        // 从 Base64 还原为 Uint8Array
        const binary = atob(encryptedBase64);
        const combined = Uint8Array.from(binary, (c) => c.charCodeAt(0));

        // 分离 IV（前12字节）和密文
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        // 导入密钥
        const encoder = new TextEncoder();
        const keyData = encoder.encode(env.ENCRYPTION_KEY);
        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        // 解密
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            ciphertext
        );

        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decrypted);

        return jsonResponse({ success: true, decrypted: plaintext }, 200);
    } catch (e) {
        return jsonResponse({ success: false, error: e.message }, 500);
    }
}

// ---------- 辅助函数：返回 JSON 响应（带 CORS） ----------
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    });
}