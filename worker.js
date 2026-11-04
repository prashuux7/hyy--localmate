async function createTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS businesses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      business_name TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      category TEXT NOT NULL,
      city TEXT NOT NULL,
      address TEXT NOT NULL,
      phone TEXT NOT NULL,
      whatsapp TEXT,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  return Uint8Array.from(
    atob(base64),
    character => character.charCodeAt(0)
  );
}

async function getSigningKey(password) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createSession(password) {
  const issuedAt = Date.now().toString();
  const key = await getSigningKey(password);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(issuedAt)
  );

  return issuedAt + "." + base64url(new Uint8Array(signature));
}

async function verifySession(request, password) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)lm_admin=([^;]+)/);

  if (!match) return false;

  try {
    const parts = match[1].split(".");
    if (parts.length !== 2) return false;

    const issuedAt = Number(parts[0]);

    if (!Number.isFinite(issuedAt)) return false;

    const age = Date.now() - issuedAt;

    if (age < 0 || age > 8 * 60 * 60 * 1000) {
      return false;
    }

    const key = await getSigningKey(password);

    return await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64url(parts[1]),
      new TextEncoder().encode(parts[0])
    );
  } catch {
    return false;
  }
}

function adminCookie(token) {
  return `lm_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=28800`;
}

function clearAdminCookie() {
  return "lm_admin=; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=0";
}

function sameOrigin(request, url) {
  return request.headers.get("Origin") === url.origin;
}

async function passwordMatches(input, expected) {
  const encoder = new TextEncoder();

  const a = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(input))
  );

  const b = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(expected))
  );

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (!env.DB) {
      return json({ error: "Database not connected" }, 500);
    }

    try {
      await createTables(env.DB);

      // PUBLIC: Approved businesses
      if (
        url.pathname === "/api/businesses" &&
        request.method === "GET"
      ) {
        const result = await env.DB.prepare(
          "SELECT * FROM businesses WHERE status = 'approved' ORDER BY id DESC"
        ).all();

        return json(result.results);
      }

      // PUBLIC: Business registration
      if (
        url.pathname === "/api/register" &&
        request.method === "POST"
      ) {
        const data = await request.json();

        const required = [
          "business_name", "owner_name", "category",
          "city", "address", "phone"
        ];

        for (const field of required) {
          if (!data[field] || !String(data[field]).trim()) {
            return json({ error: `Missing field: ${field}` }, 400);
          }
        }

        await env.DB.prepare(`
          INSERT INTO businesses
          (business_name, owner_name, category, city,
           address, phone, whatsapp, description)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          String(data.business_name).trim(),
          String(data.owner_name).trim(),
          String(data.category).trim(),
          String(data.city).trim(),
          String(data.address).trim(),
          String(data.phone).trim(),
          String(data.whatsapp || "").trim(),
          String(data.description || "").trim()
        ).run();

        return json({
          success: true,
          message: "Registration submitted for approval."
        }, 201);
      }

      // ADMIN: Login
      if (
        url.pathname === "/api/admin/login" &&
        request.method === "POST"
      ) {
        if (!sameOrigin(request, url)) {
          return json({ error: "Invalid request origin" }, 403);
        }

        if (!env.ADMIN_PASSWORD) {
          return json({ error: "Admin password not configured" }, 500);
        }

        const data = await request.json();

        if (
          typeof data.password !== "string" ||
          !(await passwordMatches(data.password, env.ADMIN_PASSWORD))
        ) {
          return json({ error: "Incorrect password" }, 401);
        }

        const token = await createSession(env.ADMIN_PASSWORD);

        return new Response(JSON.stringify({
          success: true,
          message: "Admin login successful"
        }), {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Set-Cookie": adminCookie(token)
          }
        });
      }

      // ADMIN: Logout
      if (
        url.pathname === "/api/admin/logout" &&
        request.method === "POST"
      ) {
        if (!sameOrigin(request, url)) {
          return json({ error: "Invalid request origin" }, 403);
        }

        return new Response(JSON.stringify({ success: true }), {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": clearAdminCookie()
          }
        });
      }

      // ADMIN: Protect all remaining admin routes
      if (url.pathname.startsWith("/api/admin/")) {
        if (!env.ADMIN_PASSWORD) {
          return json({ error: "Admin password not configured" }, 500);
        }

        if (!(await verifySession(request, env.ADMIN_PASSWORD))) {
          return json({ error: "Unauthorized" }, 401);
        }

        // ADMIN: View registrations
        if (
          url.pathname === "/api/admin/businesses" &&
          request.method === "GET"
        ) {
          const result = await env.DB.prepare(
            "SELECT * FROM businesses ORDER BY id DESC"
          ).all();

          return json(result.results);
        }

        // ADMIN: Approve or reject
        if (
          url.pathname === "/api/admin/decision" &&
          request.method === "POST"
        ) {
          if (!sameOrigin(request, url)) {
            return json({ error: "Invalid request origin" }, 403);
          }

          const data = await request.json();
          const id = Number(data.id);

          if (
            !Number.isInteger(id) ||
            id < 1 ||
            !["approved", "rejected"].includes(data.status)
          ) {
            return json({ error: "Invalid decision" }, 400);
          }

          const result = await env.DB.prepare(
            "UPDATE businesses SET status = ? WHERE id = ?"
          ).bind(data.status, id).run();

          if (!result.meta || result.meta.changes === 0) {
            return json({ error: "Business not found" }, 404);
          }

          return json({
            success: true,
            message: `Business ${data.status}.`
          });
        }
      }

      return json({ error: "API route not found" }, 404);

    } catch (error) {
      return json({ error: "Server error" }, 500);
    }
  }
};
