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
    headers: { "Content-Type": "application/json" }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      if (!env.DB) {
        return json({ error: "Database not connected" }, 500);
      }

      try {
        await createTables(env.DB);

        if (url.pathname === "/api/businesses" && request.method === "GET") {
          const result = await env.DB.prepare(
            "SELECT * FROM businesses WHERE status = 'approved' ORDER BY id DESC"
          ).all();

          return json(result.results);
        }

        if (url.pathname === "/api/register" && request.method === "POST") {
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
            data.business_name,
            data.owner_name,
            data.category,
            data.city,
            data.address,
            data.phone,
            data.whatsapp || "",
            data.description || ""
          ).run();

          return json({
            success: true,
            message: "Registration submitted for approval."
          }, 201);
        }

        return json({ error: "API route not found" }, 404);
      } catch (error) {
        return json({ error: "Server error" }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
