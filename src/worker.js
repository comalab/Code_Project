const COOKIE_NAME = "mito_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = decodeURIComponent(url.pathname);

    try {
      if (path === "/api/login" && request.method === "POST") {
        return handleLogin(request, env);
      }
      if (path === "/api/logout" && request.method === "POST") {
        return handleLogout();
      }
      if (path.startsWith("/api/admin/")) {
        return handleAdminApi(request, env, path);
      }
      if (path.startsWith("/uploads/") && request.method === "GET") {
        return handleUploadGet(env, path);
      }
      if (path === "/" || path === "/index.html" || path === "/미토직업전문학교.html") {
        return renderFeaturedPage(request, env, path);
      }
      if (path === "/추천과정.html") {
        return renderListPage(request, env);
      }
    } catch (err) {
      return new Response("Internal Server Error: " + err.message, { status: 500 });
    }

    return env.ASSETS.fetch(request);
  },
};

// ---------- auth ----------

function base64UrlEncode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeToString(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return atob(padded);
}

async function hmacSign(env, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return base64UrlEncode(new Uint8Array(sig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function createSessionCookie(env) {
  const exp = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ exp })));
  const sig = await hmacSign(env, payloadB64);
  const value = `${payloadB64}.${sig}`;
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? match[1] : null;
}

async function isAuthenticated(request, env) {
  const value = getCookie(request, COOKIE_NAME);
  if (!value) return false;
  const [payloadB64, sig] = value.split(".");
  if (!payloadB64 || !sig) return false;
  const expectedSig = await hmacSign(env, payloadB64);
  if (!timingSafeEqual(expectedSig, sig)) return false;
  try {
    const payload = JSON.parse(base64UrlDecodeToString(payloadB64));
    return typeof payload.exp === "number" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.username || !body.password) {
    return json({ error: "invalid_request" }, 400);
  }
  const usernameOk = timingSafeEqual(String(body.username), env.ADMIN_USERNAME);
  const passwordOk = timingSafeEqual(String(body.password), env.ADMIN_PASSWORD);
  if (!usernameOk || !passwordOk) {
    return json({ error: "invalid_credentials" }, 401);
  }
  const cookie = await createSessionCookie(env);
  return json({ ok: true }, 200, { "Set-Cookie": cookie });
}

function handleLogout() {
  const cookie = `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
  return json({ ok: true }, 200, { "Set-Cookie": cookie });
}

// ---------- admin api ----------

async function handleAdminApi(request, env, path) {
  if (!(await isAuthenticated(request, env))) {
    return json({ error: "unauthorized" }, 401);
  }
  const method = request.method;

  if (path === "/api/admin/courses" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM courses ORDER BY sort_order").all();
    return json(results.map(parseCourseRow));
  }

  if (path === "/api/admin/courses" && method === "POST") {
    const body = await request.json().catch(() => null);
    if (!body) return json({ error: "invalid_request" }, 400);
    const row = validateCourseInput(body);
    const result = await env.DB.prepare(
      `INSERT INTO courses (badge,title,category,satisfaction,start_date,end_date,capacity,applied,price_original,price_tiers,work24_url,image_key,featured,sort_order,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`
    )
      .bind(
        row.badge,
        row.title,
        row.category,
        row.satisfaction,
        row.start_date,
        row.end_date,
        row.capacity,
        row.applied,
        row.price_original,
        JSON.stringify(row.price_tiers),
        row.work24_url,
        row.image_key,
        row.featured,
        row.sort_order
      )
      .run();
    return json({ ok: true, id: result.meta.last_row_id });
  }

  if (path === "/api/admin/courses/reorder" && method === "POST") {
    const body = await request.json().catch(() => null);
    if (!Array.isArray(body)) return json({ error: "invalid_request" }, 400);
    const stmts = body.map((item) =>
      env.DB.prepare("UPDATE courses SET sort_order=?, featured=? WHERE id=?").bind(
        Number(item.sort_order) || 0,
        item.featured ? 1 : 0,
        Number(item.id)
      )
    );
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true });
  }

  if (path === "/api/admin/upload" && method === "POST") {
    return handleUpload(request, env);
  }

  const idMatch = path.match(/^\/api\/admin\/courses\/(\d+)$/);
  if (idMatch && (method === "PUT" || method === "PATCH")) {
    const id = Number(idMatch[1]);
    const body = await request.json().catch(() => null);
    if (!body) return json({ error: "invalid_request" }, 400);
    const row = validateCourseInput(body);
    await env.DB.prepare(
      `UPDATE courses SET badge=?, title=?, category=?, satisfaction=?, start_date=?, end_date=?, capacity=?, applied=?, price_original=?, price_tiers=?, work24_url=?, image_key=?, featured=?, sort_order=?, updated_at=datetime('now') WHERE id=?`
    )
      .bind(
        row.badge,
        row.title,
        row.category,
        row.satisfaction,
        row.start_date,
        row.end_date,
        row.capacity,
        row.applied,
        row.price_original,
        JSON.stringify(row.price_tiers),
        row.work24_url,
        row.image_key,
        row.featured,
        row.sort_order,
        id
      )
      .run();
    return json({ ok: true });
  }

  if (idMatch && method === "DELETE") {
    const id = Number(idMatch[1]);
    await env.DB.prepare("DELETE FROM courses WHERE id=?").bind(id).run();
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}

function validateCourseInput(body) {
  const allowedTierTypes = ["hero", "free", "discount", "general"];
  return {
    badge: String(body.badge || "").slice(0, 50),
    title: String(body.title || "").slice(0, 200),
    category: String(body.category || "").slice(0, 50),
    satisfaction: body.satisfaction ? String(body.satisfaction).slice(0, 20) : null,
    start_date: String(body.start_date || ""),
    end_date: String(body.end_date || ""),
    capacity: body.capacity !== null && body.capacity !== "" && body.capacity !== undefined ? Number(body.capacity) : null,
    applied: body.applied !== null && body.applied !== "" && body.applied !== undefined ? Number(body.applied) : null,
    price_original: Number(body.price_original) || 0,
    price_tiers: Array.isArray(body.price_tiers)
      ? body.price_tiers.map((t) => ({
          type: allowedTierTypes.includes(t.type) ? t.type : "general",
          text: String(t.text || "").slice(0, 100),
        }))
      : [],
    work24_url: String(body.work24_url || ""),
    image_key: body.image_key ? String(body.image_key) : null,
    featured: body.featured ? 1 : 0,
    sort_order: Number.isFinite(Number(body.sort_order)) ? Number(body.sort_order) : 0,
  };
}

function parseCourseRow(row) {
  let tiers = [];
  try {
    tiers = JSON.parse(row.price_tiers || "[]");
  } catch {
    tiers = [];
  }
  return { ...row, price_tiers: tiers, featured: !!row.featured };
}

// ---------- image upload ----------

async function handleUpload(request, env) {
  const form = await request.formData().catch(() => null);
  if (!form) return json({ error: "invalid_request" }, 400);
  const file = form.get("image");
  if (!file || typeof file === "string") return json({ error: "no_file" }, 400);

  const allowed = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
  const ext = allowed[file.type];
  if (!ext) return json({ error: "unsupported_type" }, 400);
  if (file.size > 8 * 1024 * 1024) return json({ error: "file_too_large" }, 400);

  const key = `uploads/${crypto.randomUUID()}.${ext}`;
  await env.IMAGES.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
  return json({ ok: true, key });
}

async function handleUploadGet(env, path) {
  const key = path.replace(/^\//, "");
  const obj = await env.IMAGES.get(key);
  if (!obj) return new Response("Not Found", { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("Cache-Control", "public, max-age=31536000, immutable");
  return new Response(obj.body, { headers });
}

// ---------- public page rendering ----------

async function renderFeaturedPage(request, env, path) {
  const assetPath = path === "/" ? "/index.html" : path;
  const assetReq = new Request(new URL(assetPath, request.url), request);
  const res = await env.ASSETS.fetch(assetReq);
  if (!res.ok) return res;

  try {
    const { results } = await env.DB.prepare("SELECT * FROM courses WHERE featured=1 ORDER BY sort_order LIMIT 5").all();
    const courses = results.map(parseCourseRow);
    const cardsHtml = courses.map(renderFeaturedCard).join("\n");

    let html = await res.text();
    html = replaceBetweenMarkers(html, "COURSES:FEATURED", cardsHtml);

    const headers = new Headers(res.headers);
    headers.delete("content-length");
    return new Response(html, { status: res.status, headers });
  } catch {
    // DB unavailable: fall back to the static file's own hardcoded content between the markers.
    return res;
  }
}

async function renderListPage(request, env) {
  const assetReq = new Request(new URL("/추천과정.html", request.url), request);
  const res = await env.ASSETS.fetch(assetReq);
  if (!res.ok) return res;

  try {
    const { results } = await env.DB.prepare("SELECT * FROM courses ORDER BY sort_order").all();
    const courses = results.map(parseCourseRow);
    const cardsHtml = courses.map(renderListCard).join("\n");

    let html = await res.text();
    html = replaceBetweenMarkers(html, "COURSES:LIST", cardsHtml);

    const headers = new Headers(res.headers);
    headers.delete("content-length");
    return new Response(html, { status: res.status, headers });
  } catch {
    return res;
  }
}

function replaceBetweenMarkers(html, name, replacement) {
  const start = `<!-- ${name}:START -->`;
  const end = `<!-- ${name}:END -->`;
  const startIdx = html.indexOf(start);
  const endIdx = html.indexOf(end);
  if (startIdx === -1 || endIdx === -1) return html;
  return html.slice(0, startIdx + start.length) + "\n" + replacement + "\n" + html.slice(endIdx);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function formatWon(n) {
  return `${Number(n || 0).toLocaleString("ko-KR")}원`;
}

function formatCapacity(capacity, applied) {
  if (capacity === null || capacity === undefined) return "";
  return applied !== null && applied !== undefined ? `정원 ${capacity}명 · 신청 ${applied}명` : `정원 ${capacity}명`;
}

function tierColorClassTailwind(type) {
  switch (type) {
    case "free":
      return "text-emerald-600";
    case "general":
      return "text-on-surface";
    default:
      return "text-[#d84315]";
  }
}

function renderFeaturedTiers(course) {
  const lines = [`<p class="text-[11px] text-on-surface-variant line-through">${escapeHtml(formatWon(course.price_original))}</p>`];
  course.price_tiers.forEach((tier) => {
    if (tier.type === "hero") {
      lines.push(`<p class="font-price-display text-lg text-[#d84315] mt-0.5">${escapeHtml(tier.text)}</p>`);
    } else {
      lines.push(`<p class="text-[11px] font-bold ${tierColorClassTailwind(tier.type)} mt-0.5">${escapeHtml(tier.text)}</p>`);
    }
  });
  return lines.join("\n");
}

function renderFeaturedCard(course) {
  const imgSrc = course.image_key ? escapeHtml(course.image_key) : "images/main.png";
  return `<a class="min-w-[240px] bg-white rounded-2xl border border-outline-variant/30 shadow-sm snap-start overflow-hidden group block" href="${escapeHtml(course.work24_url)}" target="_blank" rel="noopener">
<div class="h-32 relative">
<img src="${imgSrc}" alt="${escapeHtml(course.title)}" class="w-full h-full object-cover">
<div class="absolute top-3 left-3 bg-white/90 backdrop-blur-sm px-2 py-1 rounded text-[10px] font-bold text-[#d84315]">${escapeHtml(course.category)}</div>
</div>
<div class="p-4">
<h3 class="font-label-lg text-base text-on-surface font-bold mb-1 line-clamp-2">${escapeHtml(course.title)}</h3>
<div class="flex gap-1 mb-3">
<span class="text-[10px] bg-surface-container px-2 py-1 rounded text-on-surface-variant">국비지원</span>
<span class="text-[10px] bg-surface-container px-2 py-1 rounded text-on-surface-variant">${escapeHtml(course.badge)}</span>
</div>
<div class="flex items-end justify-between">
<div class="leading-tight">
${renderFeaturedTiers(course)}
</div>
<span class="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-[#d84315] group-hover:bg-[#d84315] group-hover:text-white transition-colors shrink-0">
<span class="material-symbols-outlined text-sm">arrow_forward</span>
</span>
</div>
</div>
</a>`;
}

function tierClassList(type) {
  switch (type) {
    case "free":
      return "tier-free";
    case "discount":
      return "tier-discount";
    case "hero":
      return "tier-hero";
    default:
      return "tier-general";
  }
}

function renderListCard(course) {
  const metaCapacity = formatCapacity(course.capacity, course.applied);
  const categoryText = course.satisfaction ? `${course.category} · 만족도 ${course.satisfaction}` : course.category;
  const tiersHtml = course.price_tiers
    .map((t) => `<span class="${tierClassList(t.type)}">${escapeHtml(t.text)}</span>`)
    .join("\n          ");

  return `<a class="course" href="${escapeHtml(course.work24_url)}" target="_blank" rel="noopener">
      <div class="course-top">
        <span class="badge">${escapeHtml(course.badge)}</span>
      </div>
      <h2 class="course-title">${escapeHtml(course.title)}</h2>
      <div class="course-meta">
        <span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v4M16 3v4"/></svg>${escapeHtml(course.start_date)} ~ ${escapeHtml(course.end_date)}</span>
        <span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c1.2-4 4-6 7-6s5.8 2 7 6"/></svg>${escapeHtml(metaCapacity)}</span>
        <span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16v12H7l-3 3V4Z"/></svg>${escapeHtml(categoryText)}</span>
      </div>
      <div class="course-bottom">
        <div class="price-tiers">
          <span class="price-original">${escapeHtml(formatWon(course.price_original))}</span>
          ${tiersHtml}
        </div>
        <span class="go">과정 상세보기<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></span>
      </div>
    </a>`;
}

// ---------- helpers ----------

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}
