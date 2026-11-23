"use strict";
// 每日任务：所有数据都是 AES-GCM 加密的，密钥由密码经 PBKDF2 派生。
// 任务由电脑每天推送（data/日期.json.enc）；勾选和补充写在 state/日期.json.enc，通过 GitHub API 同步。

const LS = { key: "quest.key", token: "quest.token", cache: "quest.cache." };
const TYPE = {
  main: { name: "主线", cls: "t-main" },
  daily: { name: "日常", cls: "t-daily" },
  train: { name: "修炼", cls: "t-train" },
  side: { name: "支线", cls: "t-side" },
  rest: { name: "作息", cls: "t-rest" },
};
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

let meta, key, index, day, dayData, state, stateSha = null, saveTimer = null, openId = null;

// ---------- 存储（浏览器存储可能不可用，全部 try/catch） ----------
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

// ---------- 加解密 ----------
const b64 = {
  to(buf) { let s = ""; const b = new Uint8Array(buf); for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); },
  from(str) { const s = atob(str.trim()); const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; },
};
async function deriveKey(secret) {
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64.from(meta.salt), iterations: meta.iter }, base, 256);
  return new Uint8Array(bits);
}
const importKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
async function decryptBytes(text) {
  const all = b64.from(text);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: all.subarray(0, 12) }, key, all.subarray(12)));
}
async function encryptText(str) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(str)));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return b64.to(out);
}
const decryptJSON = async (text) => JSON.parse(dec.decode(await decryptBytes(text)));

// ---------- 读取 ----------
async function fetchText(path) {
  const r = await fetch(`${path}?t=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.text();
}
const token = () => store.get(LS.token);
async function gh(path, opts = {}) {
  return fetch(`https://api.github.com/repos/${meta.owner}/${meta.repo}/contents/${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", ...(opts.headers || {}) },
  });
}

async function loadState(d) {
  const empty = { date: d, done: {}, notes: {}, journal: "", updated: "" };
  let remote = null;
  stateSha = null;
  if (token()) {
    try {
      const r = await gh(`state/${d}.json.enc?ref=${meta.branch}`);
      if (r.ok) {
        const j = await r.json();
        stateSha = j.sha;
        remote = await decryptJSON(atob(j.content.replace(/\n/g, "")));
        setSync("ok", "已同步");
      } else if (r.status === 404) setSync("ok", "已连接 GitHub");
      else setSync("bad", `同步失败（${r.status}），先存在本机`);
    } catch { setSync("bad", "离线，先存在本机"); }
  } else {
    try { remote = await decryptJSON(await fetchText(`state/${d}.json.enc`)); } catch {}
    setSync("bad", "未设置令牌，勾选只存在本机");
  }
  let local = null;
  try { const c = store.get(LS.cache + d); if (c) local = JSON.parse(c); } catch {}
  const pick = [remote, local].filter(Boolean).sort((a, b) => (b.updated || "").localeCompare(a.updated || ""))[0];
  return { ...empty, ...(pick || {}) };
}

// ---------- 保存 ----------
function scheduleSave() {
  state.updated = new Date().toISOString();
  store.set(LS.cache + day, JSON.stringify(state));
  if (!token()) { setSync("bad", "未设置令牌，勾选只存在本机"); return; }
  setSync("busy", "保存中…");
  clearTimeout(saveTimer);
  saveTimer = setTimeout(pushState, 1200);
}
async function pushState(retry = true) {
  try {
    const body = { message: `state ${day}`, branch: meta.branch, content: btoa(await encryptText(JSON.stringify(state))) };
    if (stateSha) body.sha = stateSha;
    const r = await gh(`state/${day}.json.enc`, { method: "PUT", body: JSON.stringify(body) });
    if (r.ok) { stateSha = (await r.json()).content.sha; setSync("ok", "已同步"); return; }
    if ((r.status === 409 || r.status === 422) && retry) {
      const g = await gh(`state/${day}.json.enc?ref=${meta.branch}`);
      stateSha = g.ok ? (await g.json()).sha : null;
      return pushState(false);
    }
    setSync("bad", r.status === 401 ? "令牌无效，请在设置里重新填写" : `同步失败（${r.status}），已存在本机`);
  } catch { setSync("bad", "离线，已存在本机，联网后再改一次就会同步"); }
}
function setSync(kind, text) { $("sync-dot").className = `dot ${kind}`; $("sync-text").textContent = text; }

// ---------- 小型 Markdown ----------
function esc(s) { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/(^|[\s（(])(https?:\/\/[^\s<）)]+)/g, '$1<a href="$2" target="_blank" rel="noopener">$2</a>');
}
function md(src) {
  const lines = (src || "").replace(/\r/g, "").split("\n");
  let html = "", list = null, para = [], table = [];
  const flushPara = () => { if (para.length) { html += `<p>${para.map(inline).join("<br>")}</p>`; para = []; } };
  const flushList = () => { if (list) { html += `</${list}>`; list = null; } };
  const flushTable = () => {
    if (!table.length) return;
    const rows = table.filter((r) => !/^\|[\s:|-]+\|$/.test(r));
    html += "<table>" + rows.map((r, i) => "<tr>" + r.slice(1, -1).split("|").map((c) => `<${i ? "td" : "th"}>${inline(c.trim())}</${i ? "td" : "th"}>`).join("") + "</tr>").join("") + "</table>";
    table = [];
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (/^\|.*\|$/.test(line.trim())) { flushPara(); flushList(); table.push(line.trim()); continue; } else flushTable();
    let m;
    if (!line.trim()) { flushPara(); flushList(); }
    else if ((m = line.match(/^#{1,4}\s+(.*)/))) { flushPara(); flushList(); html += `<h3>${inline(m[1])}</h3>`; }
    else if ((m = line.match(/^>\s?(.*)/))) { flushPara(); flushList(); html += `<blockquote>${inline(m[1])}</blockquote>`; }
    else if ((m = line.match(/^\s*[-*]\s+(.*)/))) { flushPara(); if (list !== "ul") { flushList(); html += "<ul>"; list = "ul"; } html += `<li>${inline(m[1])}</li>`; }
    else if ((m = line.match(/^\s*\d+\.\s+(.*)/))) { flushPara(); if (list !== "ol") { flushList(); html += "<ol>"; list = "ol"; } html += `<li>${inline(m[1])}</li>`; }
    else if (/^-{3,}$/.test(line.trim())) { flushPara(); flushList(); html += "<hr>"; }
    else { flushList(); para.push(line); }
  }
  flushPara(); flushList(); flushTable();
  return html;
}

// ---------- 渲染 ----------
const todayStr = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
function dayLabel(d) {
  const diff = Math.round((new Date(d) - new Date(todayStr())) / 86400000);
  const wd = "日一二三四五六"[new Date(d + "T00:00:00").getDay()];
  const rel = diff === 0 ? "今天" : diff === 1 ? "明天" : diff === -1 ? "昨天" : diff > 0 ? `${diff} 天后` : `${-diff} 天前`;
  return `${d} · 周${wd} · ${rel}`;
}
function render() {
  $("day-label").textContent = dayLabel(day);
  $("day-title").textContent = dayData.title || "今日任务";
  const motto = $("motto"); motto.classList.toggle("hidden", !dayData.motto); motto.textContent = dayData.motto || "";
  const banner = $("banner"); const t = todayStr();
  if (day < t) { banner.textContent = `今天（${t}）的任务还没推送，下面是 ${day} 的任务，还可以继续勾选。`; banner.classList.remove("hidden"); }
  else if (day > t) { banner.textContent = "这是提前推送的任务。"; banner.classList.remove("hidden"); }
  else banner.classList.add("hidden");

  const qs = dayData.quests || [];
  const doneN = qs.filter((q) => state.done[q.id]).length;
  const dayAll = qs.reduce((s, q) => s + (q.coins || 0), 0);
  const dayGot = qs.filter((q) => state.done[q.id]).reduce((s, q) => s + (q.coins || 0), 0);
  const cap = index.cap || 3000;
  const monthGot = ((index.months || {})[day.slice(0, 7)] || 0) + dayGot;
  $("coin-month").textContent = `本月 🪙 ${monthGot} / ${cap}`;
  $("coin-day").textContent = `今日 ${dayGot} / ${dayAll} · 完成 ${doneN}/${qs.length}`;
  $("xp-bar").style.width = `${Math.min(100, (monthGot / cap) * 100)}%`;

  const ul = $("quest-list"); ul.innerHTML = "";
  for (const q of qs) {
    const tp = TYPE[q.type] || TYPE.daily;
    const li = document.createElement("li");
    li.className = `quest ${tp.cls}${state.done[q.id] ? " done" : ""}`;
    li.innerHTML = `
      <button class="check-btn" aria-label="完成">${state.done[q.id] ? "✓" : ""}</button>
      <div class="q-main">
        <div class="q-meta"><span class="q-type">${tp.name}</span>${q.time ? `<span>推荐 ${esc(q.time)}</span>` : ""}${state.notes[q.id] ? '<span class="q-note">✎ 有补充</span>' : ""}</div>
        <div class="q-title">${esc(q.title)}</div>
        ${q.summary ? `<div class="q-sum">${esc(q.summary)}</div>` : ""}
      </div>
      <div class="q-xp">+${q.coins || 0} 🪙</div>`;
    li.querySelector(".check-btn").addEventListener("click", (e) => { e.stopPropagation(); toggle(q.id); });
    li.addEventListener("click", () => openQuest(q.id));
    ul.appendChild(li);
  }
  $("journal").value = state.journal || "";
}
function toggle(id) {
  if (state.done[id]) delete state.done[id]; else state.done[id] = new Date().toISOString();
  scheduleSave(); render();
  if (openId === id) fillSheet(id);
}
function fillSheet(id) {
  const q = dayData.quests.find((x) => x.id === id); const tp = TYPE[q.type] || TYPE.daily;
  const tag = $("d-type"); tag.textContent = tp.name; tag.className = `tag ${tp.cls}`;
  $("d-time").textContent = [q.time && `推荐 ${q.time}`, `+${q.coins || 0} 金币`].filter(Boolean).join(" · ");
  $("d-title").textContent = q.title;
  const links = (q.links || []).map((l) => `- [${l.label}](${l.url})`).join("\n");
  $("d-body").innerHTML = md([q.summary, q.detail, links].filter(Boolean).join("\n\n"));
  $("d-note").value = state.notes[id] || "";
  const btn = $("d-toggle"); const done = !!state.done[id];
  btn.textContent = done ? "取消完成" : "完成任务";
  btn.className = `btn wide ${done ? "" : "primary"}`;
}
function openQuest(id) { openId = id; fillSheet(id); $("sheet").classList.remove("hidden"); }
function closeSheets() { openId = null; document.querySelectorAll(".sheet").forEach((s) => s.classList.add("hidden")); }

// ---------- 封存 ----------
function renderArchive() {
  const ul = $("archive-list"); ul.innerHTML = "";
  const list = [...(index.archives || [])].sort().reverse();
  if (!list.length) { ul.innerHTML = '<li class="muted">还没有封存的日子。每天推送新任务时，前一天会自动封存成图片。</li>'; return; }
  for (const a of list) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${esc(dayLabel(a.date))}</span><span class="muted">${a.coins != null ? `🪙 ${a.coins} · ` : ""}完成 ${a.rate}%</span>`;
    li.addEventListener("click", () => showArchive(a.date));
    ul.appendChild(li);
  }
}
async function showArchive(d) {
  $("archive-list").classList.add("hidden"); $("archive-view").classList.remove("hidden");
  const img = $("archive-img"); img.removeAttribute("src");
  try {
    const bytes = await decryptBytes(await fetchText(`archive/${d}.png.enc`));
    img.src = URL.createObjectURL(new Blob([bytes], { type: "image/png" }));
  } catch { img.alt = "图片读取失败"; }
}

// ---------- 启动 ----------
async function openDay() {
  const days = [...(index.days || [])].sort();
  const t = todayStr();
  day = days.includes(t) ? t : (days.filter((d) => d <= t).pop() || days[days.length - 1]);
  if (!day) { $("day-title").textContent = "还没有推送任务"; return; }
  dayData = await decryptJSON(await fetchText(`data/${day}.json.enc`));
  state = await loadState(day);
  render(); renderArchive();
}
async function unlockWith(raw) {
  key = await importKey(raw);
  await decryptBytes(meta.check); // 密码错误会在这里抛异常
  index = await decryptJSON(await fetchText("data/index.json.enc"));
  $("lock").classList.add("hidden"); $("main").classList.remove("hidden");
  await openDay();
}
async function boot() {
  meta = JSON.parse(await fetchText("meta.json"));
  const saved = store.get(LS.key);
  if (saved) { try { await unlockWith(b64.from(saved)); return; } catch { store.del(LS.key); } }
  $("lock").classList.remove("hidden");
}

$("lock-form").addEventListener("submit", async (e) => {
  e.preventDefault(); $("lock-err").textContent = "解锁中…";
  try {
    const raw = await deriveKey($("acct").value.trim() + "\n" + $("pw").value);
    await unlockWith(raw);
    store.set(LS.key, b64.to(raw));
    $("pw").value = "";
  } catch { $("lock-err").textContent = "账号或密码不对，或者网络有问题"; }
});
document.querySelectorAll("[data-close]").forEach((el) => el.addEventListener("click", closeSheets));
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheets(); });
$("d-toggle").addEventListener("click", () => toggle(openId));
$("d-note").addEventListener("input", (e) => {
  const v = e.target.value.trim();
  if (v) state.notes[openId] = e.target.value; else delete state.notes[openId];
  scheduleSave();
});
$("d-note").addEventListener("blur", render);
$("journal").addEventListener("input", (e) => { state.journal = e.target.value; scheduleSave(); });
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
  $("tab-quests").classList.toggle("hidden", b.dataset.tab !== "quests");
  $("tab-archive").classList.toggle("hidden", b.dataset.tab !== "archive");
  $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden");
}));
$("archive-back").addEventListener("click", () => { $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden"); });
$("open-settings").addEventListener("click", () => { $("token").value = ""; $("token-msg").textContent = token() ? "已保存令牌。要更换就重新填写。" : "还没有保存令牌。"; $("settings").classList.remove("hidden"); });
$("save-token").addEventListener("click", async () => {
  const v = $("token").value.trim(); if (!v) return;
  store.set(LS.token, v); $("token").value = ""; $("token-msg").textContent = "检查中…";
  const r = await gh(`meta.json?ref=${meta.branch}`).catch(() => null);
  $("token-msg").textContent = r && r.ok ? "令牌可用，开始同步。" : "令牌好像不能访问这个仓库，请检查权限。";
  if (r && r.ok) { state = await loadState(day); render(); }
});
$("forget").addEventListener("click", () => {
  [LS.key, LS.token].forEach(store.del);
  try { Object.keys(localStorage).filter((k) => k.startsWith(LS.cache)).forEach((k) => localStorage.removeItem(k)); } catch {}
  location.reload();
});
boot().catch((e) => { document.body.innerHTML = `<p style="padding:24px;color:#ff6b6b">加载失败：${esc(String(e.message || e))}</p>`; });
