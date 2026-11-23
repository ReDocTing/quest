"use strict";
// 每日任务：所有数据都是 AES-GCM 加密的，密钥由账号和密码经 PBKDF2 派生。
// 任务由电脑每天推送（data/日期.json.enc）；勾选和补充写在 state/日期.json.enc，
// 金币花费记在 wallet.json.enc，都通过 GitHub API 同步。

const LS = { key: "quest.key", token: "quest.token", cache: "quest.cache.", wallet: "quest.wallet" };
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

let meta, key, index, day, dayData, state, wallet, openId = null;
const shas = {};      // 路径 → GitHub 上的 sha
const timers = {};    // 路径 → 防抖计时器

// ---------- 浏览器存储（可能不可用，全部 try/catch） ----------
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

// ---------- 网络 ----------
async function fetchText(path) {
  const r = await fetch(`${path}?t=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.text();
}
const token = () => store.get(LS.token);
function gh(path, opts = {}) {
  return fetch(`https://api.github.com/repos/${meta.owner}/${meta.repo}/contents/${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", ...(opts.headers || {}) },
  });
}
function setSync(kind, text) { $("sync-dot").className = `dot ${kind}`; $("sync-text").textContent = text; }

// 读取一个同步文件：有令牌走 GitHub API（最新），没有令牌读网站上的副本
async function readSynced(path) {
  if (token()) {
    try {
      const r = await gh(`${path}?ref=${meta.branch}`);
      if (r.ok) {
        const j = await r.json(); shas[path] = j.sha;
        setSync("ok", "已同步");
        return await decryptJSON(atob(j.content.replace(/\n/g, "")));
      }
      shas[path] = null;
      if (r.status === 404) { setSync("ok", "已连接 GitHub"); return null; }
      setSync("bad", r.status === 401 ? "令牌无效，请在设置里重新填写" : `同步失败（${r.status}），先存在本机`);
    } catch { setSync("bad", "离线，先存在本机"); }
    return null;
  }
  setSync("bad", "未设置令牌，只存在本机");
  try { return await decryptJSON(await fetchText(path)); } catch { return null; }
}
// 写入一个同步文件；冲突时用 merge(远端, 本地) 合并后重试
function scheduleWrite(path, getObj, merge) {
  if (!token()) { setSync("bad", "未设置令牌，只存在本机"); return; }
  setSync("busy", "保存中…");
  clearTimeout(timers[path]);
  timers[path] = setTimeout(() => writeSynced(path, getObj, merge), 1200);
}
async function writeSynced(path, getObj, merge, retry = true) {
  try {
    const body = { message: `update ${path}`, branch: meta.branch, content: btoa(await encryptText(JSON.stringify(getObj()))) };
    if (shas[path]) body.sha = shas[path];
    const r = await gh(path, { method: "PUT", body: JSON.stringify(body) });
    if (r.ok) { shas[path] = (await r.json()).content.sha; setSync("ok", "已同步"); return; }
    if ((r.status === 409 || r.status === 422) && retry) {
      const remote = await readSynced(path);
      if (remote && merge) merge(remote);
      return writeSynced(path, getObj, merge, false);
    }
    setSync("bad", r.status === 401 ? "令牌无效，请在设置里重新填写" : `同步失败（${r.status}），已存在本机`);
  } catch { setSync("bad", "离线，已存在本机，联网后再改一次就会同步"); }
}

// ---------- 当天的勾选和补充 ----------
const newer = (a, b) => [a, b].filter(Boolean).sort((x, y) => (y.updated || "").localeCompare(x.updated || ""))[0];
async function loadState(d) {
  const empty = { date: d, done: {}, notes: {}, journal: "", updated: "" };
  const remote = await readSynced(`state/${d}.json.enc`);
  let local = null;
  try { const c = store.get(LS.cache + d); if (c) local = JSON.parse(c); } catch {}
  return { ...empty, ...(newer(remote, local) || {}) };
}
function saveState() {
  state.updated = new Date().toISOString();
  store.set(LS.cache + day, JSON.stringify(state));
  scheduleWrite(`state/${day}.json.enc`, () => state, (remote) => { if ((remote.updated || "") > state.updated) state = remote; });
}

// ---------- 金币钱包 ----------
function mergeWallet(a, b) {
  const deleted = [...new Set([...(a.deleted || []), ...(b.deleted || [])])];
  const byId = {};
  for (const s of [...(a.spends || []), ...(b.spends || [])]) byId[s.id] = s;
  const spends = Object.values(byId).filter((s) => !deleted.includes(s.id)).sort((x, y) => y.at.localeCompare(x.at));
  return { spends, deleted, updated: new Date().toISOString() };
}
async function loadWallet() {
  const remote = await readSynced("wallet.json.enc");
  let local = null;
  try { const c = store.get(LS.wallet); if (c) local = JSON.parse(c); } catch {}
  return mergeWallet(remote || {}, local || {});
}
function saveWallet() {
  wallet.updated = new Date().toISOString();
  store.set(LS.wallet, JSON.stringify(wallet));
  scheduleWrite("wallet.json.enc", () => wallet, (remote) => { wallet = mergeWallet(remote, wallet); });
}

// ---------- 小型 Markdown ----------
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
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
  const flushAll = () => { flushPara(); flushList(); flushTable(); };
  for (const raw of lines) {
    const line = raw.trimEnd();
    let m;
    if ((m = line.trim().match(/^<details>\s*<summary>(.*?)<\/summary>$/))) { flushAll(); html += `<details><summary>${inline(m[1])}</summary>`; continue; }
    if (/^<\/details>$/.test(line.trim())) { flushAll(); html += "</details>"; continue; }
    if (/^\|.*\|$/.test(line.trim())) { flushPara(); flushList(); table.push(line.trim()); continue; } else flushTable();
    if (!line.trim()) { flushPara(); flushList(); }
    else if ((m = line.match(/^(#{1,4})\s+(.*)/))) { flushPara(); flushList(); html += m[1].length === 1 ? `<h2>${inline(m[2])}</h2>` : `<h3>${inline(m[2])}</h3>`; }
    else if ((m = line.match(/^>\s?(.*)/))) { flushPara(); flushList(); html += `<blockquote>${inline(m[1])}</blockquote>`; }
    else if ((m = line.match(/^\s*[-*]\s+(.*)/))) { flushPara(); if (list !== "ul") { flushList(); html += "<ul>"; list = "ul"; } html += `<li>${inline(m[1])}</li>`; }
    else if ((m = line.match(/^\s*\d+\.\s+(.*)/))) { flushPara(); if (list !== "ol") { flushList(); html += "<ol>"; list = "ol"; } html += `<li>${inline(m[1])}</li>`; }
    else if (/^-{3,}$/.test(line.trim())) { flushPara(); flushList(); html += "<hr>"; }
    else { flushList(); para.push(line); }
  }
  flushAll();
  return html;
}

// ---------- 日期 ----------
const fmt = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const todayStr = () => fmt(new Date());
function mondayOf(dstr) { const d = new Date(dstr + "T00:00:00"); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); return fmt(d); }
function dayLabel(d) {
  const diff = Math.round((new Date(d + "T00:00:00") - new Date(todayStr() + "T00:00:00")) / 86400000);
  const wd = "日一二三四五六"[new Date(d + "T00:00:00").getDay()];
  const rel = diff === 0 ? "今天" : diff === 1 ? "明天" : diff === -1 ? "昨天" : diff > 0 ? `${diff} 天后` : `${-diff} 天前`;
  return `${d} · 周${wd} · ${rel}`;
}

// ---------- 金币计算 ----------
function coinStats() {
  const qs = dayData.quests || [];
  const dayAll = qs.reduce((s, q) => s + (q.coins || 0), 0);
  const dayGot = qs.filter((q) => state.done[q.id]).reduce((s, q) => s + (q.coins || 0), 0);
  const weekGot = ((index.weeks || {})[mondayOf(day)] || 0) + dayGot;
  const earned = (index.earned || 0) + dayGot;
  const spent = (wallet.spends || []).reduce((s, x) => s + x.amount, 0);
  return { dayAll, dayGot, weekGot, cap: index.cap || 750, earned, spent, balance: earned - spent };
}

// ---------- 渲染 ----------
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
  const c = coinStats();
  $("wallet-btn").textContent = `🪙 ${c.balance}`;
  $("coin-week").textContent = `本周 ${c.weekGot} / ${c.cap}`;
  $("coin-day").textContent = `今日 ${c.dayGot} / ${c.dayAll} · 完成 ${doneN}/${qs.length}`;
  $("xp-bar").style.width = `${Math.min(100, (c.weekGot / c.cap) * 100)}%`;

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
  if (document.activeElement !== $("journal")) $("journal").value = state.journal || "";
  renderJapanese();
  if (!$("wallet").classList.contains("hidden")) renderWallet();
}
function renderJapanese() {
  const ja = dayData.japanese;
  $("ja-body").innerHTML = ja && ja.md
    ? md(ja.md)
    : '<p class="muted">今天的日语教材还没生成。另一个对话生成后，重新推送一次就会出现在这里。</p>';
}
function toggle(id) {
  if (state.done[id]) delete state.done[id]; else state.done[id] = new Date().toISOString();
  saveState(); render();
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

// ---------- 钱包面板 ----------
function renderWallet() {
  const c = coinStats();
  $("w-balance").textContent = c.balance;
  $("w-stats").textContent = `累计获得 ${c.earned} · 累计花费 ${c.spent} · 本周 ${c.weekGot}/${c.cap}`;
  const ul = $("w-list"); ul.innerHTML = "";
  if (!wallet.spends.length) { ul.innerHTML = '<li class="muted">还没有花过金币。</li>'; return; }
  for (const s of wallet.spends) {
    const li = document.createElement("li");
    const t = new Date(s.at);
    li.innerHTML = `<div><div>${esc(s.note)}</div><div class="muted small">${fmt(t)} ${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}</div></div>
      <div class="spend-amt">−${s.amount}</div><button class="icon-btn" aria-label="删除这条">✕</button>`;
    li.querySelector("button").addEventListener("click", () => {
      if (!confirm(`删除“${s.note}”这条记录？金币会退回余额。`)) return;
      wallet.deleted = [...(wallet.deleted || []), s.id];
      wallet.spends = wallet.spends.filter((x) => x.id !== s.id);
      saveWallet(); render(); renderWallet();
    });
    ul.appendChild(li);
  }
}
function spend() {
  const amount = parseInt($("w-amount").value, 10);
  const note = $("w-note").value.trim();
  const msg = $("w-msg");
  if (!amount || amount <= 0) { msg.textContent = "填一个大于 0 的金额"; return; }
  if (!note) { msg.textContent = "写一下花在哪"; return; }
  if (amount > coinStats().balance) { msg.textContent = "余额不够"; return; }
  wallet.spends.unshift({ id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, at: new Date().toISOString(), amount, note });
  $("w-amount").value = ""; $("w-note").value = ""; msg.textContent = `已花掉 ${amount} 金币：${note}`;
  saveWallet(); render(); renderWallet();
}

// ---------- 封存 ----------
function renderArchive() {
  const ul = $("archive-list"); ul.innerHTML = "";
  const list = [...(index.archives || [])].sort((a, b) => b.date.localeCompare(a.date));
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
  [state, wallet] = await Promise.all([loadState(day), loadWallet()]);
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
  if (e.target.value.trim()) state.notes[openId] = e.target.value; else delete state.notes[openId];
  saveState();
});
$("d-note").addEventListener("blur", render);
$("journal").addEventListener("input", (e) => { state.journal = e.target.value; saveState(); });
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
  for (const name of ["quests", "archive", "ja"]) $(`tab-${name}`).classList.toggle("hidden", b.dataset.tab !== name);
  $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden");
}));
$("archive-back").addEventListener("click", () => { $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden"); });
$("wallet-btn").addEventListener("click", () => { $("w-msg").textContent = ""; renderWallet(); $("wallet").classList.remove("hidden"); });
$("w-spend").addEventListener("click", spend);
$("open-settings").addEventListener("click", () => { $("token").value = ""; $("token-msg").textContent = token() ? "已保存令牌。要更换就重新填写。" : "还没有保存令牌。"; $("settings").classList.remove("hidden"); });
$("save-token").addEventListener("click", async () => {
  const v = $("token").value.trim(); if (!v) return;
  store.set(LS.token, v); $("token").value = ""; $("token-msg").textContent = "检查中…";
  const r = await gh(`meta.json?ref=${meta.branch}`).catch(() => null);
  $("token-msg").textContent = r && r.ok ? "令牌可用，开始同步。" : "令牌好像不能访问这个仓库，请检查权限。";
  if (r && r.ok) { [state, wallet] = await Promise.all([loadState(day), loadWallet()]); render(); }
});
$("forget").addEventListener("click", () => {
  [LS.key, LS.token, LS.wallet].forEach(store.del);
  try { Object.keys(localStorage).filter((k) => k.startsWith(LS.cache)).forEach((k) => localStorage.removeItem(k)); } catch {}
  location.reload();
});
boot().catch((e) => { document.body.innerHTML = `<p style="padding:24px;color:#ff6b6b">加载失败：${esc(String(e.message || e))}</p>`; });
