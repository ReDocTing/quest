"use strict";
// 每日任务：所有数据都是 AES-GCM 加密的，密钥由账号和密码经 PBKDF2 派生。
// 任务由电脑每天推送（data/日期.json.enc）；勾选和补充写在 state/日期.json.enc，
// 用金币兑换的“努力的奖励”记在 wallet.json.enc，都通过 GitHub API 同步。

const LS = { key: "quest.key", token: "quest.token", cache: "quest.cache.", wallet: "quest.wallet" };
const TYPE = {   // 顺序 = 任务列表里分组的顺序
  main: { name: "主线", cls: "t-main" },
  side: { name: "支线", cls: "t-side" },
  train: { name: "修炼", cls: "t-train" },
  daily: { name: "日常", cls: "t-daily" },
  rest: { name: "作息", cls: "t-rest" },
};
const $ = (id) => document.getElementById(id);
// 浏览器缓存了旧的 index.html、却拿到了新脚本时：强制重新加载一次，避免新标签页一片空白
if (["diet-date", "review-body", "digest-body"].some((id) => !$(id))) {
  if (!/[?&]r=/.test(location.search)) location.replace(location.pathname + "?r=" + Date.now());
  throw new Error("页面版本过旧，正在重新加载");
}
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
// 锁定的任务：推送时标了 locked 的，或者昨天练过健身房（网页上再查一次，防止推送后才勾昨天的）
let prevGymDone = false;
function lockReason(q) {
  if (q.locked) return q.locked;
  if (q.id === "gym" && prevGymDone) return "昨天练过，今天强制休息";
  return "";
}
async function loadPrevGym() {
  const d = new Date(day + "T00:00:00"); d.setDate(d.getDate() - 1);
  const prev = fmt(d);
  prevGymDone = false;
  if (!(index.days || []).includes(prev)) return;
  let remote = null, local = null;
  if (token()) {
    try { const r = await gh(`state/${prev}.json.enc?ref=${meta.branch}`); if (r.ok) remote = await decryptJSON(atob((await r.json()).content.replace(/\n/g, ""))); } catch {}
  } else {
    try { remote = await decryptJSON(await fetchText(`state/${prev}.json.enc`)); } catch {}
  }
  try { const c = store.get(LS.cache + prev); if (c) local = JSON.parse(c); } catch {}
  const st = newer(remote, local);
  prevGymDone = !!(st && st.done && st.done.gym);
}
function coinStats() {
  const qs = (dayData.quests || []).filter((q) => !lockReason(q));
  const dayAll = qs.reduce((s, q) => s + (q.coins || 0), 0);
  const dayGot = qs.filter((q) => state.done[q.id]).reduce((s, q) => s + (q.coins || 0), 0);
  const weekGot = ((index.weeks || {})[mondayOf(day)] || 0) + dayGot;
  const earned = (index.earned || 0) + dayGot;
  const spent = (wallet.spends || []).reduce((s, x) => s + x.amount, 0);
  return { dayAll, dayGot, weekGot, earned, spent, balance: earned - spent };
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
  const active = qs.filter((q) => !lockReason(q));
  const doneN = active.filter((q) => state.done[q.id]).length;
  const c = coinStats();
  $("wallet-btn").innerHTML = `<i class="coin" aria-hidden="true"></i>${c.balance}`;
  $("coin-week").innerHTML = `本周已得 <i class="coin" aria-hidden="true"></i>${c.weekGot}`;
  $("coin-day").textContent = `今日 ${c.dayGot} / ${c.dayAll} · 完成 ${doneN}/${active.length}`;
  $("xp-bar").style.width = c.dayAll ? `${Math.min(100, (c.dayGot / c.dayAll) * 100)}%` : "0";

  const ul = $("quest-list"); ul.innerHTML = "";
  // 按类型分组显示：主线 → 支线 → 修炼 → 日常 → 作息，组内保持原来的顺序
  const order = Object.keys(TYPE), typeOf = (q) => (TYPE[q.type] ? q.type : "daily");
  const sorted = [...qs].sort((a, b) => order.indexOf(typeOf(a)) - order.indexOf(typeOf(b)));
  let curType = null;
  for (const q of sorted) {
    const tp = TYPE[typeOf(q)];
    if (typeOf(q) !== curType) {
      curType = typeOf(q);
      const grp = qs.filter((x) => typeOf(x) === curType && !lockReason(x));
      const h = document.createElement("li");
      h.className = `q-group ${tp.cls}`;
      h.innerHTML = `<span>${tp.name}</span><span class="q-group-n">${grp.filter((x) => state.done[x.id]).length} / ${grp.length}</span>`;
      ul.appendChild(h);
    }
    const lock = lockReason(q);
    const li = document.createElement("li");
    li.className = `quest ${tp.cls}${state.done[q.id] ? " done" : ""}${lock ? " locked" : ""}`;
    li.innerHTML = `
      <button class="check-btn" aria-label="${lock ? "强制休息，不能勾选" : "完成"}"${lock ? " disabled" : ""}>${lock ? "休" : state.done[q.id] ? "✓" : ""}</button>
      <div class="q-main">
        ${state.notes[q.id] ? '<div class="q-meta"><span class="q-note">✎ 有补充</span></div>' : ""}
        <div class="q-title">${esc(q.title)}</div>
        ${lock ? `<div class="q-sum lock-msg">${esc(lock)}</div>` : q.summary ? `<div class="q-sum">${esc(q.summary)}</div>` : ""}
      </div>
      <div class="q-xp">${lock ? "休息" : `+${q.coins || 0} <i class="coin" aria-hidden="true"></i>`}</div>`;
    li.querySelector(".check-btn").addEventListener("click", (e) => { e.stopPropagation(); toggle(q.id); });
    li.addEventListener("click", () => openQuest(q.id));
    ul.appendChild(li);
  }
  if (document.activeElement !== $("journal")) $("journal").value = state.journal || "";
  if (!$("wallet").classList.contains("hidden")) renderWallet();
}
// ---------- 今日日语（日语对话写的 JSON，推送时加密成 data/ja/日期.json.enc；当天的语音在 data/ja-audio/日期/） ----------
const jaCache = {};
const audioUrls = {};
let jaDate = null, jaCards = [], jaCardIdx = 0, jaCardFlip = false, jaZhFront = false, curAudio = null, curAudioEl = null;
// *_ruby 只允许 <ruby> <rt> <b>：先整体转义，再放回这三个标签
function ruby(s) { return esc(s || "").replace(/&lt;(\/?)(ruby|rt|b)&gt;/g, "<$1$2>"); }
function setKana(show) {
  document.body.classList.toggle("hide-rt", !show);
  store.set("quest.kana", show ? "1" : "0");
  const b = $("kana-btn"); if (b) b.textContent = show ? "假名：显示" : "假名：隐藏";
}
function fillJaDates() {
  const dates = [...(index.ja || [])].sort();
  const sel = $("ja-date"); sel.innerHTML = "";
  setKana(store.get("quest.kana") !== "0");
  if (!dates.length) { $("ja-body").innerHTML = '<p class="muted">还没有推送过日语讲义。</p>'; return; }
  for (const d of [...dates].reverse()) {
    const o = document.createElement("option"); o.value = d; o.textContent = dayLabel(d); sel.appendChild(o);
  }
  sel.value = dates.includes(day) ? day : (dates.filter((d) => d <= day).pop() || dates[dates.length - 1]);
}
const hasAudio = (d = jaDate) => !!index.ja_audio && index.ja_audio === d;
function stopAudio() {
  if (curAudio) { curAudio.pause(); curAudio = null; }
  if (curAudioEl) { curAudioEl.classList.remove("playing"); if (curAudioEl.id === "ja-full") curAudioEl.textContent = "▶ 听全文"; curAudioEl = null; }
  document.querySelectorAll(".ja-line.now").forEach((x) => x.classList.remove("now"));
}
async function audioUrl(d, file) {
  const k = `${d}/${file}`;
  if (!audioUrls[k]) {
    const bytes = await decryptBytes(await fetchText(`data/ja-audio/${d}/${file}.enc`));
    audioUrls[k] = URL.createObjectURL(new Blob([bytes], { type: "audio/mpeg" }));
  }
  return audioUrls[k];
}
async function playAudio(file, el, d = jaDate) {
  if (!file || !hasAudio(d)) return;
  if (el && curAudioEl === el && curAudio) { stopAudio(); return; } // 再点一下停止
  stopAudio();
  try {
    const url = await audioUrl(d, file);
    curAudio = new Audio(url); curAudioEl = el || null;
    if (curAudioEl) curAudioEl.classList.add("playing");
    curAudio.addEventListener("ended", stopAudio);
    await curAudio.play();
  } catch { stopAudio(); }
}
// 听全文：播放 ALL.mp3，按每句的 start / end 高亮当前句并滚动过去
async function playFull(btn, dlg) {
  if (curAudioEl === btn && curAudio) { stopAudio(); return; }
  stopAudio();
  try {
    const url = await audioUrl(jaDate, dlg.full_audio);
    curAudio = new Audio(url); curAudioEl = btn;
    btn.classList.add("playing"); btn.textContent = "■ 停止";
    const rows = [...document.querySelectorAll("#ja-body .ja-line")];
    let last = -1;
    curAudio.addEventListener("timeupdate", () => {
      if (!curAudio) return;
      const t = curAudio.currentTime;
      const i = dlg.lines.findIndex((l) => t >= (l.start || 0) && t < (l.end || 0) + 0.6);
      if (i === last) return;
      last = i;
      rows.forEach((r, k) => r.classList.toggle("now", k === i));
      if (i >= 0 && rows[i]) rows[i].scrollIntoView({ behavior: "smooth", block: "center" });
    });
    curAudio.addEventListener("ended", stopAudio);
    await curAudio.play();
  } catch { stopAudio(); }
}
async function renderJapanese() {
  const d = $("ja-date").value; if (!d) return;
  jaDate = d; stopAudio();
  const box = $("ja-body");
  try {
    if (!jaCache[d]) { box.innerHTML = '<p class="muted">读取中…</p>'; jaCache[d] = await decryptJSON(await fetchText(`data/ja/${d}.json.enc`)); }
  } catch { box.innerHTML = '<p class="muted">这一天的讲义读取失败。</p>'; return; }
  const j = jaCache[d];
  const au = hasAudio();
  const play = (f) => (au && f ? ` data-audio="${esc(f)}"` : "");
  const icon = (f) => (au && f ? '<span class="spk" aria-hidden="true">🔊</span>' : "");
  const sec = (title, inner, id) => inner ? `<section class="ja-sec"${id ? ` id="${id}"` : ""}><h3>${title}</h3>${inner}</section>` : "";
  let h = `<div class="ja-head"><div class="day-label">第 ${esc(j.week || "")} 周 · ${esc(j.weekday || "")}${j.week_title ? ` · ${esc(j.week_title)}` : ""}</div><h2>${inline(j.title || "今日日语")}</h2>
    <p class="muted small">${au ? "点带 🔊 的句子、表达、生词和例句可以听发音，再点一下停止。" : "以前的日子只能看文字，没有声音。"}</p></div>`;
  if ((j.expressions || []).length) {
    h += sec("今天的表达", j.expressions.map((e) => `<div class="ja-expr${au && e.audio ? " tap" : ""}"${play(e.audio)}><div class="ja-big">${ruby(e.ja_ruby || esc(e.ja))}${e.srs ? ' <span class="ja-star" title="核心表达">★</span>' : ""} ${icon(e.audio)}</div><div>${inline(e.zh || "")}</div>${e.use ? `<div class="muted small">${inline(e.use)}</div>` : ""}</div>`).join(""));
  }
  if (j.extra) h += `<p class="ja-extra">另外记住：${inline(j.extra)}</p>`;
  if (j.dialogue && (j.dialogue.lines || []).length) {
    h += sec("对话", `${j.dialogue.scene ? `<p class="muted small">${inline(j.dialogue.scene)}</p>` : ""}
      <div class="dlg-tools">${au && j.dialogue.full_audio ? '<button class="btn small-btn full-btn" id="ja-full">▶ 听全文</button>' : ""}<button class="btn ghost small-btn" id="ja-zh-all">显示全部翻译</button></div>
      ${j.dialogue.lines.map((l) => `<div class="ja-line"><span class="ja-who">${esc(l.who || "")}</span><div class="ja-line-main"><div class="${au && l.audio ? "tap" : ""}"${play(l.audio)}>${ruby(l.ja_ruby || inline(l.ja))} ${icon(l.audio)}</div><div class="ja-zh hidden">${inline(l.zh || "")}</div></div><button class="zh-btn" aria-label="显示这一句的翻译">译</button></div>`).join("")}
      <p class="muted small">点句子听发音，点右边的“译”看这一句的翻译。</p>`);
  }
  if ((j.grammar || []).length) {
    h += sec("文法", j.grammar.map((g) => `<div class="ja-gram"><div class="ja-big">${esc(g.pattern)}${g.srs ? ' <span class="ja-star">★</span>' : ""}</div><div>${inline(g.meaning || "")}</div>${g.explain ? `<div class="muted small">${inline(g.explain)}</div>` : ""}${g.example ? `<div class="ja-ex${au && g.audio ? " tap" : ""}"${play(g.audio)}>${ruby(g.example_ruby || esc(g.example))} ${icon(g.audio)}<div class="muted small">${inline(g.example_zh || "")}</div></div>` : ""}</div>`).join(""));
  }
  if ((j.vocab || []).length) {
    h += sec("生词", j.vocab.map((v) => `<div class="ja-vocab"><div class="${au && v.audio ? "tap" : ""}"${play(v.audio)}><strong>${ruby(v.word_ruby || esc(v.word))}</strong>${v.reading && v.reading !== v.word ? `<span class="muted">（${esc(v.reading)}）</span>` : ""}　${inline(v.meaning || "")} ${icon(v.audio)}</div>${v.example ? `<div class="small">${ruby(v.example_ruby || esc(v.example))}</div><div class="muted small">${inline(v.example_zh || "")}</div>` : ""}</div>`).join(""));
  }
  if ((j.notes || []).length) h += sec("用法提示", `<ul>${j.notes.map((n) => `<li>${inline(n)}</li>`).join("")}</ul>`);
  if ((j.quiz || []).length) h += sec("小测", `<ol>${j.quiz.map((q) => `<li>${inline(q.q)}<details><summary>看答案</summary>${inline(q.a)}</details></li>`).join("")}</ol>`);
  if (j.mission) h += sec("实战任务", `<p>${inline(j.mission)}</p>`);
  if (j.output) h += sec("1 分钟输出", `<p>${inline(j.output)}</p>`);
  if ((j.review_of || []).length) h += `<p class="muted small">复习范围：${j.review_of.map(esc).join("、")}</p>`;
  const r = j.recite || {};
  const exBlock = (rb, plain, zh) => (plain ? `<div class="small">${ruby(rb || esc(plain))}</div><div class="muted small">${inline(zh || "")}</div>` : "");
  jaCards = [
    ...(r.words || []).map((w) => ({ front: ruby(w.word_ruby || esc(w.word)), zh: inline(w.meaning || ""), audio: w.audio,
      back: `${w.reading && w.reading !== w.word ? `<div class="muted">${esc(w.reading)}</div>` : ""}<div class="ja-big">${inline(w.meaning || "")}</div>${exBlock(w.example_ruby, w.example, w.example_zh)}` })),
    ...(r.phrases || []).map((p) => ({ front: ruby(p.ja_ruby || esc(p.ja)), zh: inline(p.zh || ""), audio: p.audio,
      back: `<div class="ja-big">${inline(p.zh || "")}</div>` })),
    ...(r.grammar || []).map((g) => ({ front: esc(g.pattern), zh: inline(g.meaning || ""), audio: null, tag: "文法",
      back: `<div class="ja-big">${inline(g.meaning || "")}</div>${exBlock(g.example_ruby, g.example, g.example_zh)}` })),
  ];
  if (jaCards.length) {
    h += sec(`本日背诵（${jaCards.length} 张）`, `${r.how ? `<p class="muted small">${inline(r.how)}</p>` : ""}
      <div class="card-tools"><button class="btn ghost small-btn" id="card-dir"></button><span id="card-count" class="muted small"></span></div>
      <div id="card" class="flashcard" role="button" tabindex="0"></div>
      <div class="card-nav"><button class="btn" id="card-prev">← 上一张</button><button class="btn" id="card-next">下一张 →</button></div>`, "ja-recite");
  }
  // 语音出处：按各声音的使用条款，页面底部要显示 voice_credits
  const cast = Object.entries(j.cast_today || {}).map(([who, c]) => `${esc(who)}：${esc(c.voice || "")}${c.speed ? `（${c.speed} 倍速）` : ""}`);
  if ((j.voice_credits || []).length || cast.length) {
    h += `<p class="ja-credits">${cast.length ? `今天的声音：${cast.join("、")}<br>` : ""}${(j.voice_credits || []).length ? `语音：${j.voice_credits.map(esc).join("、")}` : ""}</p>`;
  }
  box.innerHTML = h;
  box.querySelectorAll("[data-audio]").forEach((el) => el.addEventListener("click", (e) => { e.stopPropagation(); playAudio(el.dataset.audio, el); }));
  box.querySelectorAll(".zh-btn").forEach((b) => b.addEventListener("click", () => b.parentElement.querySelector(".ja-zh").classList.toggle("hidden")));
  const full = $("ja-full");
  if (full) full.addEventListener("click", () => playFull(full, j.dialogue));
  const all = $("ja-zh-all");
  if (all) all.addEventListener("click", () => {
    const show = all.textContent.startsWith("显示");
    box.querySelectorAll(".ja-zh").forEach((z) => z.classList.toggle("hidden", !show));
    all.textContent = show ? "隐藏全部翻译" : "显示全部翻译";
  });
  if (jaCards.length) {
    jaCardIdx = 0; jaCardFlip = false; drawCard();
    const flip = () => { jaCardFlip = !jaCardFlip; drawCard(); if (jaCardFlip) playAudio(jaCards[jaCardIdx].audio, null); };
    $("card").addEventListener("click", flip);
    $("card").addEventListener("keydown", (e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); flip(); } });
    $("card-prev").addEventListener("click", () => { jaCardIdx = (jaCardIdx - 1 + jaCards.length) % jaCards.length; jaCardFlip = false; stopAudio(); drawCard(); });
    $("card-next").addEventListener("click", () => { jaCardIdx = (jaCardIdx + 1) % jaCards.length; jaCardFlip = false; stopAudio(); drawCard(); });
    $("card-dir").addEventListener("click", () => { jaZhFront = !jaZhFront; jaCardFlip = false; drawCard(); });
  }
}
function drawCard() {
  const c = jaCards[jaCardIdx];
  const tag = c.tag ? `<span class="tag t-side">${c.tag}</span>` : "";
  const front = jaZhFront ? `<div class="ja-card-front">${c.zh}</div>` : `<div class="ja-card-front">${c.front}</div>`;
  const back = jaZhFront ? `<div class="ja-card-front">${c.front}</div>${c.back}` : c.back;
  $("card").innerHTML = jaCardFlip ? `${tag}${back}` : `${tag}${front}<div class="muted small">点一下翻面${hasAudio() && c.audio ? "，同时播放发音" : ""}</div>`;
  $("card").classList.toggle("flipped", jaCardFlip);
  $("card-count").textContent = `${jaCardIdx + 1} / ${jaCards.length}`;
  $("card-dir").textContent = jaZhFront ? "改成正面日语" : "改成正面中文";
}
// 从任务跳到日语页（target = "ja" 或 "ja-recite"）
async function gotoJapanese(target) {
  closeSheets();
  document.querySelector('.tab[data-tab="ja"]').click();
  const sel = $("ja-date");
  if ([...sel.options].some((o) => o.value === day) && sel.value !== day) { sel.value = day; await renderJapanese(); }
  if (target === "ja-recite") setTimeout(() => { const el = $("ja-recite"); if (el) el.scrollIntoView({ behavior: "smooth" }); }, 200);
  else window.scrollTo({ top: 0, behavior: "smooth" });
}
// ---------- 每日资讯（资讯对话写的 JSON，推送时加密成 data/digest.json.enc，仓库里只有当天的） ----------
let digestData = null, digestLoaded = false, wishlist = { items: {} };
const safeUrl = (u) => (typeof u === "string" && /^https?:\/\//.test(u) ? esc(u) : "");
const extLink = (text, url) => { const u = safeUrl(url); return u ? `<a href="${u}" target="_blank" rel="noopener">${esc(text)}</a>` : esc(text); };

// 想精读：和勾选一样走 GitHub 同步（wishlist.json.enc），按每篇论文最后修改时间合并
function mergeWish(a, b) {
  const items = { ...(a.items || {}) };
  for (const [id, x] of Object.entries(b.items || {})) if (!items[id] || (x.at || "") > (items[id].at || "")) items[id] = x;
  return { items, updated: new Date().toISOString() };
}
async function loadWishlist() {
  const remote = await readSynced("wishlist.json.enc");
  let local = null;
  try { const c = store.get("quest.wish"); if (c) local = JSON.parse(c); } catch {}
  return mergeWish(remote || {}, local || {});
}
function saveWishlist() {
  store.set("quest.wish", JSON.stringify(wishlist));
  scheduleWrite("wishlist.json.enc", () => wishlist, (remote) => { wishlist = mergeWish(remote, wishlist); });
}

async function renderDigest() {
  const box = $("digest-body");
  if (!index.digest || index.digest !== todayStr()) {
    box.innerHTML = '<p class="muted dg-empty">今天的资讯还没生成，以前的在电脑上的 每日资讯/预览.html 里看。</p>';
    return;
  }
  if (!digestLoaded) {
    box.innerHTML = '<p class="muted">读取中…</p>';
    try { digestData = await decryptJSON(await fetchText("data/digest.json.enc")); } catch { box.innerHTML = '<p class="muted">资讯读取失败。</p>'; return; }
    digestLoaded = true;
  }
  const g = digestData;
  const expandAll = store.get("quest.paperExpand") === "1";
  const papers = g.papers || [];
  const tr = g.today_read && papers.find((p) => p.id === g.today_read.paper_id);
  let h = `<div class="ja-head"><h2>每日资讯 ${esc(g.date || "")}（${esc(g.weekday || "")}）</h2><p class="muted small">阅读约 ${esc(g.reading_minutes || 10)} 分钟</p></div>`;
  if (tr) {
    h += `<section class="dg-card dg-today"><div class="day-label">今日一读</div><div class="dg-title">${extLink(tr.title, tr.url)}</div><p>${esc(g.today_read.reason || "")}</p></section>`;
  }
  if ((g.news || []).length || g.news_note) {
    h += `<h3 class="dg-h">昨日资讯${g.news_window ? `<span class="muted small">　${esc(g.news_window)}</span>` : ""}</h3>`;
    h += (g.news || []).map((n) => `<section class="dg-card"><div class="dg-title">${esc(n.title)}${n.date ? `<span class="muted small">　${esc(n.date)}</span>` : ""}</div>
      <p>${esc(n.summary || "")}</p>${n.why ? `<p class="muted small">${esc(n.why)}</p>` : ""}
      <div class="dg-links">${(n.sources || []).map((s) => extLink(s.name || "来源", s.url)).join("　")}</div></section>`).join("");
    if (g.news_note) h += `<p class="muted small">${esc(g.news_note)}</p>`;
  }
  if (papers.length || g.papers_note) {
    h += `<h3 class="dg-h">今日文献<button class="btn ghost small-btn" id="dg-expand-all">${expandAll ? "全部收起" : "全部展开"}</button></h3>`;
    if (g.papers_note) h += `<p class="muted small">${esc(g.papers_note)}</p>`;
    h += papers.map((p) => {
      const want = !!(wishlist.items[p.id] && wishlist.items[p.id].on);
      const meta = [
        `<span class="dg-stars">${"★".repeat(p.stars || 0)}${"☆".repeat(Math.max(0, 3 - (p.stars || 0)))}</span>`,
        p.setting ? esc(p.setting) : "",
        p.code_url ? extLink("代码", p.code_url) : `代码：${esc(p.code || "未提及")}`,
        p.project_url ? extLink("项目页", p.project_url) : "",
        p.in_my_list ? '<span class="dg-tag">已在论文清单</span>' : "",
      ].filter(Boolean).join(" · ");
      return `<section class="dg-card" data-id="${esc(p.id || "")}"><div class="dg-title">${extLink(p.title, p.url)}</div>
        <div class="muted small dg-meta">${meta}</div>
        <p>${esc(p.one_line || "")}</p><p class="muted small">${esc(p.relevance || "")}</p>
        <div class="dg-more${expandAll ? "" : " hidden"}"><p><strong>问题</strong>　${esc(p.problem || "")}</p><p><strong>方法</strong>　${esc(p.method || "")}</p><p><strong>结果</strong>　${esc(p.result || "")}</p></div>
        <div class="dg-actions"><button class="btn ghost small-btn dg-toggle">${expandAll ? "收起" : "展开"}</button>
        <button class="btn small-btn dg-want${want ? " on" : ""}">${want ? "✓ 想精读" : "想精读"}</button></div></section>`;
    }).join("");
  }
  if ((g.picks || []).length) {
    h += `<h3 class="dg-h">方向相关</h3>` + g.picks.map((k) => `<section class="dg-card"><div class="muted small"><span class="dg-tag">${esc(k.kind || "其他")}</span>${k.date ? `　${esc(k.date)}` : ""}</div>
      <div class="dg-title">${extLink(k.title, k.url)}</div><p>${esc(k.summary || "")}</p>${k.why ? `<p class="muted small">${esc(k.why)}</p>` : ""}</section>`).join("");
  }
  box.innerHTML = h;
  box.querySelectorAll(".dg-toggle").forEach((b) => b.addEventListener("click", () => {
    const more = b.closest(".dg-card").querySelector(".dg-more");
    more.classList.toggle("hidden"); b.textContent = more.classList.contains("hidden") ? "展开" : "收起";
  }));
  const all = $("dg-expand-all");
  if (all) all.addEventListener("click", () => { store.set("quest.paperExpand", expandAll ? "0" : "1"); renderDigest(); });
  box.querySelectorAll(".dg-want").forEach((b) => b.addEventListener("click", () => {
    const id = b.closest(".dg-card").dataset.id; const p = papers.find((x) => x.id === id); if (!p) return;
    const on = !(wishlist.items[id] && wishlist.items[id].on);
    wishlist.items[id] = { id, title: p.title, url: p.url, from: g.date, on, at: new Date().toISOString() };
    b.classList.toggle("on", on); b.textContent = on ? "✓ 想精读" : "想精读";
    saveWishlist();
  }));
}

// 从任务的按钮跳到别的页面：ja / ja-recite / digest
function gotoLink(link) {
  if (link === "digest" || link === "ja-review" || link === "diet") {
    closeSheets();
    document.querySelector(`.tab[data-tab="${link === "ja-review" ? "review" : link}"]`).click();
    window.scrollTo({ top: 0, behavior: "smooth" });
  } else gotoJapanese(link);
}

// ---------- 日语复习（日语对话的 review_sync.py 生成队列，推送时加密成 data/ja-review/日期.json.enc） ----------
// 交互照 日语教材/review.html：翻面 → 播放 → 忘记 / 模糊 / 记住；忘记的最后再练一次（不记录）。
// 选择写进当天 state 的 ja_review：{"<id>": {result, direction, at}}，每条只记第一次。
let rv = null; // {data, queue, again, practice, current, tally, total}
function plainRuby(html) { const d = document.createElement("div"); d.innerHTML = ruby(html); d.querySelectorAll("rt").forEach((r) => r.remove()); return esc(d.textContent); }
async function renderReview() {
  const box = $("review-body");
  if (!index.ja_review || index.ja_review !== day) {
    box.innerHTML = '<p class="muted dg-empty">今天的日语复习还没推送，推送后这里会出现要复习的卡片。</p>';
    return;
  }
  if (!rv) {
    box.innerHTML = '<p class="muted">读取中…</p>';
    let data;
    try { data = await decryptJSON(await fetchText(`data/ja-review/${day}.json.enc`)); } catch { box.innerHTML = '<p class="muted">复习队列读取失败。</p>'; return; }
    const doneMap = state.ja_review || {};
    const tally = { right: 0, fuzzy: 0, wrong: 0, ...((data.stats || {}).today || {}) };
    for (const rec of Object.values(doneMap)) if (tally[rec.result] != null) tally[rec.result]++;
    const queue = (data.items || []).filter((it) => !doneMap[String(it.id)]);
    rv = { data, queue, again: [], practice: false, current: null, tally, total: queue.length + tally.right + tally.fuzzy + tally.wrong };
  }
  if (rv.current) drawReviewCard(); else nextReview();
}
function reviewHeader() {
  const t = rv.tally, doneN = t.right + t.fuzzy + t.wrong;
  return `<div class="rv-top"><div class="rv-tally"><span class="t-ok">记住 ${t.right}</span><span class="t-mid">模糊 ${t.fuzzy}</span><span class="t-bad">忘记 ${t.wrong}</span></div>
    <div class="bar"><div style="width:${rv.total ? Math.round(100 * doneN / rv.total) : 100}%"></div></div></div>`;
}
function nextReview() {
  if (!rv.queue.length && rv.again.length && !rv.practice) { rv.practice = true; rv.queue = rv.again; rv.again = []; }
  rv.current = rv.queue.shift() || null;
  if (!rv.current) return finishReview();
  drawReviewCard();
}
function drawReviewCard() {
  const it = rv.current, rec = it.direction === "recognize", au = hasAudio(day) && it.audio;
  const spk = au ? ' <button class="play-btn" data-a="1" aria-label="播放">🔊</button>' : "";
  let ask, front, back;
  if (it.kind === "word") {
    ask = rec ? "看日语：说出读音和意思" : "看中文：说出日语";
    front = rec ? `<div class="rv-front">${esc(it.front)}</div>` : `<div class="rv-front zh">${esc(it.meaning)}</div>`;
    back = `<div class="ja-big">${ruby(it.ruby || esc(it.front))}${spk}</div><div>${esc(it.reading || "")}｜${esc(it.meaning || "")}</div>
      ${it.example_ruby ? `<div class="ja-ex">${ruby(it.example_ruby)}<div class="muted small">${esc(it.example_zh || "")}</div></div>` : it.example ? `<div class="muted">${esc(it.example)}</div>` : ""}`;
  } else if (it.kind === "phrase") {
    ask = rec ? "看日语：说出意思和什么时候用" : "看中文：用日语说出来";
    front = rec ? `<div class="rv-front">${plainRuby(it.ruby || esc(it.front))}</div>` : `<div class="rv-front zh">${esc(it.meaning)}</div>`;
    back = `<div class="ja-big">${ruby(it.ruby || esc(it.front))}${spk}</div><div>${esc(it.meaning || "")}</div><div class="muted small">${esc(it.use || it.example || "")}</div>`;
  } else {
    ask = rec ? "看句型：说出意思，再用它造一个句子" : "看意思：说出句型，再造一个句子";
    front = rec ? `<div class="rv-front">${esc(it.front)}</div>` : `<div class="rv-front zh">${esc(it.meaning)}</div>`;
    back = `<div class="ja-big">${esc(it.front)}</div><div>${esc(it.meaning || "")}</div>${it.explain ? `<div class="muted small">${esc(it.explain)}</div>` : ""}
      ${it.example_ruby ? `<div class="ja-ex">${ruby(it.example_ruby)}${spk}<div class="muted small">${esc(it.example_zh || "")}</div></div>` : it.example ? `<div class="muted">${esc(it.example)}</div>` : ""}`;
  }
  const iv = it.intervals || {};
  $("review-body").innerHTML = reviewHeader() + `
    <div class="rv-card" id="rv-card" role="button" tabindex="0">
      <div class="rv-kind"><span>${esc(it.kind_name || "")}${it.source ? ` · ${esc(it.source)}` : ""}${rv.practice ? ' <span class="rv-practice">再练一次（不记录）</span>' : ""}</span><span>第 ${esc(it.stage ?? 0)} 级 · 剩 ${rv.queue.length + 1}</span></div>
      <div class="rv-ask">${ask}</div>${front}
      <div class="rv-back hidden">${back}</div>
      <div class="muted small rv-tap">先在心里（或小声）说出来，再点一下翻面</div>
    </div>
    <div class="rv-grade hidden" id="rv-grade">${rv.practice
      ? '<button class="g-bad" data-r="wrong">还是不会</button><button class="g-mid" data-r="fuzzy">差不多</button><button class="g-ok" data-r="right">会了</button>'
      : `<button class="g-bad" data-r="wrong">忘记<small>${esc(iv.wrong || "")}</small></button><button class="g-mid" data-r="fuzzy">模糊<small>${esc(iv.fuzzy || "")}</small></button><button class="g-ok" data-r="right">记住<small>${esc(iv.right || "")}</small></button>`}</div>`;
  const card = $("rv-card");
  card.addEventListener("click", (e) => {
    if (e.target.closest(".play-btn")) { e.stopPropagation(); playAudio(it.audio, null, day); return; }
    if (card.classList.contains("open")) return;
    card.classList.add("open");
    card.querySelector(".rv-back").classList.remove("hidden"); card.querySelector(".rv-tap").classList.add("hidden");
    $("rv-grade").classList.remove("hidden");
    if (au) playAudio(it.audio, null, day);
  });
  document.querySelectorAll("#rv-grade button").forEach((b) => b.addEventListener("click", () => answerReview(b.dataset.r)));
}
function answerReview(r) {
  const it = rv.current; if (!it) return;
  rv.current = null;
  if (rv.practice) { if (r === "wrong") rv.queue.push(it); return nextReview(); }
  rv.tally[r]++;
  if (r === "wrong") rv.again.push(it);
  state.ja_review = state.ja_review || {};
  const id = String(it.id);
  if (!state.ja_review[id]) state.ja_review[id] = { result: r, direction: it.direction, at: new Date().toISOString() };
  saveState();
  nextReview();
}
function finishReview() {
  const s = rv.data.stats || {}, t = rv.tally, doneN = t.right + t.fuzzy + t.wrong;
  const stages = s.stages || [], max = Math.max(1, ...stages, s.mastered || 0);
  const bars = [...stages, s.mastered || 0].map((n, i) => `<div class="rv-col"><div style="height:${Math.round(70 * n / max) + 2}px"></div><span>${i < stages.length ? `${i}级` : "掌握"}<br>${n}</span></div>`).join("");
  const fc = (s.forecast || []).filter((f) => f.n).map((f) => `<div>${esc(f.date.slice(5))}：${f.n} 条</div>`).join("") || "<div>接下来几天没有要复习的</div>";
  $("review-body").innerHTML = reviewHeader() + `<div class="rv-done">
    <h2>${doneN ? "今天的日语复习完成了" : "今天没有要复习的"}</h2>
    <p class="muted">${doneN ? `记住 ${t.right} · 模糊 ${t.fuzzy} · 忘记 ${t.wrong}` : s.next_due ? `下次复习：${esc(s.next_due)}` : ""}</p>
    <p class="muted small">已学 ${esc(s.learned ?? 0)} 条 · 已掌握 ${esc(s.mastered ?? 0)} 条（推送时的统计）</p>
    <div class="rv-stages">${bars}</div><div class="muted small rv-fc">${fc}</div>
    <p class="muted small">结果已存进今天的同步状态，明天推送时自动回到记忆库。</p></div>`;
}


// ---------- 饮食（饮食对话写的 饮食/输出/日期.json，推送时加密成 data/diet/日期.json.enc；页面由它提供的 renderDiet 生成） ----------
function renderDiet(j) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const n = (x, dg = 0) => x == null ? "—" : Number(x).toLocaleString("zh-CN", { maximumFractionDigits: dg, minimumFractionDigits: dg });
  const pct = (x) => Math.max(0, Math.min(100, x * 100)).toFixed(1) + "%";
  const sgn = (x, u) => x == null ? "" : (x > 0 ? "+" : x < 0 ? "−" : "±") + n(Math.abs(x), 1) + u;
  let h = "";

  // 1. 主目标：体重
  const w = j.goals.find((g) => g.main) || j.goals[0];
  const t = j.timeline;
  h += `<section class="dt-card"><h3>目标进度</h3>
    <div class="dt-main-num"><b>${n(w.current, 1)}</b><span class="muted">${esc(w.unit)}</span><span class="arrow">→</span><span class="tgt">${n(w.target, 1)}${esc(w.unit)}</span></div>
    <div class="muted small">${esc(w.source)}</div>
    <div style="margin:6px 0 10px"><span class="dt-pace ${esc(t.pace)}">${esc(t.pace_text)}</span></div>
    <div class="dt-row"><span>减重 ${n(w.progress * 100, 0)}%</span><span class="muted">${(w.delta || 0) <= 0 ? `已减 ${n(-(w.delta || 0), 1)}` : `比起点 +${n(w.delta, 1)}`} · 还差 ${n(w.remaining, 1)}${esc(w.unit)}</span></div>
    <div class="dt-bar${w.status === "warn" ? " dt-warn" : ""}"><i style="width:${pct(w.progress)}"></i></div>
    <div class="dt-row"><span>时间 ${n(t.time_progress * 100, 0)}%</span><span class="muted">第 ${t.days_passed}/${t.days_total} 天 · 按计划今天 ${n(t.expected_weight, 1)}kg</span></div>
    <div class="dt-bar thin"><i style="width:${pct(t.time_progress)};background:var(--rest)"></i></div>
    <div class="dt-stones">${t.milestones.map((m) => {
      const cls = m.date === t.next_milestone.date ? "next" : m.hit === true ? "hit" : m.hit === false ? "miss" : "";
      return `<div class="dt-stone ${cls}" title="${esc(m.label)}">${esc(m.date.slice(5).replace("-", "/"))}<b>${m.low === m.high ? m.low : m.low + "–" + m.high}</b></div>`;
    }).join("")}</div>
    <div class="dt-note">下一个阶段：${esc(t.next_milestone.label)} ${t.next_milestone.low === t.next_milestone.high ? t.next_milestone.low : t.next_milestone.low + "–" + t.next_milestone.high}kg，还有 ${t.next_milestone.days_left} 天</div>
  </section>`;

  // 2. 其他指标
  h += `<section class="dt-card"><h3>身体成分${j.inbody ? `（InBody ${esc(j.inbody.date)}）` : ""}</h3>` +
    j.goals.filter((g) => g !== w).map((g) => {
      const right = g.kind === "keep"
        ? `${n(g.current, 1)}${esc(g.unit)} <span class="muted">维持 ≥${n(g.target, 1)}，底线 ${n(g.floor, 1)}</span>`
        : `${n(g.current, 1)} → <span style="color:var(--gold)">${n(g.target, 1)}</span>${esc(g.unit)} <span class="muted">${sgn(g.delta, g.unit)}</span>`;
      return `<div class="dt-goal"><div class="dt-row"><span class="lab">${esc(g.label)}</span><span class="val">${right}</span></div>
        <div class="dt-bar thin${g.status === "warn" ? " dt-warn" : ""}"><i style="width:${pct(g.progress)}${g.kind === "keep" ? ";background:var(--daily)" : ""}"></i></div>
        ${g.note ? `<div class="dt-note">${esc(g.note)}</div>` : ""}</div>`;
    }).join("") + `</section>`;

  // 3. 今日热量
  const it = j.intake, pl = j.plan, ex = j.expenditure, bal = j.balance, tg = pl.targets;
  const scale = Math.max(ex.total, pl.total.kcal, it.total.kcal) * 1.05;
  h += `<section class="dt-card"><h3>今日热量 · ${esc(j.date.slice(5))} ${esc(j.weekday)}${pl.training_day ? " · 训练日" : ""}</h3>
    <div class="dt-kcal">
      <div><b style="color:var(--gold)">${n(it.total.kcal)}</b><span>已吃（${it.meals_logged} 顿）</span></div>
      <div><b>${n(pl.total.kcal)}</b><span>计划摄入</span></div>
      <div><b style="color:var(--train)">${n(ex.total)}</b><span>消耗${ex.steps_estimated ? "（预估）" : ""}</span></div>
    </div>
    <div class="dt-row small"><span>已吃 / 计划</span><span class="muted">${it.remaining.kcal >= 0 ? `还能吃 ${n(it.remaining.kcal)}` : `超出 ${n(-it.remaining.kcal)}`} kcal</span></div>
    <div class="dt-bar"><i style="width:${pct(it.total.kcal / scale)};background:var(--gold)"></i><span class="dt-mark" style="left:${pct(pl.total.kcal / scale)}"></span></div>
    <div class="dt-row small"><span>消耗</span><span class="muted">白线 = 计划摄入</span></div>
    <div class="dt-bar"><i style="width:${pct(ex.total / scale)};background:var(--train)"></i><span class="dt-mark" style="left:${pct(pl.total.kcal / scale)}"></span></div>
    <div class="dt-balance">${bal.day_complete && bal.deficit != null ? `今日实际缺口 <b>${n(bal.deficit)}</b> kcal <span class="muted">（计划 ${n(bal.planned_deficit)}）</span>` : `按计划吃完，缺口 <b>${n(bal.planned_deficit)}</b> kcal`}</div>
  </section>`;

  // 4. 宏量
  const macro = (k, label, color) => {
    const [lo, hi] = tg[k], max = hi * 1.25, v = it.total[k];
    return `<div class="dt-row small"><span>${label}</span><span class="val">${n(v)} g <span class="muted">/ 目标 ${lo}–${hi}</span></span></div>
      <div class="dt-bar"><span class="dt-band" style="left:${pct(lo / max)};width:${pct((hi - lo) / max)}"></span><i style="width:${pct(v / max)};background:${color}"></i></div>`;
  };
  h += `<section class="dt-card"><h3>宏量营养（已吃）</h3>${macro("p", "蛋白质", "var(--ok)")}${macro("c", "碳水", "var(--daily)")}${macro("f", "脂肪", "var(--side)")}
    <div class="dt-note">虚线框是目标范围</div></section>`;

  // 5. 提醒
  if (j.advice) h += `<section class="dt-card dt-advice"><h3>下一顿提醒</h3><p>${esc(j.advice)}</p></section>`;

  // 6. 今日摄入（照片估算）
  const itemRows = (items, sum) => `<table class="dt-items">${items.map((x) => `<tr><td>${esc(x.food)}${x.amount ? ` <span class="muted">${esc(x.amount)}</span>` : ""}</td><td class="n">${n(x.kcal)} kcal · P${n(x.p)}</td></tr>`).join("")}${sum ? `<tr class="sum"><td>合计</td><td class="n">${n(sum.kcal)} kcal · P${n(sum.p)} C${n(sum.c)} F${n(sum.f)}</td></tr>` : ""}</table>`;
  h += `<section class="dt-card"><h3>今日摄入（拍照估算）</h3>` + (it.meals.length
    ? it.meals.map((m) => `<div class="dt-meal"><div class="dt-meal-head"><div>${esc(m.name)} <small class="muted">${esc(m.time)}${m.source === "photo" ? " 📷" : ""}</small></div><span>${n(m.total.kcal)} kcal · P${n(m.total.p)}</span></div>${itemRows(m.items)}${m.note ? `<div class="dt-note">${esc(m.note)}</div>` : ""}</div>`).join("")
    : `<p class="muted">还没有记录。吃饭时拍照发给饮食对话，更新后这里会显示。</p>`) + `</section>`;

  // 7. 计划摄入、消耗明细（折叠）
  h += `<details class="dt-card"><summary>计划摄入 ${n(pl.total.kcal)} kcal${pl.training_day ? "（含训练日加餐）" : ""}</summary>${itemRows(pl.items, pl.total)}</details>`;
  h += `<details class="dt-card"><summary>消耗明细 ${n(ex.total)} kcal</summary><table class="dt-items">
    <tr><td>基础代谢 ${n(ex.bmr)} × ${n(ex.base_factor, 1)}（日常生活和消化）</td><td class="n">${n(ex.base)}</td></tr>
    <tr><td>走路 ${n(ex.steps)} 步${ex.steps_estimated ? "（还没报步数，按计划算）" : ""}</td><td class="n">${n(ex.walk)}</td></tr>
    <tr><td>力量训练${pl.training_note ? ` <span class="muted">${esc(pl.training_note)}</span>` : ""}</td><td class="n">${n(ex.training_kcal)}</td></tr>
    <tr class="sum"><td>合计</td><td class="n">${n(ex.total)} kcal</td></tr></table></details>`;

  // 8. 最近 14 天
  const rc = j.recent.filter((r) => r.intake != null || r.weight != null);
  if (rc.length >= 2) {
    const W = 600, H = 170, pad = 26, bw = (W - pad * 2) / 14;
    const slot = (r) => 13 - Math.round((new Date(j.date) - new Date(r.date)) / 864e5);  // 固定 14 格，今天在最右
    const kmax = Math.max(...rc.map((r) => Math.max(r.expenditure, r.intake || 0))) * 1.05;
    const ws = rc.filter((r) => r.weight != null).map((r) => r.weight);
    const wlo = Math.min(...ws) - 0.5, whi = Math.max(...ws) + 0.5;
    const y = (k) => H - pad - (k / kmax) * (H - pad * 2), yw = (v) => pad + (whi - v) / (whi - wlo) * (H - pad * 2);
    let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="最近摄入、消耗和体重">`;
    rc.forEach((r) => {
      const x = pad + slot(r) * bw;
      s += `<rect x="${x + bw * .15}" y="${y(r.expenditure)}" width="${bw * .32}" height="${H - pad - y(r.expenditure)}" fill="#ff7a59" opacity=".55"/>`;
      if (r.intake != null) s += `<rect x="${x + bw * .5}" y="${y(r.intake)}" width="${bw * .32}" height="${H - pad - y(r.intake)}" fill="#f2c14e"/>`;
      s += `<text x="${x + bw / 2}" y="${H - 8}" fill="#8a94ab" font-size="11" text-anchor="middle">${esc(r.date.slice(8))}</text>`;
    });
    const pts = rc.map((r) => r.weight == null ? null : [pad + slot(r) * bw + bw / 2, yw(r.weight)]).filter(Boolean);
    if (pts.length >= 2) s += `<polyline points="${pts.map((p) => p.join(",")).join(" ")}" fill="none" stroke="#4fd18b" stroke-width="2"/>`;
    pts.forEach((p, i) => s += `<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="#4fd18b"/>`);
    s += `</svg>`;
    h += `<section class="dt-card dt-chart"><h3>最近 14 天</h3>${s}<div class="dt-legend"><span><i style="background:#ff7a59;opacity:.55"></i>消耗</span><span><i style="background:#f2c14e"></i>摄入</span><span><i style="background:#4fd18b"></i>体重</span></div></section>`;
  }
  return h;
}

function fillDietDates() {
  const dates = [...(index.diet || [])].sort();
  const sel = $("diet-date"); sel.innerHTML = "";
  for (const d of [...dates].reverse()) { const o = document.createElement("option"); o.value = d; o.textContent = dayLabel(d); sel.appendChild(o); }
  const t = todayStr();
  if (dates.length) sel.value = dates.includes(t) ? t : (dates.filter((d) => d <= t).pop() || dates[dates.length - 1]);
}
const dietCache = {};
async function renderDietTab() {
  const box = $("diet-body"), d = $("diet-date").value;
  if (!d) { box.innerHTML = '<p class="muted dg-empty">还没有推送过饮食数据。</p>'; return; }
  const draw = (j) => { box.innerHTML = renderDiet(j) + `<p class="muted small">更新于 ${esc(j.updated || "")}</p>`; box.dataset.shown = `${d}|${j.updated || ""}`; };
  if (dietCache[d]) { if (box.dataset.shown !== `${d}|${dietCache[d].updated || ""}`) draw(dietCache[d]); }
  else box.innerHTML = '<p class="muted">读取中…</p>';
  try {
    const j = await decryptJSON(await fetchText(`data/diet/${d}.json.enc`)); // 饮食一天会更新好几次，每次打开都在后台读一遍
    dietCache[d] = j;
    if ($("diet-date").value === d && box.dataset.shown !== `${d}|${j.updated || ""}`) draw(j);
  } catch { if (!dietCache[d]) box.innerHTML = '<p class="muted">这一天的饮食数据读取失败。</p>'; }
}

function toggle(id) {
  const q = dayData.quests.find((x) => x.id === id);
  if (q && lockReason(q) && !state.done[id]) return; // 强制休息日不能勾
  if (state.done[id]) delete state.done[id]; else state.done[id] = new Date().toISOString();
  saveState(); render();
  if (openId === id) fillSheet(id);
}
function fillSheet(id) {
  const q = dayData.quests.find((x) => x.id === id); const tp = TYPE[q.type] || TYPE.daily;
  const tag = $("d-type"); tag.textContent = tp.name; tag.className = `tag ${tp.cls}`;
  $("d-time").textContent = `+${q.coins || 0} 金币`;
  $("d-title").textContent = q.title;
  const links = (q.links || []).map((l) => `- [${l.label}](${l.url})`).join("\n");
  $("d-body").innerHTML = md([q.summary, q.detail, links].filter(Boolean).join("\n\n"));
  $("d-note").value = state.notes[id] || "";
  const go = $("d-link");
  go.classList.toggle("hidden", !q.link);
  go.textContent = q.link === "ja-recite" ? "去背诵卡片 →" : q.link === "digest" ? "打开每日资讯 →" : q.link === "ja-review" ? "去日语复习 →" : q.link === "diet" ? "打开饮食页 →" : "打开今日日语 →";
  go.onclick = () => gotoLink(q.link);
  const btn = $("d-toggle"); const done = !!state.done[id]; const lock = lockReason(q);
  btn.disabled = !!lock && !done;
  btn.textContent = lock && !done ? `🛌 ${lock}` : done ? "取消完成" : "完成任务";
  btn.className = `btn wide ${done || lock ? "" : "primary"}`;
}
function openQuest(id) { openId = id; fillSheet(id); $("sheet").classList.remove("hidden"); }
function closeSheets() { openId = null; document.querySelectorAll(".sheet").forEach((s) => s.classList.add("hidden")); }

// ---------- 钱包面板 ----------
function renderWallet() {
  const c = coinStats();
  $("w-balance").textContent = c.balance;
  $("w-stats").textContent = `累计获得 ${c.earned} · 已兑换奖励 ${c.spent} · 本周已得 ${c.weekGot}`;
  const ul = $("w-list"); ul.innerHTML = "";
  if (!wallet.spends.length) { ul.innerHTML = '<li class="muted">还没有兑换过奖励。好好努力，给自己攒一个！</li>'; return; }
  for (const s of wallet.spends) {
    const li = document.createElement("li");
    const t = new Date(s.at);
    li.innerHTML = `<div><div>${esc(s.note)}</div><div class="muted small">${fmt(t)} ${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}</div></div>
      <div class="spend-amt">−${s.amount}</div><button class="icon-btn" aria-label="删除这条">✕</button>`;
    li.querySelector("button").addEventListener("click", () => {
      if (!confirm(`删除“${s.note}”这条奖励？金币会退回余额。`)) return;
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
  if (!note) { msg.textContent = "写一下奖励自己什么"; return; }
  if (amount > coinStats().balance) { msg.textContent = "金币还不够，再努力一下"; return; }
  wallet.spends.unshift({ id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, at: new Date().toISOString(), amount, note });
  $("w-amount").value = ""; $("w-note").value = ""; msg.textContent = `已兑换努力的奖励：${note}（−${amount} 金币）`;
  saveWallet(); render(); renderWallet();
}

// ---------- 封存 ----------
function renderArchive() {
  const ul = $("archive-list"); ul.innerHTML = "";
  const list = [...(index.archives || [])].sort((a, b) => b.date.localeCompare(a.date));
  if (!list.length) { ul.innerHTML = '<li class="muted">还没有封存的日子。每天推送新任务时，前一天会自动封存成图片。</li>'; return; }
  for (const a of list) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${esc(dayLabel(a.date))}</span><span class="muted">${a.coins != null ? `<i class="coin" aria-hidden="true"></i>${a.coins} · ` : ""}完成 ${a.rate}%</span>`;
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
  [state, wallet, wishlist] = await Promise.all([loadState(day), loadWallet(), loadWishlist()]);
  await loadPrevGym();
  render(); renderArchive(); fillJaDates(); fillDietDates();
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
  for (const name of ["quests", "archive", "ja", "review", "diet", "digest"]) $(`tab-${name}`).classList.toggle("hidden", b.dataset.tab !== name);
  if (b.dataset.tab === "diet") renderDietTab();
  if (b.dataset.tab === "digest") renderDigest();
  if (b.dataset.tab === "review") renderReview();
  $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden");
  if (b.dataset.tab === "ja") { if ($("ja-date").value !== jaDate) renderJapanese(); } else stopAudio();
}));
$("ja-date").addEventListener("change", renderJapanese);
$("diet-date").addEventListener("change", renderDietTab);
$("kana-btn").addEventListener("click", () => setKana(document.body.classList.contains("hide-rt")));
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
  [LS.key, LS.token, LS.wallet, "quest.wish"].forEach(store.del);
  try { Object.keys(localStorage).filter((k) => k.startsWith(LS.cache)).forEach((k) => localStorage.removeItem(k)); } catch {}
  location.reload();
});

// ---------- 左右滑动切换标签：页面跟手移动，松手后滑出 / 滑入，不够距离就弹回 ----------
(() => {
  const main = $("main");
  const tabs = () => [...document.querySelectorAll(".tab")];
  const shown = () => document.querySelector(".tab-body:not(.hidden)");
  const EASE = "cubic-bezier(.2,.8,.2,1)";
  let idx = Math.max(0, tabs().findIndex((b) => b.classList.contains("active")));

  // 新页面从滑动方向的另一侧滑进来（点标签和滑动都用）
  function enter(dir) {
    const b = shown(); if (!b || !dir) return;
    b.style.transition = "none";
    b.style.transform = `translateX(${dir * 28}%)`;
    b.style.opacity = "0";
    b.getBoundingClientRect(); // 让浏览器先应用起始位置
    b.style.transition = `transform .28s ${EASE}, opacity .22s ease-out`;
    b.style.transform = "";
    b.style.opacity = "";
  }
  function centerTab(t) {
    const bar = document.querySelector(".tabs"), br = bar.getBoundingClientRect(), tr = t.getBoundingClientRect();
    bar.scrollTo({ left: bar.scrollLeft + (tr.left - br.left) - (br.width - tr.width) / 2, behavior: "smooth" });
  }
  tabs().forEach((t, i) => t.addEventListener("click", () => {
    const dir = i > idx ? 1 : i < idx ? -1 : 0;
    idx = i;
    enter(dir);
    centerTab(t);
    if (window.scrollX) window.scrollTo({ left: 0, top: window.scrollY });
  }));

  let sx = 0, sy = 0, t0 = 0, dx = 0, lock = null, cur = null;
  const reset = (el) => { el.style.transition = `transform .3s ${EASE}, opacity .3s`; el.style.transform = ""; el.style.opacity = ""; };
  main.addEventListener("touchstart", (e) => {
    lock = null; cur = null; dx = 0;
    if (e.touches.length !== 1 || document.querySelector(".sheet:not(.hidden)") ||
        e.target.closest(".tabs, .flashcard, .rv-card, input, textarea, select, svg, table")) { lock = "no"; return; }
    const t = e.touches[0]; sx = t.clientX; sy = t.clientY; t0 = Date.now(); cur = shown();
  }, { passive: true });
  main.addEventListener("touchmove", (e) => {
    if (lock === "no" || !cur) return;
    const t = e.touches[0], mx = t.clientX - sx, my = t.clientY - sy;
    if (!lock) {
      if (Math.abs(mx) < 8 && Math.abs(my) < 8) return;
      lock = Math.abs(mx) > Math.abs(my) * 1.2 ? "h" : "no";   // 先判断是横滑还是竖着滚动
      if (lock === "no") return;
      cur.style.transition = "none";
    }
    const n = tabs().length;
    const edge = (mx > 0 && idx === 0) || (mx < 0 && idx === n - 1);
    dx = edge ? mx * 0.25 : mx;                                   // 第一个 / 最后一个标签：有阻力
    cur.style.transform = `translateX(${dx}px)`;
    cur.style.opacity = String(1 - Math.min(0.45, Math.abs(dx) / 700));
  }, { passive: true });
  function end() {
    if (lock !== "h" || !cur) { lock = null; return; }
    const el = cur, w = main.clientWidth, speed = Math.abs(dx) / Math.max(1, Date.now() - t0);
    const next = tabs()[idx + (dx < 0 ? 1 : -1)];
    lock = null; cur = null;
    if (next && (Math.abs(dx) > w * 0.22 || (speed > 0.45 && Math.abs(dx) > 30))) {
      el.style.transition = "transform .16s ease-in, opacity .16s ease-in";
      el.style.transform = `translateX(${dx < 0 ? -w * 0.45 : w * 0.45}px)`;
      el.style.opacity = "0";
      setTimeout(() => {
        el.style.transition = "none"; el.style.transform = ""; el.style.opacity = "";
        next.click();                                            // 触发上面的 enter()，新页面滑进来、标签栏居中
        window.scrollTo({ top: 0, left: 0 });
      }, 150);
    } else reset(el);
  }
  main.addEventListener("touchend", end, { passive: true });
  main.addEventListener("touchcancel", () => { if (cur) reset(cur); lock = null; cur = null; }, { passive: true });
})();

boot().catch((e) => { document.body.innerHTML = `<p style="padding:24px;color:#ff6b6b">加载失败：${esc(String(e.message || e))}</p>`; });
