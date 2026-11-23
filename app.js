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
  $("wallet-btn").textContent = `🪙 ${c.balance}`;
  $("coin-week").textContent = `本周已得 🪙 ${c.weekGot}`;
  $("coin-day").textContent = `今日 ${c.dayGot} / ${c.dayAll} · 完成 ${doneN}/${active.length}`;
  $("xp-bar").style.width = c.dayAll ? `${Math.min(100, (c.dayGot / c.dayAll) * 100)}%` : "0";

  const ul = $("quest-list"); ul.innerHTML = "";
  for (const q of qs) {
    const tp = TYPE[q.type] || TYPE.daily;
    const lock = lockReason(q);
    const li = document.createElement("li");
    li.className = `quest ${tp.cls}${state.done[q.id] ? " done" : ""}${lock ? " locked" : ""}`;
    li.innerHTML = `
      <button class="check-btn" aria-label="${lock ? "强制休息，不能勾选" : "完成"}"${lock ? " disabled" : ""}>${lock ? "休" : state.done[q.id] ? "✓" : ""}</button>
      <div class="q-main">
        <div class="q-meta"><span class="q-type">${tp.name}</span>${q.time ? `<span>推荐 ${esc(q.time)}</span>` : ""}${state.notes[q.id] ? '<span class="q-note">✎ 有补充</span>' : ""}</div>
        <div class="q-title">${esc(q.title)}</div>
        ${lock ? `<div class="q-sum lock-msg">${esc(lock)}</div>` : q.summary ? `<div class="q-sum">${esc(q.summary)}</div>` : ""}
      </div>
      <div class="q-xp">${lock ? "休息" : `+${q.coins || 0} 🪙`}</div>`;
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
const hasAudio = () => index.ja_audio && index.ja_audio === jaDate;
function stopAudio() {
  if (curAudio) { curAudio.pause(); curAudio = null; }
  if (curAudioEl) { curAudioEl.classList.remove("playing"); curAudioEl = null; }
}
async function playAudio(file, el) {
  if (!file || !hasAudio()) return;
  if (curAudioEl === el && curAudio) { stopAudio(); return; } // 再点一下停止
  stopAudio();
  try {
    const k = `${jaDate}/${file}`;
    if (!audioUrls[k]) {
      const bytes = await decryptBytes(await fetchText(`data/ja-audio/${jaDate}/${file}.enc`));
      audioUrls[k] = URL.createObjectURL(new Blob([bytes], { type: "audio/mpeg" }));
    }
    curAudio = new Audio(audioUrls[k]); curAudioEl = el || null;
    if (curAudioEl) curAudioEl.classList.add("playing");
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
      <button class="btn ghost small-btn" id="ja-zh-all">显示全部翻译</button>
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
  if (link === "digest") {
    closeSheets();
    document.querySelector('.tab[data-tab="digest"]').click();
    window.scrollTo({ top: 0, behavior: "smooth" });
  } else gotoJapanese(link);
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
  $("d-time").textContent = [q.time && `推荐 ${q.time}`, `+${q.coins || 0} 金币`].filter(Boolean).join(" · ");
  $("d-title").textContent = q.title;
  const links = (q.links || []).map((l) => `- [${l.label}](${l.url})`).join("\n");
  $("d-body").innerHTML = md([q.summary, q.detail, links].filter(Boolean).join("\n\n"));
  $("d-note").value = state.notes[id] || "";
  const go = $("d-link");
  go.classList.toggle("hidden", !q.link);
  go.textContent = q.link === "ja-recite" ? "去背诵卡片 →" : q.link === "digest" ? "打开每日资讯 →" : "打开今日日语 →";
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
  $("w-stats").textContent = `累计获得 ${c.earned} · 累计花费 ${c.spent} · 本周已得 ${c.weekGot}`;
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
  [state, wallet, wishlist] = await Promise.all([loadState(day), loadWallet(), loadWishlist()]);
  await loadPrevGym();
  render(); renderArchive(); fillJaDates();
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
  for (const name of ["quests", "archive", "ja", "digest"]) $(`tab-${name}`).classList.toggle("hidden", b.dataset.tab !== name);
  if (b.dataset.tab === "digest") renderDigest();
  $("archive-list").classList.remove("hidden"); $("archive-view").classList.add("hidden");
  if (b.dataset.tab === "ja") { if ($("ja-date").value !== jaDate) renderJapanese(); } else stopAudio();
}));
$("ja-date").addEventListener("change", renderJapanese);
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
boot().catch((e) => { document.body.innerHTML = `<p style="padding:24px;color:#ff6b6b">加载失败：${esc(String(e.message || e))}</p>`; });
