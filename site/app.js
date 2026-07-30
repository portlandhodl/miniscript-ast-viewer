/* MINISCRIPT://AST_BROWSER — frontend driver */
import init, { analyze, engine_info } from "./pkg/miniscript_ast_viewer.js";

/* ------------------------------------------------------------------ *
 *  Matrix backdrop: while the wasm engine boots, a swarm of glyphs
 *  flows naturally inside a giant bitcoin ₿ silhouette — a full-screen
 *  video-game style loader; once loaded, every glyph glides to its
 *  column and the classic waterfall rain takes over.
 * ------------------------------------------------------------------ */
function startRain() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches)
    return { loaded() {} };
  const canvas = document.getElementById("rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "アカサタナハマヤラワ0123456789ABCDEF·:+*<>";
  const fontSize = 15;
  const MORPH_MS = 1700; // total ₿ -> waterfall transition
  const CELL = 6; // ₿ silhouette sampling resolution (px)
  const rndGlyph = () => glyphs[(Math.random() * glyphs.length) | 0];
  const rndTone = () => {
    const r = Math.random();
    return r < 0.04 ? "#ffb000" : r < 0.15 ? "#b6ffb9" : r < 0.34 ? "#00b32d" : "#00ff41";
  };
  let w, h, cx, cy;
  let drops = [];
  let phase = "logo"; // logo -> morph -> rain
  let morphT0 = 0;
  let maskGrid, maskW, maskH, maskPts; // ₿ silhouette

  /* Rasterize a huge bitcoin ₿ and remember which cells it covers. */
  function buildMask() {
    const off = document.createElement("canvas");
    off.width = w;
    off.height = h;
    const o = off.getContext("2d", { willReadFrequently: true });
    const size = Math.min(w, h) * 0.62;
    o.fillStyle = "#fff";
    o.textAlign = "center";
    o.textBaseline = "middle";
    o.font = `900 ${size}px "Arial Black", Arial, Helvetica, sans-serif`;
    o.fillText("B", cx, cy);
    // find the glyph's true vertical extent so the two strokes of the
    // bitcoin sign overshoot both ends, whatever the font metrics are
    let probe = o.getImageData(0, 0, w, h).data;
    let top = h, bot = 0;
    for (let py = 0; py < h; py += 2)
      for (let px = 0; px < w; px += 6)
        if (probe[(py * w + px) * 4 + 3] > 40) {
          if (py < top) top = py;
          if (py > bot) bot = py;
        }
    const bw = o.measureText("B").width;
    const barW = Math.max(5, size * 0.05);
    const over = size * 0.07;
    o.fillRect(cx - bw * 0.26 - barW / 2, top - over, barW, bot - top + over * 2);
    o.fillRect(cx - bw * 0.02 - barW / 2, top - over, barW, bot - top + over * 2);
    const img = o.getImageData(0, 0, w, h).data;
    maskW = Math.ceil(w / CELL);
    maskH = Math.ceil(h / CELL);
    maskGrid = new Uint8Array(maskW * maskH);
    maskPts = [];
    for (let gy = 0; gy < maskH; gy++)
      for (let gx = 0; gx < maskW; gx++) {
        const px = Math.min(w - 1, gx * CELL + (CELL >> 1));
        const py = Math.min(h - 1, gy * CELL + (CELL >> 1));
        if (img[(py * w + px) * 4 + 3] > 40) {
          maskGrid[gy * maskW + gx] = 1;
          maskPts.push([gx * CELL + (CELL >> 1), gy * CELL + (CELL >> 1)]);
        }
      }
  }

  const inside = (x, y) => {
    const gx = (x / CELL) | 0;
    const gy = (y / CELL) | 0;
    return gx >= 0 && gy >= 0 && gx < maskW && gy < maskH && maskGrid[gy * maskW + gx] === 1;
  };

  /* (Re)seed a glyph at a random spot inside the ₿. */
  function spawn(d) {
    const p = maskPts[(Math.random() * maskPts.length) | 0];
    d.x = p[0] + (Math.random() - 0.5) * CELL;
    d.y = p[1] + (Math.random() - 0.5) * CELL;
    d.vx = (Math.random() - 0.5) * 0.8;
    d.vy = (Math.random() - 0.5) * 0.8;
    d.bias = Math.random() * Math.PI * 2;
    d.tone = rndTone();
    d.stuck = 0;
    return d;
  }

  function resize() {
    w = canvas.width = innerWidth;
    h = canvas.height = innerHeight;
    cx = w / 2;
    cy = h / 2;
    buildMask();
    const nCols = Math.ceil(w / fontSize);
    // enough glyphs to fill the ₿ (~1 per 110 px²), while keeping the
    // eventual waterfall in the 2..6-drops-per-column range
    const target = Math.max(
      nCols * 2,
      Math.min(nCols * 6, 1500, Math.round((maskPts.length * CELL * CELL) / 110))
    );
    drops.length = Math.min(drops.length, target);
    for (let i = 0; i < target; i++) {
      let d = drops[i];
      if (!d)
        d = drops[i] = {
          glyph: rndGlyph(),
          x: 0, y: Math.random() * h, vx: 0, vy: 0, bias: 0, tone: "#00ff41", stuck: 0,
          // morph endpoints (captured when the engine comes online)
          sx: 0, sy: 0, ty: Math.random() * h, delay: Math.random() * 500,
        };
      d.col = i % nCols; // rain column
      if (phase === "logo" && !inside(d.x, d.y)) spawn(d);
    }
    if (phase === "morph") {
      // resize mid-transition: snap straight into the waterfall
      for (const d of drops) d.y = d.ty;
      phase = "rain";
    }
  }
  resize();
  addEventListener("resize", resize);

  function drawLogo(t) {
    for (const d of drops) {
      // smooth pseudo-turbulent drift + a whisper of pull toward the core,
      // so the swarm keeps circulating inside the ₿
      const a =
        Math.sin(d.x * 0.006 + t * 0.00035) * 1.8 +
        Math.cos(d.y * 0.007 - t * 0.00027) * 1.8 +
        d.bias * 0.35;
      d.vx += Math.cos(a) * 0.09 + (cx - d.x) * 0.00006;
      d.vy += Math.sin(a) * 0.09 + (cy - d.y) * 0.00006;
      d.vx *= 0.92;
      d.vy *= 0.92;
      const nx = d.x + d.vx;
      const ny = d.y + d.vy;
      if (inside(nx, ny)) {
        d.x = nx;
        d.y = ny;
        d.stuck = 0;
      } else {
        // bounced off the silhouette edge — let the flow re-aim us
        d.vx *= -0.4;
        d.vy *= -0.4;
        if (++d.stuck > 40) spawn(d); // wedged in a crevice: reseed
      }
      if (Math.random() < 0.03) d.glyph = rndGlyph();
      if (Math.random() < 0.004) d.tone = rndTone();
      ctx.fillStyle = d.tone;
      ctx.fillText(d.glyph, d.x, d.y);
    }
  }

  function drawMorph(t) {
    let done = true;
    for (const d of drops) {
      const k = Math.min(1, Math.max(0, (t - morphT0 - d.delay) / (MORPH_MS - 500)));
      if (k < 1) done = false;
      const e = k * k * (3 - 2 * k); // smoothstep
      if (Math.random() < 0.05) d.glyph = rndGlyph();
      ctx.fillStyle = Math.random() < 0.12 ? "#b6ffb9" : "#00ff41";
      ctx.fillText(d.glyph, d.sx + (d.col * fontSize - d.sx) * e, d.sy + (d.ty - d.sy) * e);
    }
    if (done) {
      for (const d of drops) d.y = d.ty;
      phase = "rain";
    }
  }

  function drawRain() {
    for (const d of drops) {
      if (Math.random() < 0.06) d.glyph = rndGlyph();
      ctx.fillStyle = Math.random() < 0.06 ? "#b6ffb9" : "#00ff41";
      ctx.fillText(d.glyph, d.col * fontSize, d.y);
      d.y = d.y > h && Math.random() > 0.975 ? 0 : d.y + fontSize;
    }
  }

  let last = 0;
  function frame(t) {
    if (!document.hidden && t - last > 50) {
      last = t;
      ctx.fillStyle = "rgba(0,0,0,0.06)";
      ctx.fillRect(0, 0, w, h);
      ctx.font = `${fontSize}px monospace`;
      if (phase === "logo") drawLogo(t);
      else if (phase === "morph") drawMorph(t);
      else drawRain();
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return {
    // engine online: capture each glyph's spot in the ₿ and send it
    // gliding to its waterfall column
    loaded() {
      if (phase !== "logo") return;
      morphT0 = performance.now();
      for (const d of drops) {
        d.sx = d.x;
        d.sy = d.y;
        d.ty = Math.random() * h;
        d.delay = Math.random() * 500;
      }
      phase = "morph";
    },
  };
}

/* ------------------------------------------------------------------ *
 *  Examples (all verified against the engine)
 * ------------------------------------------------------------------ */
const K = {
  A: "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261",
  B: "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
  C: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  H: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  XP: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
  TI: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
  XG: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  X2: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
};
const EXAMPLES = [
  ["policy · escrow with timelock", `or(pk(${K.A}),and(pk(${K.B}),older(144)))`],
  ["policy · vault (2-of-2 or recovery)", `or(and(pk(${K.A}),pk(${K.B})),and(pk(${K.C}),older(12960)))`],
  ["policy · HTLC swap", `or(and(pk(${K.A}),sha256(${K.H})),and(pk(${K.B}),after(800000)))`],
  ["policy · 2-of-3 threshold", `thresh(2,pk(${K.A}),pk(${K.B}),pk(${K.C}))`],
  ["descriptor · wsh timelocked key", `wsh(and_v(v:pk(${K.A}),older(144)))`],
  ["descriptor · wsh 2-of-3 sortedmulti", `wsh(sortedmulti(2,${K.A},${K.B},${K.C}))`],
  ["descriptor · ranged xpub wallet", `wsh(and_v(v:pk(${K.XP}/0/*),older(40320)))`],
  ["descriptor · taproot tree", `tr(${K.TI},{pk(${K.XG}),pk(${K.X2})})`],
];

/* ------------------------------------------------------------------ *
 *  DOM helpers
 * ------------------------------------------------------------------ */
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

function copyBtn(getText) {
  const b = el("button", "copy", "⧉");
  b.title = "copy to clipboard";
  b.addEventListener("click", async (ev) => {
    ev.stopPropagation();
    try {
      await navigator.clipboard.writeText(getText());
      b.textContent = "✓";
    } catch {
      const ta = el("textarea");
      ta.value = getText();
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      b.textContent = "✓";
    }
    setTimeout(() => (b.textContent = "⧉"), 900);
  });
  return b;
}

function codeBox(label, text, extraCls) {
  const wrap = el("div");
  if (label) wrap.appendChild(el("div", "code-label", label));
  const box = el("div", "code-box" + (extraCls ? " " + extraCls : ""), text);
  box.appendChild(copyBtn(() => text));
  wrap.appendChild(box);
  return wrap;
}

/* ------------------------------------------------------------------ *
 *  Tree rendering + interaction
 * ------------------------------------------------------------------ */
const FRAG_CATEGORY = [
  [/^pk|^key|^pkh$|^wpkh$|^internal_key$|^raw_pkh/, "cat-key"],
  [/^(older|after)$/, "cat-time"],
  [/^(sha256|hash256|ripemd160|hash160)$/, "cat-hash"],
  [/^(alt|swap|check|dupif|verify|nonzero|zero_not_equal)/, "cat-wrap"],
];
const fragCat = (frag) => {
  for (const [re, cls] of FRAG_CATEGORY) if (re.test(frag)) return cls;
  return "";
};

let selectedRow = null;
let activeTree = null; // { label, root }
let selectedPathRow = null; // active row in the spend-paths list

function renderNode(node, byId) {
  const li = el("li");
  const hasKids = node.children && node.children.length > 0;

  const row = el("div", "node-row");
  row.dataset.id = node.id;
  row.setAttribute("role", "treeitem");
  row._ast = node;

  const twisty = el("span", "twisty", hasKids ? "▼" : "·");
  row.appendChild(twisty);
  row.appendChild(el("span", "frag " + fragCat(node.fragment), node.fragment));
  if (node.typeBase) row.appendChild(el("span", "type-badge", node.typeBase));
  if (node.value !== undefined) {
    const v = el("span", "val", node.value);
    v.title = node.value;
    row.appendChild(v);
  }

  row.addEventListener("click", () => {
    selectRow(row);
    if (hasKids) toggleLi(li);
  });
  li.appendChild(row);
  byId.set(node.id, { row, li, node });

  if (hasKids) {
    const ul = el("ul");
    ul.setAttribute("role", "group");
    for (const child of node.children) ul.appendChild(renderNode(child, byId));
    li.appendChild(ul);
    li.setAttribute("aria-expanded", "true");
  }
  return li;
}

function toggleLi(li, force) {
  const collapsed = force !== undefined ? force : !li.classList.contains("collapsed");
  li.classList.toggle("collapsed", collapsed);
  const t = li.querySelector(":scope > .node-row .twisty");
  if (t && t.textContent !== "·") t.textContent = collapsed ? "▶" : "▼";
  li.setAttribute("aria-expanded", String(!collapsed));
}

function setTreeDepth(li, depth) {
  // expand all below depth, collapse at depth
  const kids = li.querySelectorAll(":scope > ul > li");
  toggleLi(li, depth <= 0);
  kids.forEach((k) => setTreeDepth(k, depth - 1));
}

function selectRow(row) {
  if (selectedRow) selectedRow.classList.remove("selected");
  clearPathHighlight();
  selectedRow = row;
  row.classList.add("selected");
  renderNodeDetail(row._ast);
  highlightCodepath(row._ast);
}

/* ------------------------------------------------------------------ *
 *  Codepath visualization + spend analysis
 * ------------------------------------------------------------------ */
function ancestorIds(id) {
  const parts = id.split(".");
  const out = [];
  for (let i = 1; i < parts.length; i++) out.push(parts.slice(0, i).join("."));
  return out;
}

function jumpTo(id) {
  const entry = $("tree-container")._byId?.get(id);
  if (!entry) return;
  let li = entry.li;
  while (li) {
    toggleLi(li, false);
    li = li.parentElement?.closest("li");
  }
  selectRow(entry.row);
  entry.row.scrollIntoView({ block: "center", behavior: "smooth" });
}

const fragBase = (f) => f.split(/[\s(]/)[0];
const WRAPPERS = ["alt", "swap", "check", "dupif", "verify", "nonzero", "zero_not_equal"];

/** ids that must be satisfied assuming `node` must be satisfied (excl. itself) */
function downReq(node) {
  const b = fragBase(node.fragment);
  const kids = node.children || [];
  const out = [];
  const req = (n) => out.push(n.id, ...downReq(n));
  if (["and_v", "and_b", "and"].includes(b)) kids.forEach(req);
  else if (b === "and_or") { req(kids[0]); req(kids[1]); }
  else if (WRAPPERS.includes(b) && kids[0]) req(kids[0]);
  return out;
}

/** Walk up from `node`: siblings forced by and/and_or ancestors + notes. */
function computeSpend(node, byId) {
  const required = new Set(downReq(node));
  const notes = [];
  let cur = node;
  while (cur.id.includes(".")) {
    const pid = cur.id.slice(0, cur.id.lastIndexOf("."));
    const p = byId.get(pid)?.node;
    if (!p) break;
    const b = fragBase(p.fragment);
    const idx = Number(cur.id.slice(pid.length + 1));
    const sibReq = (s) => { required.add(s.id); downReq(s).forEach((x) => required.add(x)); };
    if (["and_v", "and_b", "and"].includes(b)) {
      (p.children || []).forEach((c, i) => i !== idx && sibReq(c));
    } else if (b === "and_or") {
      if (idx === 0) sibReq(p.children[1]);
      else if (idx === 1) sibReq(p.children[0]);
      else notes.push("spend via the ELSE arm: the left arm of this and_or is NOT satisfied");
    } else if (["thresh", "multi", "multi_a", "sortedmulti"].includes(b)) {
      const m = p.fragment.match(/k=(\d+),n=(\d+)/);
      if (m && Number(m[1]) > 1)
        notes.push(`${b} needs ${m[1]}-of-${m[2]} here — pick ${m[1] - 1} more sibling(s)`);
    }
    cur = p;
  }
  required.delete(node.id);
  return { required: [...required], notes };
}

/** Byte segments of `node`'s own opcodes (its range minus children's ranges). */
function ownSegments(node) {
  if (!node.scriptRange) return [];
  const kids = (node.children || [])
    .filter((c) => c.scriptRange)
    .sort((a, b) => a.scriptRange[0] - b.scriptRange[0]);
  const segs = [];
  let cur = node.scriptRange[0];
  for (const k of kids) {
    if (k.scriptRange[0] > cur) segs.push([cur, k.scriptRange[0]]);
    cur = Math.max(cur, k.scriptRange[1]);
  }
  if (cur < node.scriptRange[1]) segs.push([cur, node.scriptRange[1]]);
  return segs;
}

function renderScriptViz(tree) {
  const viz = $("script-viz");
  viz.innerHTML = "";
  if (!tree.script) {
    viz.hidden = true;
    return;
  }
  viz.hidden = false;
  const strip = el("div", "viz-strip");
  for (const ins of tree.script.instructions) {
    const s = el("span", "viz-op", ins.text);
    s.dataset.start = ins.start;
    s.dataset.end = ins.end;
    s.title = `${ins.text}   [${ins.start}..${ins.end}]`;
    s.addEventListener("click", () => {
      // select the deepest AST node whose range covers this instruction
      const byId = $("tree-container")._byId;
      let best = null;
      for (const { node } of byId.values()) {
        const r = node.scriptRange;
        if (!r || r[0] > ins.start || ins.end > r[1]) continue;
        if (!best || r[1] - r[0] < best.scriptRange[1] - best.scriptRange[0]) best = node;
      }
      if (best) jumpTo(best.id);
    });
    strip.appendChild(s);
  }
  viz.appendChild(strip);
  viz.appendChild(
    el("div", "viz-legend", "click an opcode to locate its AST node · select an AST node: green = its codepath · amber = ancestor routing opcodes")
  );
}

/** Highlight the activated codepath of the selected node in the script viz. */
function highlightCodepath(node) {
  const ops = $("script-viz").querySelectorAll(".viz-op");
  ops.forEach((o) => o.classList.remove("hl-own", "hl-path"));
  if (!node.scriptRange) return;
  const pathSegs = [];
  for (const pid of ancestorIds(node.id)) {
    const p = $("tree-container")._byId?.get(pid)?.node;
    if (p) pathSegs.push(...ownSegments(p));
  }
  const inSegs = (s, e, segs) => segs.some(([a, b]) => a <= s && e <= b);
  const [rs, re] = node.scriptRange;
  ops.forEach((o) => {
    const s = Number(o.dataset.start);
    const e = Number(o.dataset.end);
    if (rs <= s && e <= re) o.classList.add("hl-own");
    else if (inSegs(s, e, pathSegs)) o.classList.add("hl-path");
  });
}

/* ------------------------------------------------------------------ *
 *  Spend-path permutations: every distinct way to satisfy the active
 *  tree. Selecting a path lights up the opcodes it executes (green =
 *  conditions, amber = routing) and the AST members it uses.
 * ------------------------------------------------------------------ */
function leafLabel(node) {
  const f = fragBase(node.fragment);
  const v = node.value;
  if (v === undefined) return f;
  if (v.length <= 12) return `${f}(${v})`;
  return `${f}(…${v.slice(-8)})`;
}

/** Highlight every opcode executed by a spend path (multi-leaf codepath). */
function highlightSpendPath(leaves) {
  const ops = $("script-viz").querySelectorAll(".viz-op");
  ops.forEach((o) => o.classList.remove("hl-own", "hl-path"));
  const ownSegs = [];
  const pathSegs = [];
  const anc = new Set();
  for (const n of leaves) {
    if (n.scriptRange) ownSegs.push(n.scriptRange);
    for (const pid of ancestorIds(n.id)) anc.add(pid);
  }
  for (const pid of anc) {
    const p = $("tree-container")._byId?.get(pid)?.node;
    if (p) pathSegs.push(...ownSegments(p));
  }
  const inSegs = (s, e, segs) => segs.some(([a, b]) => a <= s && e <= b);
  ops.forEach((o) => {
    const s = Number(o.dataset.start);
    const e = Number(o.dataset.end);
    if (inSegs(s, e, ownSegs)) o.classList.add("hl-own");
    else if (inSegs(s, e, pathSegs)) o.classList.add("hl-path");
  });
}

function clearPathHighlight() {
  selectedPathRow = null;
  $("paths-body")
    .querySelectorAll(".path-row.active")
    .forEach((r) => r.classList.remove("active"));
  $("tree-container")
    .querySelectorAll(".node-row.path-leaf, .node-row.path-route")
    .forEach((r) => r.classList.remove("path-leaf", "path-route"));
}

/** (De)select a spend path: highlight its opcodes + AST members. */
function togglePath(row, path) {
  const wasActive = row.classList.contains("active");
  clearPathHighlight();
  if (wasActive) {
    // deselecting: restore the viz to the selected node's codepath
    if (selectedRow) highlightCodepath(selectedRow._ast);
    return;
  }
  row.classList.add("active");
  selectedPathRow = row;
  const byId = $("tree-container")._byId;
  // path selection supersedes the per-node "spend with" markings
  $("tree-container")
    .querySelectorAll(".node-row.spend-req")
    .forEach((r) => r.classList.remove("spend-req"));
  const leaves = path.nodes.map((id) => byId.get(id)).filter(Boolean);
  const anc = new Set();
  for (const { li, node, row: r } of leaves) {
    // expand collapsed ancestors so every highlighted row is visible
    let p = li.parentElement?.closest("li");
    while (p) {
      toggleLi(p, false);
      p = p.parentElement?.closest("li");
    }
    r.classList.add("path-leaf");
    for (const pid of ancestorIds(node.id)) anc.add(pid);
  }
  for (const pid of anc) byId.get(pid)?.row.classList.add("path-route");
  highlightSpendPath(leaves.map((e) => e.node));
  row.scrollIntoView({ block: "nearest" });
}

function renderPaths(tree) {
  const body = $("paths-body");
  body.innerHTML = "";
  selectedPathRow = null;
  const pl = tree.paths;
  if (!pl || !pl.items.length) {
    body.appendChild(el("span", "dim", "no spend paths for this tree"));
    return;
  }
  const byId = $("tree-container")._byId || new Map();
  pl.items.forEach((p, i) => {
    const row = el("button", "path-row");
    row.appendChild(el("span", "path-num", `#${i + 1}`));
    const nodes = p.nodes.map((id) => byId.get(id)?.node).filter(Boolean);
    if (nodes.length) {
      for (const n of nodes)
        row.appendChild(el("span", "path-chip " + fragCat(n.fragment), leafLabel(n)));
    } else {
      row.appendChild(el("span", "dim", "always satisfiable"));
    }
    row.title = "highlight this spend path";
    row.addEventListener("click", () => togglePath(row, p));
    body.appendChild(row);
  });
  const total = pl.capped && pl.total >= 1000000 ? "1000000+" : pl.total;
  const head = pl.capped
    ? `showing first ${pl.items.length} of ${total} paths`
    : `${pl.total} way(s) to spend`;
  body.appendChild(
    el("div", "paths-note", head + " · select a path: green = conditions · amber = routing opcodes")
  );
}

function renderNodeDetail(node) {
  const d = $("node-detail");
  const container = $("tree-container");
  const byId = container._byId || new Map();
  d.innerHTML = "";
  const kv = el("div", "kv");
  const add = (k, v, bright, copyText) => {
    kv.appendChild(el("div", "k", k));
    const ve = el("div", "v" + (bright ? " bright" : ""), v);
    if (copyText) ve.appendChild(copyBtn(() => copyText));
    kv.appendChild(ve);
  };
  add("fragment", node.fragment, true);
  if (node.typeBase) add("type", node.typeBase);
  if (node.value !== undefined) add("value", node.value, false, node.value);
  if (node.template) add("template", node.template);
  if (node.scriptAsm) add("script", node.scriptAsm, false, node.scriptAsm);
  if (node.scriptRange) add("bytes", `[${node.scriptRange[0]}..${node.scriptRange[1]}]`);
  add("path", node.id);
  add("meaning", node.detail);
  d.appendChild(kv);

  // ---- parents (clickable breadcrumb) ----
  const anc = ancestorIds(node.id);
  if (anc.length) {
    const row = el("div", "chip-row");
    row.appendChild(el("span", "chip-label", "parents:"));
    for (const pid of anc) {
      const e = byId.get(pid);
      if (!e) continue;
      const c = el("button", "chip parent", e.node.fragment);
      c.title = `path ${pid}`;
      c.addEventListener("click", () => jumpTo(pid));
      row.appendChild(c);
    }
    d.appendChild(row);
  }

  // ---- spend path: required siblings/subtrees + branch notes ----
  const { required, notes } = computeSpend(node, byId);
  container
    .querySelectorAll(".node-row.spend-req")
    .forEach((r) => r.classList.remove("spend-req"));
  for (const id of required) byId.get(id)?.row.classList.add("spend-req");
  if (required.length) {
    const row = el("div", "chip-row");
    row.appendChild(el("span", "chip-label", "spend with:"));
    for (const id of required) {
      const e = byId.get(id);
      if (!e) continue;
      const c = el("button", "chip spend", e.node.fragment);
      c.title = `path ${id}`;
      c.addEventListener("click", () => jumpTo(id));
      row.appendChild(c);
    }
    d.appendChild(row);
  }
  for (const n of notes) d.appendChild(el("div", "note", "⚠ " + n));
}

function visibleRows() {
  return [...$("tree-container").querySelectorAll(".node-row")].filter(
    (r) => r.offsetParent !== null
  );
}

function keyboardNav(e) {
  if (!selectedRow) {
    const first = $("tree-container").querySelector(".node-row");
    if (first) selectRow(first);
    return;
  }
  const rows = visibleRows();
  const idx = rows.indexOf(selectedRow);
  const li = selectedRow.closest("li");
  const hasKids = !!li.querySelector(":scope > ul");
  const collapsed = li.classList.contains("collapsed");

  switch (e.key) {
    case "ArrowDown":
      if (rows[idx + 1]) selectRow(rows[idx + 1]);
      break;
    case "ArrowUp":
      if (rows[idx - 1]) selectRow(rows[idx - 1]);
      break;
    case "ArrowRight":
      if (hasKids && collapsed) toggleLi(li, false);
      else if (hasKids) {
        const child = li.querySelector(":scope > ul > li > .node-row");
        if (child) selectRow(child);
      }
      break;
    case "ArrowLeft":
      if (hasKids && !collapsed) toggleLi(li, true);
      else {
        const parent = li.parentElement?.closest("li")?.querySelector(":scope > .node-row");
        if (parent) selectRow(parent);
      }
      break;
    case "Enter":
    case " ":
      if (hasKids) toggleLi(li);
      break;
    default:
      return;
  }
  e.preventDefault();
  selectedRow.scrollIntoView({ block: "nearest" });
}

/* ------------------------------------------------------------------ *
 *  Result rendering
 * ------------------------------------------------------------------ */
function kvRows(parent, rows) {
  const kv = el("div", "kv");
  for (const [k, v, bright] of rows) {
    if (v === null || v === undefined) continue;
    kv.appendChild(el("div", "k", k));
    kv.appendChild(el("div", "v" + (bright ? " bright" : ""), String(v)));
  }
  parent.appendChild(kv);
}

function renderResult(r) {
  $("result").hidden = false;

  // warnings
  const w = $("warnings");
  if (r.warnings?.length) {
    w.hidden = false;
    w.innerHTML = "";
    r.warnings.forEach((msg) => w.appendChild(el("div", null, msg)));
  } else w.hidden = true;

  // descriptor panel
  const db = $("descriptor-body");
  db.innerHTML = "";
  db.appendChild(codeBox(r.inputKind === "policy" ? "COMPILED DESCRIPTOR (wsh)" : "DESCRIPTOR", r.descriptor));
  if (r.taprootDescriptor) db.appendChild(codeBox("TAPROOT COMPILATION (compile_tr)", r.taprootDescriptor, "tap"));
  if (r.addressMainnet) db.appendChild(codeBox(r.hasWildcard ? "ADDRESS · mainnet (index 0)" : "ADDRESS · mainnet", r.addressMainnet));
  if (r.addressTestnet) db.appendChild(codeBox(r.hasWildcard ? "ADDRESS · testnet (index 0)" : "ADDRESS · testnet", r.addressTestnet));

  // stats panel
  const sb = $("stats-body");
  sb.innerHTML = "";
  kvRows(sb, [
    ["input kind", r.inputKind, true],
    ["descriptor type", r.descriptorType],
    ["script size", r.stats.scriptSize != null ? r.stats.scriptSize + " bytes" : null],
    ["static opcodes", r.stats.staticOps],
    ["keys", r.stats.nKeys],
    ["max satisfaction", r.stats.maxSatisfactionWeight != null ? r.stats.maxSatisfactionWeight + " WU" : null],
    ["rel. timelocks", r.timelocks.relative.length ? r.timelocks.relative.join(", ") : null],
    ["abs. timelocks", r.timelocks.absolute.length ? r.timelocks.absolute.join(", ") : null],
    ["ranged", r.hasWildcard ? "yes (…/*)" : null],
  ]);

  // script panel
  const sp = $("script-body");
  sp.innerHTML = "";
  if (r.scriptHex) sp.appendChild(codeBox("HEX", r.scriptHex));
  if (r.scriptAsm) {
    sp.appendChild(el("div", "code-label", "ASSEMBLY"));
    const asm = el("div", "code-box asm", r.scriptAsm);
    asm.appendChild(copyBtn(() => r.scriptAsm));
    sp.appendChild(asm);
  }
  if (!r.scriptHex) sp.appendChild(el("span", "dim", "no concrete script (keys cannot be derived)"));

  // trees
  const tabs = $("tree-tabs");
  tabs.innerHTML = "";
  activeTree = null;
  r.trees.forEach((tree, i) => {
    const b = el("button", null, tree.label);
    b.setAttribute("role", "tab");
    b.addEventListener("click", () => {
      tabs.querySelectorAll("button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      showTree(tree);
    });
    tabs.appendChild(b);
    if (i === r.trees.length - 1) {
      // default: last tree (the compiled miniscript for policy input)
      b.classList.add("active");
      showTree(tree);
    }
  });

  // expand / collapse tools
  $("expand-all").onclick = () =>
    $("tree-container").querySelectorAll("li").forEach((li) => toggleLi(li, false));
  $("collapse-all").onclick = () => {
    const rootLi = $("tree-container").querySelector(".tree > li");
    if (rootLi) setTreeDepth(rootLi, 0);
  };
}

function showTree(tree) {
  activeTree = tree;
  const container = $("tree-container");
  container.innerHTML = "";
  renderScriptViz(tree);
  const byId = new Map();
  const ul = el("ul", "tree");
  ul.setAttribute("role", "tree");
  ul.appendChild(renderNode(tree.root, byId));
  container.appendChild(ul);
  container._byId = byId;
  renderPaths(tree);
  // default: expand two levels
  const rootLi = ul.firstElementChild;
  setTreeDepth(rootLi, 2);
  const firstRow = ul.querySelector(".node-row");
  if (firstRow) selectRow(firstRow);
}

/* ------------------------------------------------------------------ *
 *  Analyze flow
 * ------------------------------------------------------------------ */
function runAnalysis() {
  const input = $("input").value;
  const mode = $("mode").value;
  const errBox = $("error");
  errBox.hidden = true;
  try {
    const result = JSON.parse(analyze(input, mode));
    renderResult(result);
    // shareable URL
    const h = new URLSearchParams();
    h.set("q", input);
    if (mode !== "auto") h.set("mode", mode);
    history.replaceState(null, "", "#" + h.toString());
  } catch (e) {
    $("result").hidden = true;
    errBox.hidden = false;
    errBox.textContent = e.message || String(e);
  }
}

/* ------------------------------------------------------------------ *
 *  Boot
 * ------------------------------------------------------------------ */
async function boot() {
  const rain = startRain();
  const boot = $("boot-status");
  const loader = $("loader");

  // examples dropdown
  const sel = $("examples");
  for (const [label, value] of EXAMPLES) sel.appendChild(new Option(label, value));
  sel.addEventListener("change", () => {
    if (sel.value) {
      $("input").value = sel.value;
      runAnalysis();
    }
    sel.value = "";
  });

  try {
    // keep the vortex on screen for a moment even when the wasm is cached
    await Promise.all([init(), new Promise((r) => setTimeout(r, 800))]);
    boot.textContent = "[ wasm module online — engine ready ]";
    boot.classList.add("ok");
    $("run").disabled = false;
    $("engine-info").textContent = "engine: " + engine_info();
    const ls = $("loader-status");
    if (ls) ls.textContent = "[ engine online — entering the matrix ]";
    rain.loaded();
    document.body.classList.add("ready");
    setTimeout(() => loader?.remove(), 1100);
  } catch (e) {
    boot.textContent = "[ FAILED to load wasm module: " + e + " ]";
    boot.classList.add("fail");
    const ls = $("loader-status");
    if (ls) {
      ls.textContent = "[ FAILED to load wasm module: " + e + " ]";
      ls.classList.add("fail");
    }
    return;
  }

  $("run").addEventListener("click", runAnalysis);
  $("input").addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runAnalysis();
  });
  $("tree-container").addEventListener("keydown", keyboardNav);

  // deep-link: #q=...&mode=...
  if (location.hash.length > 1) {
    const h = new URLSearchParams(location.hash.slice(1));
    if (h.get("q")) {
      $("input").value = h.get("q");
      if (h.get("mode")) $("mode").value = h.get("mode");
      runAnalysis();
    }
  }
}

boot();
