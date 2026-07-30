/* MINISCRIPT://AST_BROWSER — frontend driver */
import init, { analyze, engine_info } from "./pkg/miniscript_ast_viewer.js";

/* ------------------------------------------------------------------ *
 *  Matrix backdrop: a vortex of characters swirls while the wasm
 *  engine boots; once loaded, every glyph glides to its column and
 *  the classic waterfall rain takes over.
 * ------------------------------------------------------------------ */
function startRain() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches)
    return { loaded() {} };
  const canvas = document.getElementById("rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "アカサタナハマヤラワ0123456789ABCDEF·:+*<>";
  const fontSize = 15;
  const MORPH_MS = 1700; // total vortex -> waterfall transition
  const rndGlyph = () => glyphs[(Math.random() * glyphs.length) | 0];
  let w, h, cx, cy, maxRad;
  let drops = []; // one per rain column
  let phase = "vortex"; // vortex -> morph -> rain
  let morphT0 = 0;

  function resize() {
    w = canvas.width = innerWidth;
    h = canvas.height = innerHeight;
    cx = w / 2;
    cy = h / 2;
    maxRad = Math.hypot(w, h) * 0.42;
    const nCols = Math.ceil(w / fontSize);
    const n = nCols * 2; // two drops per rain column
    drops = Array.from({ length: n }, (_, i) => {
      const old = drops[i];
      return {
        glyph: old?.glyph ?? rndGlyph(),
        // vortex state (polar)
        ang: old?.ang ?? Math.random() * Math.PI * 2,
        rad: old?.rad ?? maxRad * (0.2 + 0.8 * Math.random()),
        spin: old?.spin ?? 0.7 + Math.random() * 0.6,
        // rain state (cartesian)
        x: (i % nCols) * fontSize,
        y: old?.y ?? Math.random() * h,
        // morph endpoints (captured when the engine comes online)
        sx: 0,
        sy: 0,
        ty: Math.random() * h,
        delay: Math.random() * 500,
      };
    });
    if (phase === "morph") {
      // resize mid-transition: snap straight into the waterfall
      for (const d of drops) d.y = d.ty;
      phase = "rain";
    }
  }
  resize();
  addEventListener("resize", resize);

  function drawVortex() {
    for (const d of drops) {
      // differential rotation: fast near the singularity, lazy at the rim
      d.ang += Math.min(0.14, 0.015 + 12 / d.rad) * d.spin;
      d.rad *= 0.995;
      if (d.rad < 26) {
        // swallowed by the singularity — respawn at the rim
        d.rad = maxRad * (0.7 + 0.3 * Math.random());
        d.ang = Math.random() * Math.PI * 2;
      }
      if (Math.random() < 0.03) d.glyph = rndGlyph();
      const x = cx + Math.cos(d.ang) * d.rad;
      const y = cy + Math.sin(d.ang) * d.rad * 0.55; // tilted disc
      ctx.fillStyle =
        d.rad < maxRad * 0.25
          ? Math.random() < 0.6
            ? "#b6ffb9"
            : "#00ff41"
          : d.rad > maxRad * 0.7
            ? "#00b32d"
            : "#00ff41";
      ctx.fillText(d.glyph, x, y);
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
      ctx.fillText(d.glyph, d.sx + (d.x - d.sx) * e, d.sy + (d.ty - d.sy) * e);
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
      ctx.fillText(d.glyph, d.x, d.y);
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
      if (phase === "vortex") drawVortex();
      else if (phase === "morph") drawMorph(t);
      else drawRain();
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return {
    // engine online: capture each glyph's vortex position and send it
    // gliding to its waterfall column
    loaded() {
      if (phase !== "vortex") return;
      morphT0 = performance.now();
      for (const d of drops) {
        d.sx = cx + Math.cos(d.ang) * d.rad;
        d.sy = cy + Math.sin(d.ang) * d.rad * 0.55;
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
