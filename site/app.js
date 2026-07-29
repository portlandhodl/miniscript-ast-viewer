/* MINISCRIPT://AST_BROWSER — frontend driver */
import init, { analyze, engine_info } from "./pkg/miniscript_ast_viewer.js";

/* ------------------------------------------------------------------ *
 *  Matrix rain backdrop
 * ------------------------------------------------------------------ */
function startRain() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const canvas = document.getElementById("rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "アカサタナハマヤラワ0123456789ABCDEF·:+*<>";
  const fontSize = 15;
  let columns = [];
  let w, h;

  function resize() {
    w = canvas.width = innerWidth;
    h = canvas.height = innerHeight;
    const n = Math.ceil(w / fontSize);
    columns = Array.from({ length: n }, () => Math.floor((Math.random() * h) / fontSize));
  }
  resize();
  addEventListener("resize", resize);

  let last = 0;
  function frame(t) {
    if (!document.hidden && t - last > 50) {
      last = t;
      ctx.fillStyle = "rgba(0,0,0,0.08)";
      ctx.fillRect(0, 0, w, h);
      ctx.font = `${fontSize}px monospace`;
      columns.forEach((y, i) => {
        const ch = glyphs[(Math.random() * glyphs.length) | 0];
        const head = Math.random() < 0.06;
        ctx.fillStyle = head ? "#b6ffb9" : "#00ff41";
        ctx.fillText(ch, i * fontSize, y * fontSize);
        columns[i] = y * fontSize > h && Math.random() > 0.975 ? 0 : y + 1;
      });
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
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
}

function renderNodeDetail(node) {
  const d = $("node-detail");
  d.innerHTML = "";
  const kv = el("div", "kv");
  const add = (k, v, bright) => {
    kv.appendChild(el("div", "k", k));
    const ve = el("div", "v" + (bright ? " bright" : ""), v);
    if (k === "value") ve.appendChild(copyBtn(() => v));
    kv.appendChild(ve);
  };
  add("fragment", node.fragment, true);
  if (node.typeBase) add("type", node.typeBase);
  if (node.value !== undefined) add("value", node.value);
  add("path", node.id);
  add("meaning", node.detail);
  if (node.children?.length) add("children", String(node.children.length));
  d.appendChild(kv);
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
  startRain();
  const boot = $("boot-status");

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
    await init();
    boot.textContent = "[ wasm module online — engine ready ]";
    boot.classList.add("ok");
    $("run").disabled = false;
    $("engine-info").textContent = "engine: " + engine_info();
  } catch (e) {
    boot.textContent = "[ FAILED to load wasm module: " + e + " ]";
    boot.classList.add("fail");
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
