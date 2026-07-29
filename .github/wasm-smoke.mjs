// CI smoke test: load the compiled (nodejs-target) wasm bundle and exercise
// the public API against known inputs. Usage: node wasm-smoke.mjs <pkg-dir>
import { createRequire } from "node:module";

const pkgDir = process.argv[2] ?? "/tmp/pkg-node";
const require = createRequire(import.meta.url);
const m = require(`${pkgDir}/miniscript_ast_viewer.js`);

const A = "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261";
const B = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";

let failures = 0;
const check = (name, cond) => {
  console.log(cond ? "PASS" : "FAIL", name);
  if (!cond) failures++;
};

// 1. policy compiles to a wsh descriptor with both AST trees
const r = JSON.parse(m.analyze(`or(pk(${A}),and(pk(${B}),older(144)))`, "auto"));
check("policy detected", r.inputKind === "policy");
check("wsh descriptor", r.descriptor.startsWith("wsh("));
check("two trees", r.trees.length === 2);
check("mainnet address", r.addressMainnet.startsWith("bc1"));

// 2. descriptor round-trips
const d = JSON.parse(m.analyze(`wsh(and_v(v:pk(${A}),older(144)))`, "auto"));
check("descriptor detected", d.inputKind === "descriptor");
check("single tree", d.trees.length === 1);
check("root fragment", d.trees[0].root.fragment === "and_v");

// 3. errors propagate
let threw = false;
try { m.analyze("garbage", "auto"); } catch { threw = true; }
check("invalid input throws", threw);

// 4. engine info string
check("engine info", /rust-miniscript/.test(m.engine_info()));

process.exit(failures ? 1 : 0);
