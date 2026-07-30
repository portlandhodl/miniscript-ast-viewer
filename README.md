# MINISCRIPT://AST_BROWSER

A matrix-themed, fully client-side **miniscript policy / output descriptor AST
browser**. [`rust-miniscript`](https://github.com/rust-bitcoin/rust-miniscript)
is compiled to WebAssembly and runs in your browser — no server, no key material
ever leaves the page.

**Live:** <https://portlandhodl.github.io/miniscript-ast-viewer/>

## What it does

- Paste a **miniscript policy** (e.g. `or(pk(A),and(pk(B),older(144)))`)
  - compiles it with the actual rust-miniscript policy compiler
  - shows the resulting `wsh(...)` descriptor (plus the `tr(...)` compilation)
- Paste an **output descriptor** (`wsh`, `sh`, `tr`, `pkh`, `wpkh`, bare,
  `sortedmulti`, ranged xpubs — anything `rust-miniscript` parses)
- Renders every script as an **interactive AST**: expand/collapse, click or
  drive with the keyboard (`↑ ↓ ← →`, `enter`), and inspect each node
  (fragment, correctness type, keys/timelocks/hashes, meaning)
- **Codepath visualizer**: the script is rendered opcode-by-opcode above the
  tree; selecting an AST node lights up its exact byte range of the script,
  plus the routing opcodes of its ancestors (`OP_IF`/`OP_NOTIF`/`OP_ELSE`…)
  that activate that codepath. Click an opcode to jump to its AST node.
- **Spend-path permutations**: every distinct way to satisfy the script is
  enumerated (capped at 64 per tree). Selecting a path highlights the opcodes
  it executes (conditions + routing) and the AST members it uses.
- **Node inspector**: per-node script template (`<A> OP_BOOLOR <B>`), the
  actually encoded subtree script with byte offsets, a clickable *parents*
  breadcrumb, and *spend with* links that compute and highlight the sibling
  conditions required to satisfy the selected node.
- Shows script hex + assembly, mainnet/testnet addresses (derived at index 0
  for ranged descriptors), script size, static opcode count, max satisfaction
  weight, and the timelocks in play
- Deep-linkable: the input is stored in the URL hash for sharing

## Local development

Requires `rustup` (with `wasm32-unknown-unknown`) and
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```sh
wasm-pack build --target web --release --out-dir site/pkg
python3 -m http.server 8000 --directory site
# open http://localhost:8000
```

## Tests

```sh
cargo test            # native integration tests of the analysis pipeline
```

CI additionally builds the wasm bundle and smoke-tests it in Node
(`.github/wasm-smoke.mjs`), then deploys `site/` to GitHub Pages on every push
to `main`.

## Stack

- `rust-miniscript 13.1` / `rust-bitcoin 0.32` → `wasm32-unknown-unknown` via
  `wasm-bindgen` / `wasm-pack`
- dependency-free frontend (`site/index.html`, `style.css`, `app.js`)
- GitHub Actions: fmt + clippy + tests → wasm build → GitHub Pages deploy

## License

MIT
