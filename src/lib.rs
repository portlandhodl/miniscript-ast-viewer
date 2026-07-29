//! miniscript-ast-viewer: analyze miniscript policies and output descriptors,
//! then expose the resulting ASTs as JSON for an interactive browser UI.
//!
//! The pure-Rust entry point is [`analyze_impl`]; the WASM export is [`analyze`].

use std::str::FromStr;
use std::sync::Arc;

use miniscript::bitcoin::hex::DisplayHex;
use miniscript::bitcoin::{self, Network};
use miniscript::descriptor::{DescriptorPublicKey, ShInner, SortedMultiVec, Wsh, WshInner};
use miniscript::policy::Concrete;
use miniscript::{
    Descriptor, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Tap, Terminal, ToPublicKey,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Complete analysis of a user-supplied policy or descriptor.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    input_kind: &'static str,
    descriptor: Option<String>,
    taproot_descriptor: Option<String>,
    script_hex: Option<String>,
    script_asm: Option<String>,
    address_mainnet: Option<String>,
    address_testnet: Option<String>,
    has_wildcard: bool,
    descriptor_type: Option<String>,
    stats: Stats,
    timelocks: Timelocks,
    trees: Vec<Tree>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    script_size: Option<usize>,
    static_ops: Option<usize>,
    n_keys: usize,
    max_satisfaction_weight: Option<u64>,
}

#[derive(Serialize)]
pub struct Timelocks {
    relative: Vec<u32>,
    absolute: Vec<u32>,
}

/// A named AST tree the UI should render (policy tree, witness script,
/// taproot leaves, ...).
#[derive(Serialize)]
pub struct Tree {
    label: String,
    root: AstNode,
    #[serde(skip_serializing_if = "Option::is_none")]
    script: Option<ScriptInfo>,
}

/// Flat view of a tree's concrete script for the opcode visualizer.
#[derive(Serialize)]
pub struct ScriptInfo {
    hex: String,
    asm: String,
    instructions: Vec<InstructionInfo>,
}

#[derive(Serialize)]
pub struct InstructionInfo {
    /// Display text, e.g. `OP_CHECKSIG` or `OP_PUSHBYTES_33 <hex>`.
    text: String,
    /// Byte offset of this instruction within the script.
    start: usize,
    /// Byte offset one past the end of this instruction.
    end: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AstNode {
    id: String,
    fragment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_base: Option<String>,
    /// Static script template of the fragment, e.g. `<A> OP_BOOLOR <B>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
    /// Actually encoded script (asm) of this subtree, when concrete keys are
    /// derivable.
    #[serde(skip_serializing_if = "Option::is_none")]
    script_asm: Option<String>,
    /// Byte range `[start, end)` of this subtree's encoding within the tree's
    /// root script.
    #[serde(skip_serializing_if = "Option::is_none")]
    script_range: Option<[usize; 2]>,
    detail: String,
    children: Vec<AstNode>,
}

impl AstNode {
    fn leaf(
        id: &str,
        fragment: impl Into<String>,
        value: Option<String>,
        detail: impl Into<String>,
        type_base: Option<String>,
    ) -> Self {
        AstNode {
            id: id.to_string(),
            fragment: fragment.into(),
            value,
            type_base,
            template: None,
            script_asm: None,
            script_range: None,
            detail: detail.into(),
            children: Vec::new(),
        }
    }

    fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }
}

/// Human-readable description of an absolute (CLTV) locktime.
fn abs_lock_desc(n: u32) -> String {
    if n < 500_000_000 {
        format!("block height {}", n)
    } else {
        format!("unix timestamp {}", n)
    }
}

/// Human-readable description of a relative (CSV) locktime.
fn rel_lock_desc(n: u32) -> String {
    if n & (1 << 22) != 0 {
        let units = n & 0xffff;
        format!(
            "time-based: {} x 512s (~{} minutes)",
            units,
            units.saturating_mul(512) / 60
        )
    } else {
        format!("{} block(s)", n)
    }
}

/// Serialize a miniscript subtree into an [`AstNode`].
fn ms_to_ast<Pk: MiniscriptKey, Ctx: ScriptContext>(
    ms: &Miniscript<Pk, Ctx>,
    path: String,
) -> AstNode {
    let type_base = Some(format!("{:?}", ms.ty.corr.base));
    let cid = |i: usize| format!("{}.{}", path, i);

    let single = |fragment: &str,
                  wrapper: &str,
                  detail: &str,
                  template: &str,
                  sub: &Arc<Miniscript<Pk, Ctx>>| AstNode {
        id: path.clone(),
        fragment: format!("{} ({}:)", fragment, wrapper),
        value: None,
        type_base: type_base.clone(),
        template: Some(template.to_string()),
        script_asm: None,
        script_range: None,
        detail: detail.to_string(),
        children: vec![ms_to_ast(sub, cid(0))],
    };
    let double = |fragment: &str,
                  detail: &str,
                  template: &str,
                  a: &Arc<Miniscript<Pk, Ctx>>,
                  b: &Arc<Miniscript<Pk, Ctx>>| AstNode {
        id: path.clone(),
        fragment: fragment.to_string(),
        value: None,
        type_base: type_base.clone(),
        template: Some(template.to_string()),
        script_asm: None,
        script_range: None,
        detail: detail.to_string(),
        children: vec![ms_to_ast(a, cid(0)), ms_to_ast(b, cid(1))],
    };

    match &ms.node {
        Terminal::True => {
            AstNode::leaf(&path, "true", Some("1".into()), "Always satisfied", type_base)
                .with_template("OP_1")
        }
        Terminal::False => {
            AstNode::leaf(&path, "false", Some("0".into()), "Never satisfied", type_base)
                .with_template("OP_0")
        }
        Terminal::PkK(pk) => AstNode::leaf(
            &path,
            "pk_k",
            Some(pk.to_string()),
            "Raw public key (CHECKSIG provided by a parent check/wrapper)",
            type_base,
        )
        .with_template("<key push> (check opcode provided by parent)"),
        Terminal::PkH(pk) => AstNode::leaf(
            &path,
            "pk_h",
            Some(pk.to_string()),
            "Legacy-style key-hash check: DUP HASH160 <hash160> EQUALVERIFY",
            type_base,
        )
        .with_template("OP_DUP OP_HASH160 <hash160(key)> OP_EQUALVERIFY"),
        Terminal::RawPkH(h) => AstNode::leaf(
            &path,
            "raw_pkh",
            Some(h.to_string()),
            "Raw HASH160 public key hash (decoded from a script)",
            type_base,
        )
        .with_template("OP_DUP OP_HASH160 <hash160(key)> OP_EQUALVERIFY"),
        Terminal::After(t) => {
            let n = t.to_consensus_u32();
            AstNode::leaf(
                &path,
                "after",
                Some(n.to_string()),
                format!("Absolute timelock (CLTV): {}", abs_lock_desc(n)),
                type_base,
            )
            .with_template("<n> OP_CHECKLOCKTIMEVERIFY")
        }
        Terminal::Older(t) => {
            let n = t.to_consensus_u32();
            AstNode::leaf(
                &path,
                "older",
                Some(n.to_string()),
                format!("Relative timelock (CSV): {}", rel_lock_desc(n)),
                type_base,
            )
            .with_template("<n> OP_CHECKSEQUENCEVERIFY")
        }
        Terminal::Sha256(h) => AstNode::leaf(
            &path,
            "sha256",
            Some(h.to_string()),
            "SHA256 hashlock: a 32-byte preimage must be revealed",
            type_base,
        )
        .with_template("OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL"),
        Terminal::Hash256(h) => AstNode::leaf(
            &path,
            "hash256",
            Some(h.to_string()),
            "HASH256 (double SHA256) hashlock: a preimage must be revealed",
            type_base,
        )
        .with_template("OP_SIZE <32> OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL"),
        Terminal::Ripemd160(h) => AstNode::leaf(
            &path,
            "ripemd160",
            Some(h.to_string()),
            "RIPEMD160 hashlock: a preimage must be revealed",
            type_base,
        )
        .with_template("OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL"),
        Terminal::Hash160(h) => AstNode::leaf(
            &path,
            "hash160",
            Some(h.to_string()),
            "HASH160 (RIPEMD160 of SHA256) hashlock: a preimage must be revealed",
            type_base,
        )
        .with_template("OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL"),
        Terminal::Alt(sub) => single(
            "alt",
            "a",
            "Executes the child using the alt stack (TOALTSTACK/FROMALTSTACK)",
            "OP_TOALTSTACK <A> OP_FROMALTSTACK",
            sub,
        ),
        Terminal::Swap(sub) => single(
            "swap",
            "s",
            "Swaps the top two stack elements before executing the child",
            "OP_SWAP <A>",
            sub,
        ),
        Terminal::Check(sub) => single(
            "check",
            "c",
            "Applies CHECKSIG/CHECKMULTISIG to the key expression below",
            "<A> OP_CHECKSIG (or OP_CHECKMULTISIG / OP_CHECKSIGADD)",
            sub,
        ),
        Terminal::DupIf(sub) => single(
            "dupif",
            "d",
            "Duplicates the top stack element if it is non-zero (DUP IF)",
            "OP_DUP OP_IF <A> OP_ENDIF",
            sub,
        ),
        Terminal::Verify(sub) => single(
            "verify",
            "v",
            "VERIFY semantics: the child must consume/abort on failure",
            "<A> in verify form (OP_VERIFY or verify-variant of the last opcode)",
            sub,
        ),
        Terminal::NonZero(sub) => single(
            "nonzero",
            "j",
            "Asserts the wrapped value is non-zero (SIZE 0NOTEQUAL IF)",
            "OP_SIZE OP_0NOTEQUAL OP_IF <A> OP_ENDIF",
            sub,
        ),
        Terminal::ZeroNotEqual(sub) => single(
            "zero_not_equal",
            "n",
            "Converts the child result to a boolean (0NOTEQUAL)",
            "<A> OP_0NOTEQUAL",
            sub,
        ),
        Terminal::AndV(a, b) => double(
            "and_v",
            "Both branches must be satisfied; the right branch is evaluated in verify position",
            "<A> <B>",
            a,
            b,
        ),
        Terminal::AndB(a, b) => double(
            "and_b",
            "Both branches must be satisfied; results combined with BOOLAND",
            "<A> <B> OP_BOOLAND",
            a,
            b,
        ),
        Terminal::AndOr(a, b, c) => AstNode {
            id: path.clone(),
            fragment: "and_or".to_string(),
            value: None,
            type_base: type_base.clone(),
            template: Some("<A> OP_NOTIF <C> OP_ELSE <B> OP_ENDIF".to_string()),
            script_asm: None,
            script_range: None,
            detail: "If the left branch holds, the middle branch must hold; otherwise the right branch must hold".to_string(),
            children: vec![ms_to_ast(a, cid(0)), ms_to_ast(b, cid(1)), ms_to_ast(c, cid(2))],
        },
        Terminal::OrB(a, b) => double(
            "or_b",
            "Both branches always execute; succeeds if either succeeds (BOOLOR)",
            "<A> <B> OP_BOOLOR",
            a,
            b,
        ),
        Terminal::OrC(a, b) => double(
            "or_c",
            "If the left branch fails, the right branch must hold (short-circuit)",
            "<A> OP_NOTIF <B> OP_ENDIF",
            a,
            b,
        ),
        Terminal::OrD(a, b) => double(
            "or_d",
            "If the left branch succeeds, done; otherwise the right branch must hold (IF/ELSE)",
            "<A> OP_IFDUP OP_NOTIF <B> OP_ENDIF",
            a,
            b,
        ),
        Terminal::OrI(a, b) => double(
            "or_i",
            "An extra witness element selects which branch executes (IF/ELSE)",
            "OP_IF <A> OP_ELSE <B> OP_ENDIF",
            a,
            b,
        ),
        Terminal::Thresh(th) => {
            let children = th
                .iter()
                .enumerate()
                .map(|(i, sub)| ms_to_ast(sub, cid(i)))
                .collect();
            AstNode {
                id: path.clone(),
                fragment: format!("thresh(k={},n={})", th.k(), th.n()),
                value: None,
                type_base,
                template: Some(format!(
                    "<X1> (<Xi> OP_ADD)... <{}> OP_NUMEQUAL",
                    th.k()
                )),
                script_asm: None,
                script_range: None,
                detail: format!("{}-of-{} threshold over sub-expressions", th.k(), th.n()),
                children,
            }
        }
        Terminal::Multi(th) => {
            let children = th
                .iter()
                .enumerate()
                .map(|(i, pk)| {
                    AstNode::leaf(
                        &cid(i),
                        "key",
                        Some(pk.to_string()),
                        "Multisig participant public key",
                        None,
                    )
                })
                .collect();
            AstNode {
                id: path.clone(),
                fragment: format!("multi(k={},n={})", th.k(), th.n()),
                value: None,
                type_base,
                template: Some(format!(
                    "<{}> <key1..key{}> <{}> OP_CHECKMULTISIG",
                    th.k(),
                    th.n(),
                    th.n()
                )),
                script_asm: None,
                script_range: None,
                detail: format!("{}-of-{} bare CHECKMULTISIG", th.k(), th.n()),
                children,
            }
        }
        Terminal::MultiA(th) => {
            let children = th
                .iter()
                .enumerate()
                .map(|(i, pk)| {
                    AstNode::leaf(
                        &cid(i),
                        "key",
                        Some(pk.to_string()),
                        "CHECKSIGADD participant key",
                        None,
                    )
                })
                .collect();
            AstNode {
                id: path.clone(),
                fragment: format!("multi_a(k={},n={})", th.k(), th.n()),
                value: None,
                type_base,
                template: Some(format!(
                    "<key1> OP_CHECKSIGADD ... <key{}> OP_CHECKSIGADD <{}> OP_NUMEQUAL",
                    th.n(),
                    th.k()
                )),
                script_asm: None,
                script_range: None,
                detail: format!("{}-of-{} CHECKSIGADD multisig (taproot)", th.k(), th.n()),
                children,
            }
        }
        #[allow(unreachable_patterns)]
        _ => AstNode::leaf(&path, "unknown", None, "Unrecognized terminal", type_base),
    }
}

/// Direct miniscript children of a terminal (multisig keys are plain pushes,
/// not miniscript nodes, and are skipped).
fn child_ms<Pk: MiniscriptKey, Ctx: ScriptContext>(
    t: &Terminal<Pk, Ctx>,
) -> Vec<&Miniscript<Pk, Ctx>> {
    use Terminal::*;
    match t {
        Alt(s) | Swap(s) | Check(s) | DupIf(s) | Verify(s) | NonZero(s) | ZeroNotEqual(s) => {
            vec![s]
        }
        AndV(a, b) | AndB(a, b) | OrB(a, b) | OrC(a, b) | OrD(a, b) | OrI(a, b) => vec![a, b],
        AndOr(a, b, c) => vec![a, b, c],
        Thresh(th) => th.iter().map(AsRef::as_ref).collect(),
        _ => vec![],
    }
}

/// Find `needle` in `haystack` starting at `from` (scripts are tiny, naive is fine).
fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from + needle.len() > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}

/// Zip the AST with the concrete-key miniscript, attaching each node's encoded
/// script (asm) and its byte range within the tree's root script.
fn attach_scripts<Pk: MiniscriptKey + ToPublicKey, Ctx: ScriptContext>(
    ast: &mut AstNode,
    ms: &Miniscript<Pk, Ctx>,
    root_bytes: &[u8],
    search_from: usize,
) {
    let enc = ms.encode();
    let bytes = enc.as_bytes();
    ast.script_asm = Some(enc.to_asm_string());
    ast.script_range = find_subslice(root_bytes, bytes, search_from).map(|s| [s, s + bytes.len()]);
    let mut cursor = ast.script_range.map(|r| r[0]).unwrap_or(search_from);
    for (child_ast, child_ms) in ast.children.iter_mut().zip(child_ms(&ms.node)) {
        attach_scripts(child_ast, child_ms, root_bytes, cursor);
        if let Some(r) = child_ast.script_range {
            cursor = r[1];
        }
    }
}

/// Build the flat instruction view of a script for the opcode visualizer.
fn script_info(script: &bitcoin::Script) -> ScriptInfo {
    use miniscript::bitcoin::blockdata::script::Instruction;
    let asm = script.to_asm_string();
    // Instruction display text is taken from the asm rendering itself so the
    // visualizer always matches the raw script panel.
    let mut tokens = asm.split(' ');
    let mut instructions = Vec::new();
    let mut prev: Option<(usize, String)> = None;
    for (pos, ins) in script.instruction_indices().filter_map(Result::ok) {
        if let Some((p, text)) = prev.take() {
            instructions.push(InstructionInfo {
                text,
                start: p,
                end: pos,
            });
        }
        let text = match ins {
            Instruction::Op(_) => tokens.next().unwrap_or_default().to_string(),
            Instruction::PushBytes(_) => {
                format!(
                    "{} {}",
                    tokens.next().unwrap_or_default(),
                    tokens.next().unwrap_or_default()
                )
            }
        };
        prev = Some((pos, text));
    }
    if let Some((p, text)) = prev {
        instructions.push(InstructionInfo {
            text,
            start: p,
            end: script.len(),
        });
    }
    ScriptInfo {
        hex: script.as_bytes().to_hex_string(bitcoin::hex::Case::Lower),
        asm,
        instructions,
    }
}

/// Serialize a concrete policy tree into an [`AstNode`].
fn policy_to_ast<Pk: MiniscriptKey>(pol: &Concrete<Pk>, path: String) -> AstNode {
    let cid = |i: usize| format!("{}.{}", path, i);
    match pol {
        Concrete::Unsatisfiable => AstNode::leaf(
            &path,
            "unsatisfiable",
            Some("0".into()),
            "Can never be satisfied",
            None,
        ),
        Concrete::Trivial => {
            AstNode::leaf(&path, "trivial", Some("1".into()), "Always satisfied", None)
        }
        Concrete::Key(pk) => AstNode::leaf(
            &path,
            "pk",
            Some(pk.to_string()),
            "A signature for this key is required",
            None,
        ),
        Concrete::After(t) => {
            let n = t.to_consensus_u32();
            AstNode::leaf(
                &path,
                "after",
                Some(n.to_string()),
                format!("Absolute timelock (CLTV): {}", abs_lock_desc(n)),
                None,
            )
        }
        Concrete::Older(t) => {
            let n = t.to_consensus_u32();
            AstNode::leaf(
                &path,
                "older",
                Some(n.to_string()),
                format!("Relative timelock (CSV): {}", rel_lock_desc(n)),
                None,
            )
        }
        Concrete::Sha256(h) => AstNode::leaf(
            &path,
            "sha256",
            Some(h.to_string()),
            "SHA256 hashlock",
            None,
        ),
        Concrete::Hash256(h) => AstNode::leaf(
            &path,
            "hash256",
            Some(h.to_string()),
            "HASH256 hashlock",
            None,
        ),
        Concrete::Ripemd160(h) => AstNode::leaf(
            &path,
            "ripemd160",
            Some(h.to_string()),
            "RIPEMD160 hashlock",
            None,
        ),
        Concrete::Hash160(h) => AstNode::leaf(
            &path,
            "hash160",
            Some(h.to_string()),
            "HASH160 hashlock",
            None,
        ),
        Concrete::And(subs) => AstNode {
            id: path.clone(),
            fragment: format!("and({} branches)", subs.len()),
            value: None,
            type_base: None,
            template: None,
            script_asm: None,
            script_range: None,
            detail: "ALL sub-policies must be satisfied".to_string(),
            children: subs
                .iter()
                .enumerate()
                .map(|(i, sub)| policy_to_ast(sub, cid(i)))
                .collect(),
        },
        Concrete::Or(subs) => AstNode {
            id: path.clone(),
            fragment: format!("or({} branches)", subs.len()),
            value: None,
            type_base: None,
            template: None,
            script_asm: None,
            script_range: None,
            detail: "ANY ONE branch must be satisfied (odds guide the compiler)".to_string(),
            children: subs
                .iter()
                .enumerate()
                .map(|(i, (odds, sub))| {
                    let mut node = policy_to_ast(sub, cid(i));
                    node.value = Some(format!("odds {}", odds));
                    node
                })
                .collect(),
        },
        Concrete::Thresh(th) => AstNode {
            id: path.clone(),
            fragment: format!("thresh(k={},n={})", th.k(), th.n()),
            value: None,
            type_base: None,
            template: None,
            script_asm: None,
            script_range: None,
            detail: format!(
                "Any {} of the {} sub-policies must be satisfied",
                th.k(),
                th.n()
            ),
            children: th
                .iter()
                .enumerate()
                .map(|(i, sub)| policy_to_ast(sub, cid(i)))
                .collect(),
        },
    }
}

/// Collect relative/absolute timelock values used anywhere in a miniscript.
fn collect_timelocks<Pk: MiniscriptKey, Ctx: ScriptContext>(
    ms: &Miniscript<Pk, Ctx>,
    rel: &mut Vec<u32>,
    abs: &mut Vec<u32>,
) {
    for node in ms.iter() {
        match &node.node {
            Terminal::Older(t) => rel.push(t.to_consensus_u32()),
            Terminal::After(t) => abs.push(t.to_consensus_u32()),
            _ => {}
        }
    }
}

/// AST for a `sortedmulti(...)` fragment (synthetic node with key children).
fn sorted_multi_ast<Pk: MiniscriptKey, Ctx: ScriptContext>(
    sm: &SortedMultiVec<Pk, Ctx>,
    path: &str,
) -> AstNode {
    let children = sm
        .pks()
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            AstNode::leaf(
                &format!("{}.{}", path, i),
                "key",
                Some(pk.to_string()),
                "Multisig participant public key (BIP67 sorted at address derivation)",
                None,
            )
        })
        .collect();
    AstNode {
        id: path.to_string(),
        fragment: format!("sortedmulti(k={},n={})", sm.k(), sm.n()),
        value: None,
        type_base: None,
        template: Some(format!(
            "<{}> <BIP67-sorted key1..key{}> <{}> OP_CHECKMULTISIG",
            sm.k(),
            sm.n(),
            sm.n()
        )),
        script_asm: None,
        script_range: None,
        detail: format!("{}-of-{} sorted CHECKMULTISIG", sm.k(), sm.n()),
        children,
    }
}

/// Accumulators shared by the tree-extraction passes.
struct TreeSink<'a> {
    trees: &'a mut Vec<Tree>,
    rel: &'a mut Vec<u32>,
    abs: &'a mut Vec<u32>,
    static_ops: &'a mut Option<usize>,
    script_size: &'a mut Option<usize>,
}

/// Push a miniscript tree plus its stats/timelocks onto the sink.
/// When the concrete-key twin miniscript is available, every node also gets
/// its encoded script + byte range within the root script.
fn push_ms_tree<Pk, Ctx, CPk, CCtx>(
    sink: &mut TreeSink,
    label: String,
    ms: &Miniscript<Pk, Ctx>,
    concrete_ms: Option<&Miniscript<CPk, CCtx>>,
) where
    Pk: MiniscriptKey,
    Ctx: ScriptContext,
    CPk: MiniscriptKey + ToPublicKey,
    CCtx: ScriptContext,
{
    collect_timelocks(ms, sink.rel, sink.abs);
    if sink.static_ops.is_none() {
        *sink.static_ops = Some(ms.ext.static_ops);
        *sink.script_size = Some(ms.script_size());
    }
    let mut root = ms_to_ast(ms, "0".to_string());
    let mut script = None;
    if let Some(cms) = concrete_ms {
        let enc = cms.encode();
        attach_scripts(&mut root, cms, enc.as_bytes(), 0);
        script = Some(script_info(&enc));
    }
    sink.trees.push(Tree {
        label,
        root,
        script,
    });
}

/// Extract trees from a wsh inner (shared by bare wsh and sh-wrapped wsh).
fn extract_wsh_trees(
    wsh: &Wsh<DescriptorPublicKey>,
    cwsh: Option<&Wsh<bitcoin::PublicKey>>,
    ms_label: &str,
    multi_label: &str,
    sink: &mut TreeSink,
) {
    match wsh.as_inner() {
        WshInner::Ms(ms) => {
            let cms = cwsh.and_then(|w| match w.as_inner() {
                WshInner::Ms(m) => Some(m),
                _ => None,
            });
            push_ms_tree(sink, ms_label.to_string(), ms, cms);
        }
        WshInner::SortedMulti(sm) => sink.trees.push(Tree {
            label: multi_label.to_string(),
            root: sorted_multi_ast(sm, "0"),
            script: None,
        }),
    }
}

/// Extract every visualizable tree from a descriptor, pairing each miniscript
/// with its concrete-key counterpart (when derivable) for script data.
fn extract_trees(
    desc: &Descriptor<DescriptorPublicKey>,
    concrete: Option<&Descriptor<bitcoin::PublicKey>>,
    sink: &mut TreeSink,
) {
    match desc {
        Descriptor::Bare(b) => {
            let cms = concrete.and_then(|c| match c {
                Descriptor::Bare(cb) => Some(cb.as_inner()),
                _ => None,
            });
            push_ms_tree(sink, "Bare Script".into(), b.as_inner(), cms);
        }
        Descriptor::Pkh(p) => sink.trees.push(Tree {
            label: "P2PKH Key".into(),
            root: AstNode::leaf(
                "0",
                "pkh",
                Some(p.as_inner().to_string()),
                "Pay-to-public-key-hash",
                None,
            )
            .with_template("OP_DUP OP_HASH160 <hash160(key)> OP_EQUALVERIFY OP_CHECKSIG"),
            script: None,
        }),
        Descriptor::Wpkh(w) => sink.trees.push(Tree {
            label: "P2WPKH Key".into(),
            root: AstNode::leaf(
                "0",
                "wpkh",
                Some(w.as_inner().to_string()),
                "Pay-to-witness-public-key-hash",
                None,
            )
            .with_template("OP_0 <hash160(key)> (witness program)"),
            script: None,
        }),
        Descriptor::Sh(sh) => {
            let csh = concrete.and_then(|c| match c {
                Descriptor::Sh(s) => Some(s),
                _ => None,
            });
            match sh.as_inner() {
                ShInner::Wsh(wsh) => {
                    let cwsh = csh.and_then(|s| match s.as_inner() {
                        ShInner::Wsh(w) => Some(w),
                        _ => None,
                    });
                    extract_wsh_trees(
                        wsh,
                        cwsh,
                        "P2SH-P2WSH Witness Script",
                        "P2SH-P2WSH Sorted Multisig",
                        sink,
                    );
                }
                ShInner::Wpkh(w) => sink.trees.push(Tree {
                    label: "P2SH-P2WPKH Key".into(),
                    root: AstNode::leaf(
                        "0",
                        "wpkh",
                        Some(w.as_inner().to_string()),
                        "Nested segwit key",
                        None,
                    )
                    .with_template("OP_0 <hash160(key)> (witness program)"),
                    script: None,
                }),
                ShInner::Ms(ms) => {
                    let cms = csh.and_then(|s| match s.as_inner() {
                        ShInner::Ms(m) => Some(m),
                        _ => None,
                    });
                    push_ms_tree(sink, "P2SH Redeem Script (Legacy)".into(), ms, cms);
                }
                ShInner::SortedMulti(sm) => sink.trees.push(Tree {
                    label: "P2SH Sorted Multisig".into(),
                    root: sorted_multi_ast(sm, "0"),
                    script: None,
                }),
            }
        }
        Descriptor::Wsh(wsh) => {
            let cwsh = concrete.and_then(|c| match c {
                Descriptor::Wsh(w) => Some(w),
                _ => None,
            });
            extract_wsh_trees(
                wsh,
                cwsh,
                "Witness Script (P2WSH)",
                "Sorted Multisig (P2WSH)",
                sink,
            );
        }
        Descriptor::Tr(tr) => {
            sink.trees.push(Tree {
                label: "Taproot Internal Key".into(),
                root: AstNode::leaf(
                    "0",
                    "internal_key",
                    Some(tr.internal_key().to_string()),
                    "Key-path spend key (script tree hidden when unused)",
                    None,
                )
                .with_template("OP_1 <tweaked x-only key> (key-path spend)"),
                script: None,
            });
            let ctr = concrete.and_then(|c| match c {
                Descriptor::Tr(t) => Some(t),
                _ => None,
            });
            let cleaves: Vec<&Miniscript<bitcoin::PublicKey, Tap>> = ctr
                .and_then(|t| t.tap_tree())
                .map(|t| t.leaves().map(|i| i.miniscript().as_ref()).collect())
                .unwrap_or_default();
            if let Some(taptree) = tr.tap_tree() {
                for (i, item) in taptree.leaves().enumerate() {
                    push_ms_tree(
                        sink,
                        format!("Taproot Leaf Script (depth {})", item.depth()),
                        item.miniscript(),
                        cleaves.get(i).copied(),
                    );
                }
            }
        }
    }
}

/// Shared analysis pipeline once we hold a `Descriptor<DescriptorPublicKey>`.
fn descriptor_analysis(
    mut desc: Descriptor<DescriptorPublicKey>,
    input_kind: &'static str,
    extra_trees: Vec<Tree>,
    taproot_descriptor: Option<String>,
    mut warnings: Vec<String>,
    mut timelocks: Timelocks,
) -> Result<Analysis, String> {
    if desc.is_multipath() {
        warnings.push("Multipath descriptor (</>): displaying the first path only".into());
        let singles = desc
            .into_single_descriptors()
            .map_err(|e| format!("could not split multipath descriptor: {e}"))?;
        desc = singles
            .into_iter()
            .next()
            .ok_or_else(|| "empty multipath descriptor".to_string())?;
    }
    // Sanity-check problems (e.g. sigless branches) are surfaced as warnings:
    // the user may still want to inspect the AST of such descriptors.
    if let Err(e) = desc.sanity_check() {
        warnings.push(format!("sanity check: {e}"));
    }

    let has_wildcard = desc.has_wildcard();
    if has_wildcard {
        warnings.push(
            "Ranged descriptor (…/*): keys, scripts and addresses are shown at derivation index 0"
                .into(),
        );
    }

    let n_keys = desc.iter_pk().count();
    let descriptor_type = Some(format!("{:?}", desc.desc_type()));
    let max_w = desc.max_weight_to_satisfy().ok().map(|w| w.to_wu());

    // Derive concrete keys (index 0) so scripts/addresses/ranges are available.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let concrete = desc
        .at_derivation_index(0)
        .ok()
        .map(|d| d.derived_descriptor(&secp));

    let mut trees = extra_trees;
    let mut static_ops = None;
    let mut script_size = None;
    extract_trees(
        &desc,
        concrete.as_ref(),
        &mut TreeSink {
            trees: &mut trees,
            rel: &mut timelocks.relative,
            abs: &mut timelocks.absolute,
            static_ops: &mut static_ops,
            script_size: &mut script_size,
        },
    );
    timelocks.relative.sort_unstable();
    timelocks.relative.dedup();
    timelocks.absolute.sort_unstable();
    timelocks.absolute.dedup();

    let (script_hex, script_asm, address_mainnet, address_testnet) = match &concrete {
        Some(c) => {
            let script = c.explicit_script().unwrap_or_else(|_| c.script_pubkey());
            (
                Some(script.as_bytes().to_hex_string(bitcoin::hex::Case::Lower)),
                Some(script.to_asm_string()),
                c.address(Network::Bitcoin).ok().map(|a| a.to_string()),
                c.address(Network::Testnet).ok().map(|a| a.to_string()),
            )
        }
        None => (None, None, None, None),
    };

    Ok(Analysis {
        input_kind,
        descriptor: Some(desc.to_string()),
        taproot_descriptor,
        script_hex,
        script_asm,
        address_mainnet,
        address_testnet,
        has_wildcard,
        descriptor_type,
        stats: Stats {
            script_size,
            static_ops,
            n_keys,
            max_satisfaction_weight: max_w,
        },
        timelocks,
        trees,
        warnings,
    })
}

/// Analyze input as a miniscript policy: compile to Segwitv0, wrap in wsh().
fn analyze_as_policy(s: &str) -> Result<Analysis, String> {
    let pol = Concrete::<DescriptorPublicKey>::from_str(s)
        .map_err(|e| format!("policy parse error: {e}"))?;

    let ms: Miniscript<DescriptorPublicKey, Segwitv0> = pol
        .compile()
        .map_err(|e| format!("policy compilation failed: {e}"))?;
    let desc =
        Descriptor::new_wsh(ms).map_err(|e| format!("could not build wsh descriptor: {e}"))?;
    let taproot_descriptor = pol.compile_tr(None).ok().map(|d| d.to_string());

    let policy_tree = Tree {
        label: "Policy AST".into(),
        root: policy_to_ast(&pol, "0".to_string()),
        script: None,
    };

    // Timelocks are collected from the compiled miniscript by descriptor_analysis.
    descriptor_analysis(
        desc,
        "policy",
        vec![policy_tree],
        taproot_descriptor,
        Vec::new(),
        Timelocks {
            relative: Vec::new(),
            absolute: Vec::new(),
        },
    )
}

/// Analyze input as an output descriptor.
fn analyze_as_descriptor(s: &str) -> Result<Analysis, String> {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(s)
        .map_err(|e| format!("descriptor parse error: {e}"))?;
    descriptor_analysis(
        desc,
        "descriptor",
        Vec::new(),
        None,
        Vec::new(),
        Timelocks {
            relative: Vec::new(),
            absolute: Vec::new(),
        },
    )
}

/// Pure-Rust entry point (unit-testable without a WASM runtime).
pub fn analyze_impl(input: &str, mode: &str) -> Result<Analysis, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty input".to_string());
    }
    match mode {
        "descriptor" => analyze_as_descriptor(s),
        "policy" => analyze_as_policy(s),
        _ => {
            // auto-detect: obvious descriptor wrappers first
            let desc_like = [
                "wsh(", "sh(", "tr(", "pkh(", "wpkh(", "pk(", "combo(", "addr(", "raw(",
            ]
            .iter()
            .any(|p| s.starts_with(p))
                || s.contains('#');
            // On failure, report the error from the most likely parser.
            if desc_like {
                match analyze_as_descriptor(s) {
                    Ok(a) => Ok(a),
                    Err(e) => analyze_as_policy(s).map_err(|_| e),
                }
            } else {
                match analyze_as_policy(s) {
                    Ok(a) => Ok(a),
                    Err(e) => analyze_as_descriptor(s).map_err(|_| e),
                }
            }
        }
    }
}

/// WASM export: returns the [`Analysis`] as a JSON string.
#[wasm_bindgen]
pub fn analyze(input: &str, mode: &str) -> Result<String, JsError> {
    let analysis = analyze_impl(input, mode).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&analysis).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM export: engine description for the UI footer.
#[wasm_bindgen]
pub fn engine_info() -> String {
    "rust-miniscript 13.1 / rust-bitcoin 0.32".to_string()
}
