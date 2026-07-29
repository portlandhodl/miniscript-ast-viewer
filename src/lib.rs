//! miniscript-ast-viewer: analyze miniscript policies and output descriptors,
//! then expose the resulting ASTs as JSON for an interactive browser UI.
//!
//! The pure-Rust entry point is [`analyze_impl`]; the WASM export is [`analyze`].

use std::str::FromStr;
use std::sync::Arc;

use miniscript::bitcoin::hex::DisplayHex;
use miniscript::bitcoin::{self, Network};
use miniscript::descriptor::{DescriptorPublicKey, ShInner, SortedMultiVec, WshInner};
use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Terminal};
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
            detail: detail.into(),
            children: Vec::new(),
        }
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

    let single =
        |fragment: &str, wrapper: &str, detail: &str, sub: &Arc<Miniscript<Pk, Ctx>>| AstNode {
            id: path.clone(),
            fragment: format!("{} ({}:)", fragment, wrapper),
            value: None,
            type_base: type_base.clone(),
            detail: detail.to_string(),
            children: vec![ms_to_ast(sub, cid(0))],
        };
    let double = |fragment: &str,
                  detail: &str,
                  a: &Arc<Miniscript<Pk, Ctx>>,
                  b: &Arc<Miniscript<Pk, Ctx>>| AstNode {
        id: path.clone(),
        fragment: fragment.to_string(),
        value: None,
        type_base: type_base.clone(),
        detail: detail.to_string(),
        children: vec![ms_to_ast(a, cid(0)), ms_to_ast(b, cid(1))],
    };

    match &ms.node {
        Terminal::True => AstNode::leaf(&path, "true", Some("1".into()), "Always satisfied", type_base),
        Terminal::False => AstNode::leaf(&path, "false", Some("0".into()), "Never satisfied", type_base),
        Terminal::PkK(pk) => AstNode::leaf(
            &path,
            "pk_k",
            Some(pk.to_string()),
            "Raw public key (CHECKSIG provided by a parent check/wrapper)",
            type_base,
        ),
        Terminal::PkH(pk) => AstNode::leaf(
            &path,
            "pk_h",
            Some(pk.to_string()),
            "Legacy-style key-hash check: DUP HASH160 <hash160> EQUALVERIFY",
            type_base,
        ),
        Terminal::RawPkH(h) => AstNode::leaf(
            &path,
            "raw_pkh",
            Some(h.to_string()),
            "Raw HASH160 public key hash (decoded from a script)",
            type_base,
        ),
        Terminal::After(t) => {
            let n = t.to_consensus_u32();
            AstNode::leaf(
                &path,
                "after",
                Some(n.to_string()),
                format!("Absolute timelock (CLTV): {}", abs_lock_desc(n)),
                type_base,
            )
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
        }
        Terminal::Sha256(h) => AstNode::leaf(
            &path,
            "sha256",
            Some(h.to_string()),
            "SHA256 hashlock: a 32-byte preimage must be revealed",
            type_base,
        ),
        Terminal::Hash256(h) => AstNode::leaf(
            &path,
            "hash256",
            Some(h.to_string()),
            "HASH256 (double SHA256) hashlock: a preimage must be revealed",
            type_base,
        ),
        Terminal::Ripemd160(h) => AstNode::leaf(
            &path,
            "ripemd160",
            Some(h.to_string()),
            "RIPEMD160 hashlock: a preimage must be revealed",
            type_base,
        ),
        Terminal::Hash160(h) => AstNode::leaf(
            &path,
            "hash160",
            Some(h.to_string()),
            "HASH160 (RIPEMD160 of SHA256) hashlock: a preimage must be revealed",
            type_base,
        ),
        Terminal::Alt(sub) => single("alt", "a", "Executes the child using the alt stack (TOALTSTACK/FROMALTSTACK)", sub),
        Terminal::Swap(sub) => single("swap", "s", "Swaps the top two stack elements before executing the child", sub),
        Terminal::Check(sub) => single("check", "c", "Applies CHECKSIG/CHECKMULTISIG to the key expression below", sub),
        Terminal::DupIf(sub) => single("dupif", "d", "Duplicates the top stack element if it is non-zero (DUP IF)", sub),
        Terminal::Verify(sub) => single("verify", "v", "VERIFY semantics: the child must consume/abort on failure", sub),
        Terminal::NonZero(sub) => single("nonzero", "j", "Asserts the wrapped value is non-zero (0NOTEQUAL ... SIZE)", sub),
        Terminal::ZeroNotEqual(sub) => single("zero_not_equal", "n", "Converts the child result to a boolean (0NOTEQUAL)", sub),
        Terminal::AndV(a, b) => double(
            "and_v",
            "Both branches must be satisfied; the right branch is evaluated in verify position",
            a,
            b,
        ),
        Terminal::AndB(a, b) => double(
            "and_b",
            "Both branches must be satisfied; results combined with BOOLAND",
            a,
            b,
        ),
        Terminal::AndOr(a, b, c) => AstNode {
            id: path.clone(),
            fragment: "and_or".to_string(),
            value: None,
            type_base: type_base.clone(),
            detail: "If the left branch holds, the middle branch must hold; otherwise the right branch must hold".to_string(),
            children: vec![ms_to_ast(a, cid(0)), ms_to_ast(b, cid(1)), ms_to_ast(c, cid(2))],
        },
        Terminal::OrB(a, b) => double(
            "or_b",
            "Both branches always execute; succeeds if either succeeds (BOOLOR)",
            a,
            b,
        ),
        Terminal::OrC(a, b) => double(
            "or_c",
            "If the left branch fails, the right branch must hold (short-circuit)",
            a,
            b,
        ),
        Terminal::OrD(a, b) => double(
            "or_d",
            "If the left branch succeeds, done; otherwise the right branch must hold (IF/ELSE)",
            a,
            b,
        ),
        Terminal::OrI(a, b) => double(
            "or_i",
            "An extra witness element selects which branch executes (IF/ELSE)",
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
                detail: format!("{}-of-{} CHECKSIGADD multisig (taproot)", th.k(), th.n()),
                children,
            }
        }
        #[allow(unreachable_patterns)]
        _ => AstNode::leaf(&path, "unknown", None, "Unrecognized terminal", type_base),
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
        detail: format!("{}-of-{} sorted CHECKMULTISIG", sm.k(), sm.n()),
        children,
    }
}

/// Push a miniscript tree plus its stats/timelocks onto the accumulators.
fn push_ms_tree<Pk: MiniscriptKey, Ctx: ScriptContext>(
    trees: &mut Vec<Tree>,
    rel: &mut Vec<u32>,
    abs: &mut Vec<u32>,
    static_ops: &mut Option<usize>,
    script_size: &mut Option<usize>,
    label: String,
    ms: &Miniscript<Pk, Ctx>,
) {
    collect_timelocks(ms, rel, abs);
    if static_ops.is_none() {
        *static_ops = Some(ms.ext.static_ops);
        *script_size = Some(ms.script_size());
    }
    trees.push(Tree {
        label,
        root: ms_to_ast(ms, "0".to_string()),
    });
}

/// Extract every visualizable tree from a descriptor.
fn extract_trees<Pk: MiniscriptKey>(
    desc: &Descriptor<Pk>,
    trees: &mut Vec<Tree>,
    rel: &mut Vec<u32>,
    abs: &mut Vec<u32>,
    static_ops: &mut Option<usize>,
    script_size: &mut Option<usize>,
) {
    match desc {
        Descriptor::Bare(b) => push_ms_tree(
            trees,
            rel,
            abs,
            static_ops,
            script_size,
            "Bare Script".into(),
            b.as_inner(),
        ),
        Descriptor::Pkh(p) => trees.push(Tree {
            label: "P2PKH Key".into(),
            root: AstNode::leaf(
                "0",
                "pkh",
                Some(p.as_inner().to_string()),
                "Pay-to-public-key-hash",
                None,
            ),
        }),
        Descriptor::Wpkh(w) => trees.push(Tree {
            label: "P2WPKH Key".into(),
            root: AstNode::leaf(
                "0",
                "wpkh",
                Some(w.as_inner().to_string()),
                "Pay-to-witness-public-key-hash",
                None,
            ),
        }),
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Wsh(wsh) => match wsh.as_inner() {
                WshInner::Ms(ms) => push_ms_tree(
                    trees,
                    rel,
                    abs,
                    static_ops,
                    script_size,
                    "P2SH-P2WSH Witness Script".into(),
                    ms,
                ),
                WshInner::SortedMulti(sm) => trees.push(Tree {
                    label: "P2SH-P2WSH Sorted Multisig".into(),
                    root: sorted_multi_ast(sm, "0"),
                }),
            },
            ShInner::Wpkh(w) => trees.push(Tree {
                label: "P2SH-P2WPKH Key".into(),
                root: AstNode::leaf(
                    "0",
                    "wpkh",
                    Some(w.as_inner().to_string()),
                    "Nested segwit key",
                    None,
                ),
            }),
            ShInner::Ms(ms) => push_ms_tree(
                trees,
                rel,
                abs,
                static_ops,
                script_size,
                "P2SH Redeem Script (Legacy)".into(),
                ms,
            ),
            ShInner::SortedMulti(sm) => trees.push(Tree {
                label: "P2SH Sorted Multisig".into(),
                root: sorted_multi_ast(sm, "0"),
            }),
        },
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            WshInner::Ms(ms) => push_ms_tree(
                trees,
                rel,
                abs,
                static_ops,
                script_size,
                "Witness Script (P2WSH)".into(),
                ms,
            ),
            WshInner::SortedMulti(sm) => trees.push(Tree {
                label: "Sorted Multisig (P2WSH)".into(),
                root: sorted_multi_ast(sm, "0"),
            }),
        },
        Descriptor::Tr(tr) => {
            trees.push(Tree {
                label: "Taproot Internal Key".into(),
                root: AstNode::leaf(
                    "0",
                    "internal_key",
                    Some(tr.internal_key().to_string()),
                    "Key-path spend key (script tree hidden when unused)",
                    None,
                ),
            });
            if let Some(taptree) = tr.tap_tree() {
                for item in taptree.leaves() {
                    push_ms_tree(
                        trees,
                        rel,
                        abs,
                        static_ops,
                        script_size,
                        format!("Taproot Leaf Script (depth {})", item.depth()),
                        item.miniscript(),
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

    let mut trees = extra_trees;
    let mut static_ops = None;
    let mut script_size = None;
    extract_trees(
        &desc,
        &mut trees,
        &mut timelocks.relative,
        &mut timelocks.absolute,
        &mut static_ops,
        &mut script_size,
    );
    timelocks.relative.sort_unstable();
    timelocks.relative.dedup();
    timelocks.absolute.sort_unstable();
    timelocks.absolute.dedup();

    // Derive concrete keys (index 0) so we can show script + addresses.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let concrete = desc
        .at_derivation_index(0)
        .ok()
        .map(|d| d.derived_descriptor(&secp));

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
