//! Integration tests for the analysis pipeline (native, no WASM runtime).

use miniscript_ast_viewer::analyze_impl;

const KEY_A: &str = "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261";
const KEY_B: &str = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
const KEY_C: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SHA256_TEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const TR_INTERNAL: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const XONLY_G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const XONLY_2G: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

#[test]
fn policy_escrow_compiles_to_wsh() {
    let input = format!("or(pk({}),and(pk({}),older(144)))", KEY_A, KEY_B);
    let a = analyze_impl(&input, "auto").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();

    assert_eq!(json["inputKind"], "policy");
    let desc = json["descriptor"].as_str().unwrap();
    assert!(
        desc.starts_with("wsh("),
        "expected wsh descriptor, got {desc}"
    );
    assert!(desc.contains("older(144)"));
    assert!(desc.contains(KEY_A) && desc.contains(KEY_B));

    // two trees: policy AST + compiled miniscript AST
    let trees = json["trees"].as_array().unwrap();
    assert_eq!(trees.len(), 2);
    assert_eq!(trees[0]["label"], "Policy AST");
    assert_eq!(trees[0]["root"]["fragment"], "or(2 branches)");

    // compiled tree root should be an or_* fragment
    let compiled_frag = trees[1]["root"]["fragment"].as_str().unwrap();
    assert!(compiled_frag.starts_with("or_"), "got {compiled_frag}");

    // timelock surfaced
    assert_eq!(json["timelocks"]["relative"], serde_json::json!([144]));

    // stats + addresses present
    assert!(json["stats"]["scriptSize"].as_u64().unwrap() > 0);
    assert!(json["addressMainnet"].as_str().unwrap().starts_with("bc1"));
    assert!(json["addressTestnet"].as_str().unwrap().starts_with("tb1"));
    assert!(json["scriptHex"].as_str().unwrap().len() > 10);

    // taproot compilation also offered
    assert!(json["taprootDescriptor"]
        .as_str()
        .unwrap()
        .starts_with("tr("));
}

#[test]
fn descriptor_wsh_parses() {
    let input = format!("wsh(and_v(v:pk({}),older(144)))", KEY_A);
    let a = analyze_impl(&input, "auto").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();

    assert_eq!(json["inputKind"], "descriptor");
    assert_eq!(json["descriptorType"], "Wsh");
    let trees = json["trees"].as_array().unwrap();
    assert_eq!(trees.len(), 1);
    assert_eq!(trees[0]["root"]["fragment"], "and_v");
    // children: verify(pk) wrapper node and older(144) leaf
    let children = trees[0]["root"]["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert!(children[0]["fragment"].as_str().unwrap().contains("verify"));
    assert_eq!(children[1]["fragment"], "older");
    assert_eq!(children[1]["value"], "144");
}

#[test]
fn descriptor_sortedmulti() {
    let input = format!("wsh(sortedmulti(2,{},{},{}))", KEY_A, KEY_B, KEY_C);
    let a = analyze_impl(&input, "descriptor").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();

    let root = &json["trees"][0]["root"];
    assert!(root["fragment"]
        .as_str()
        .unwrap()
        .starts_with("sortedmulti(k=2"));
    assert_eq!(root["children"].as_array().unwrap().len(), 3);
    assert_eq!(json["stats"]["nKeys"], 3);
}

#[test]
fn descriptor_thresh_fragment() {
    let input = format!("wsh(thresh(2,pk({}),s:pk({})))", KEY_A, KEY_B);
    let a = analyze_impl(&input, "auto").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();
    let root = &json["trees"][0]["root"];
    assert!(root["fragment"].as_str().unwrap().starts_with("thresh(k=2"));
}

#[test]
fn wildcard_xpub_derives_addresses() {
    let input = format!("wsh(and_v(v:pk({}/0/*),older(144)))", XPUB);
    let a = analyze_impl(&input, "auto").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();

    assert_eq!(json["hasWildcard"], true);
    assert!(!json["warnings"].as_array().unwrap().is_empty());
    // addresses are derived at index 0
    assert!(json["addressMainnet"].as_str().unwrap().starts_with("bc1"));
}

#[test]
fn taproot_descriptor_trees() {
    let input = format!("tr({},{{pk({}),pk({})}})", TR_INTERNAL, XONLY_G, XONLY_2G);
    let a = analyze_impl(&input, "auto").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();

    let trees = json["trees"].as_array().unwrap();
    assert_eq!(trees.len(), 3, "internal key + 2 leaves");
    assert_eq!(trees[0]["label"], "Taproot Internal Key");
    assert!(trees[1]["label"].as_str().unwrap().contains("Taproot Leaf"));
    // taproot descriptors have no explicit script but do have an address
    assert!(json["scriptHex"].as_str().unwrap().len() > 10);
    assert!(json["addressMainnet"].as_str().unwrap().starts_with("bc1p"));
}

#[test]
fn policy_htlc_with_hash_and_cltv() {
    let input = format!(
        "or(and(pk({}),sha256({})),and(pk({}),after(800000)))",
        KEY_A, SHA256_TEST, KEY_B
    );
    let a = analyze_impl(&input, "policy").expect("analysis failed");
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(json["timelocks"]["absolute"], serde_json::json!([800000]));
    // policy tree must contain a sha256 node
    let policy_tree = serde_json::to_string(&json["trees"][0]).unwrap();
    assert!(policy_tree.contains("sha256"));
}

#[test]
fn auto_detect_distinguishes_kinds() {
    let policy = format!("and(pk({}),older(100))", KEY_A);
    assert_eq!(
        serde_json::to_value(analyze_impl(&policy, "auto").unwrap()).unwrap()["inputKind"],
        "policy"
    );
    let desc = format!("wsh(and_v(v:pk({}),older(100)))", KEY_A);
    assert_eq!(
        serde_json::to_value(analyze_impl(&desc, "auto").unwrap()).unwrap()["inputKind"],
        "descriptor"
    );
}

#[test]
fn invalid_input_errors() {
    assert!(analyze_impl("this is not miniscript", "auto").is_err());
    assert!(analyze_impl("", "auto").is_err());
    assert!(analyze_impl("wsh(and_v(v:pk(deadbeef),older(1)))", "auto").is_err());
    // malleable policy should fail compilation
    let malleable = format!("or(pk({}),pk({}))", KEY_A, KEY_A);
    assert!(analyze_impl(&malleable, "policy").is_err());
}

#[test]
fn script_ranges_templates_and_instructions() {
    let input = format!("wsh(and_v(v:pk({}),older(144)))", KEY_A);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let tree = &json["trees"][0];

    // flat script info with instructions reassembling into the asm string
    let script = &tree["script"];
    let hex = script["hex"].as_str().unwrap();
    assert!(hex.len() > 10);
    let instrs = script["instructions"].as_array().unwrap();
    assert!(instrs.len() >= 4);
    let joined: Vec<&str> = instrs.iter().map(|i| i["text"].as_str().unwrap()).collect();
    assert_eq!(joined.join(" "), script["asm"].as_str().unwrap());
    // instruction ranges are contiguous and cover the whole script
    assert_eq!(instrs[0]["start"], 0);
    for w in instrs.windows(2) {
        assert_eq!(w[0]["end"], w[1]["start"]);
    }
    assert_eq!(
        instrs.last().unwrap()["end"].as_u64().unwrap(),
        hex.len() as u64 / 2
    );

    // root node: whole-script range, template, subtree asm
    let root = &tree["root"];
    assert_eq!(root["scriptRange"], serde_json::json!([0, hex.len() / 2]));
    assert_eq!(root["template"], "<A> <B>");
    assert!(root["scriptAsm"]
        .as_str()
        .unwrap()
        .contains("OP_CHECKSIGVERIFY"));

    // older leaf: nested range with the right opcodes inside
    let older = &root["children"][1];
    assert_eq!(older["fragment"], "older");
    assert_eq!(older["template"], "<n> OP_CHECKSEQUENCEVERIFY");
    let [os, oe] = [
        older["scriptRange"][0].as_u64().unwrap() as usize,
        older["scriptRange"][1].as_u64().unwrap() as usize,
    ];
    assert!(os > 0 && oe <= hex.len() / 2);
    let older_hex = &hex[os * 2..oe * 2];
    assert!(
        older_hex.starts_with("029000"),
        "older leaf should push 144, got {older_hex}"
    );
}

#[test]
fn instruction_texts_align_on_empty_push() {
    // OP_0 iterates as an *empty* PushBytes instruction but renders in asm as
    // a single token ("OP_0", no hex part); positional token counting used to
    // swallow the next token ("OP_0 OP_ELSE") and shift every later
    // instruction, leaving a blank entry at the end.
    let input = format!(
        "wsh(thresh(2,pk({}),s:pk({}),snl:after(1765929600)))",
        KEY_A, KEY_B
    );
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let script = &json["trees"][0]["script"];
    let asm = script["asm"].as_str().unwrap();
    assert!(
        asm.contains("OP_0 OP_ELSE"),
        "expected OP_0 branch, got {asm}"
    );
    let instrs = script["instructions"].as_array().unwrap();
    let joined: Vec<&str> = instrs.iter().map(|i| i["text"].as_str().unwrap()).collect();
    assert_eq!(joined.join(" "), asm);
    assert!(instrs.iter().any(|i| i["text"] == "OP_0"));
    assert!(instrs
        .iter()
        .all(|i| !i["text"].as_str().unwrap().is_empty()));
}

#[test]
fn policy_tree_has_no_script_compiled_tree_does() {
    let input = format!("or(pk({}),and(pk({}),older(144)))", KEY_A, KEY_B);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    assert!(json["trees"][0]["script"].is_null());
    assert!(json["trees"][0]["root"].get("scriptAsm").is_none());
    let compiled = &json["trees"][1];
    assert!(compiled["script"]["instructions"].as_array().unwrap().len() > 3);
    assert!(compiled["root"]["scriptAsm"].as_str().is_some());
}

#[test]
fn taproot_leaf_scripts_have_ranges() {
    let input = format!("tr({},{{pk({}),pk({})}})", TR_INTERNAL, XONLY_G, XONLY_2G);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let leaf = &json["trees"][1];
    assert!(leaf["script"]["asm"]
        .as_str()
        .unwrap()
        .contains("OP_CHECKSIG"));
    let hex = leaf["script"]["hex"].as_str().unwrap();
    assert_eq!(
        leaf["root"]["scriptRange"],
        serde_json::json!([0, hex.len() / 2])
    );
    // x-only keys are 32 bytes on the wire
    assert_eq!(hex.len() / 2, 34);
}

#[test]
fn sortedmulti_template_without_ranges() {
    let input = format!("wsh(sortedmulti(2,{},{},{}))", KEY_A, KEY_B, KEY_C);
    let json = serde_json::to_value(analyze_impl(&input, "descriptor").unwrap()).unwrap();
    let root = &json["trees"][0]["root"];
    assert!(root["template"]
        .as_str()
        .unwrap()
        .contains("OP_CHECKMULTISIG"));
    assert!(root.get("scriptAsm").is_none());
}

#[test]
fn wildcard_descriptor_gets_concrete_ranges() {
    let input = format!("wsh(and_v(v:pk({}/0/*),older(144)))", XPUB);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let root = &json["trees"][0]["root"];
    assert!(root["scriptAsm"].as_str().unwrap().contains("OP_CSV"));
    // derived key (not the xpub) appears in the script
    let asm = root["scriptAsm"].as_str().unwrap();
    assert!(!asm.contains("xpub"));
}

#[test]
fn forced_modes_are_respected() {
    let policy = format!("and(pk({}),older(100))", KEY_A);
    assert!(analyze_impl(&policy, "descriptor").is_err());
    assert!(analyze_impl(&policy, "policy").is_ok());
}

/// Collect every AST node id of a tree JSON (depth-first).
fn collect_ids(node: &serde_json::Value, out: &mut Vec<String>) {
    out.push(node["id"].as_str().unwrap().to_string());
    if let Some(ch) = node["children"].as_array() {
        for c in ch {
            collect_ids(c, out);
        }
    }
}

/// Assert that every node id referenced by a tree's spend paths exists in
/// the tree's AST.
fn assert_path_ids_exist(tree: &serde_json::Value) {
    let mut ids = Vec::new();
    collect_ids(&tree["root"], &mut ids);
    for path in tree["paths"]["items"].as_array().unwrap() {
        for id in path["nodes"].as_array().unwrap() {
            assert!(
                ids.contains(&id.as_str().unwrap().to_string()),
                "path references unknown node id {id}"
            );
        }
    }
}

#[test]
fn spend_paths_and_v_single() {
    // a plain conjunction has exactly one spend path, listing both leaves
    let input = format!("wsh(and_v(v:pk({}),older(144)))", KEY_A);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let paths = &json["trees"][0]["paths"];
    assert_eq!(paths["total"], 1);
    assert_eq!(paths["capped"], false);
    let items = paths["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    // verify(check(pk_k)) leaf + older leaf
    assert_eq!(
        items[0]["nodes"],
        serde_json::json!(["0.0.0.0".to_string(), "0.1".to_string()])
    );
    assert_path_ids_exist(&json["trees"][0]);
}

#[test]
fn spend_paths_or_escrow_two_paths() {
    let input = format!("or(pk({}),and(pk({}),older(144)))", KEY_A, KEY_B);
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();

    // the policy tree carries no paths; the compiled miniscript tree does
    assert!(json["trees"][0].get("paths").is_none());
    let tree = &json["trees"][1];
    let paths = &tree["paths"];
    assert_eq!(paths["total"], 2);
    assert_eq!(paths["capped"], false);
    let items = paths["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // one path satisfies only the left key, the other the key + timelock
    let mut lens: Vec<usize> = items
        .iter()
        .map(|p| p["nodes"].as_array().unwrap().len())
        .collect();
    lens.sort_unstable();
    assert_eq!(lens, vec![1, 2]);
    assert_path_ids_exist(tree);
}

#[test]
fn spend_paths_and_or_htlc() {
    // or(and(pk(A),sha256(H)),and(pk(B),after(N))) compiles to an and_or
    let input = format!(
        "or(and(pk({}),sha256({})),and(pk({}),after(800000)))",
        KEY_A, SHA256_TEST, KEY_B
    );
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let tree = &json["trees"][1];
    assert!(tree["root"]["fragment"]
        .as_str()
        .unwrap()
        .starts_with("and_or"));
    let paths = &tree["paths"];
    assert_eq!(paths["total"], 2);
    let items = paths["items"].as_array().unwrap();
    // one path = key + sha256 preimage, other = key + CLTV
    for p in items {
        assert_eq!(p["nodes"].as_array().unwrap().len(), 2);
    }
    assert_path_ids_exist(tree);
}

#[test]
fn spend_paths_thresh_2_of_3() {
    let input = format!(
        "wsh(thresh(2,pk({}),s:pk({}),s:pk({})))",
        KEY_A, KEY_B, KEY_C
    );
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let paths = &json["trees"][0]["paths"];
    // C(3,2) = 3 ways, each satisfying two pk leaves
    assert_eq!(paths["total"], 3);
    assert_eq!(paths["capped"], false);
    for p in paths["items"].as_array().unwrap() {
        assert_eq!(p["nodes"].as_array().unwrap().len(), 2);
    }
    assert_path_ids_exist(&json["trees"][0]);
}

#[test]
fn spend_paths_sortedmulti_combinations() {
    let input = format!("wsh(sortedmulti(2,{},{},{}))", KEY_A, KEY_B, KEY_C);
    let json = serde_json::to_value(analyze_impl(&input, "descriptor").unwrap()).unwrap();
    let paths = &json["trees"][0]["paths"];
    assert_eq!(paths["total"], 3);
    let combos: Vec<Vec<String>> = paths["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            p["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_string())
                .collect()
        })
        .collect();
    assert_eq!(
        combos,
        vec![
            vec!["0.0".to_string(), "0.1".to_string()],
            vec!["0.0".to_string(), "0.2".to_string()],
            vec!["0.1".to_string(), "0.2".to_string()],
        ]
    );
}

#[test]
fn spend_paths_bare_multi() {
    let input = format!("wsh(multi(2,{},{},{}))", KEY_A, KEY_B, KEY_C);
    let json = serde_json::to_value(analyze_impl(&input, "descriptor").unwrap()).unwrap();
    let paths = &json["trees"][0]["paths"];
    assert_eq!(paths["total"], 3);
    for p in paths["items"].as_array().unwrap() {
        assert_eq!(p["nodes"].as_array().unwrap().len(), 2);
    }
    assert_path_ids_exist(&json["trees"][0]);
}

#[test]
fn spend_paths_capped_when_huge() {
    // C(8,4) = 70 paths exceed the display cap of 64
    let input = format!(
        "wsh(thresh(4,pk({0}),s:pk({1}),s:pk({2}),s:pk({0}),s:pk({1}),s:pk({2}),s:pk({0}),s:pk({1})))",
        KEY_A, KEY_B, KEY_C
    );
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let paths = &json["trees"][0]["paths"];
    assert_eq!(paths["total"], 70);
    assert_eq!(paths["capped"], true);
    assert_eq!(paths["items"].as_array().unwrap().len(), 64);
}

#[test]
fn spend_paths_single_key_descriptors() {
    for input in [
        format!("pkh({})", KEY_A),
        format!("wpkh({})", KEY_A),
        format!("tr({})", TR_INTERNAL),
    ] {
        let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
        let paths = &json["trees"][0]["paths"];
        assert_eq!(paths["total"], 1, "{input}");
        assert_eq!(paths["items"][0]["nodes"], serde_json::json!(["0"]));
    }
}

#[test]
fn and_or_timelock_branch_gets_script_ranges() {
    // `and_or(A,B,C)` encodes out of AST order: `<A> OP_NOTIF <C> OP_ELSE <B>
    // OP_ENDIF`. The C branch (typically an after/older timelock path) must
    // still receive a byte range so the codepath highlighter works.
    let input = format!(
        "or(and(pk({}),sha256({})),and(pk({}),after(800000)))",
        KEY_A, SHA256_TEST, KEY_B
    );
    let json = serde_json::to_value(analyze_impl(&input, "auto").unwrap()).unwrap();
    let tree = &json["trees"][1]; // compiled witness script
    let hex = tree["script"]["hex"].as_str().unwrap();
    let root = &tree["root"];
    assert!(root["fragment"].as_str().unwrap().starts_with("and_or"));

    // all three branches have ranges inside the root script
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for child in root["children"].as_array().unwrap() {
        let s = child["scriptRange"][0].as_u64().unwrap() as usize;
        let e = child["scriptRange"][1].as_u64().unwrap() as usize;
        assert!(s < e && e <= hex.len() / 2, "branch range within script");
        ranges.push((s, e));
    }
    ranges.sort_unstable();

    // the gaps between the sorted branch ranges are exactly the routing
    // opcodes: OP_NOTIF between A and C, OP_ELSE between C and B, OP_ENDIF
    // closing the root
    let re = root["scriptRange"][1].as_u64().unwrap() as usize;
    let gap = |a: usize, b: usize| &hex[a * 2..b * 2];
    assert_eq!(ranges[0].0, 0);
    assert_eq!(gap(ranges[0].1, ranges[1].0), "64"); // OP_NOTIF
    assert_eq!(gap(ranges[1].1, ranges[2].0), "67"); // OP_ELSE
    assert_eq!(gap(ranges[2].1, re), "68"); // OP_ENDIF

    // the after() leaf deep inside the C branch highlights: its range ends at
    // the CLTV opcode
    let and_v = &root["children"][2];
    let after = &and_v["children"][1];
    assert_eq!(after["fragment"], "after");
    let s = after["scriptRange"][0].as_u64().unwrap() as usize;
    let e = after["scriptRange"][1].as_u64().unwrap() as usize;
    assert!(
        hex[s * 2..e * 2].ends_with("b1"),
        "after() range should end at OP_CHECKLOCKTIMEVERIFY"
    );

    // every node in the tree except a `check` directly under `verify` (whose
    // final opcode is rewritten to its VERIFY form by the parent) has a range
    fn assert_ranged(node: &serde_json::Value, under_verify: bool) {
        let frag = node["fragment"].as_str().unwrap();
        let is_check = frag.starts_with("check");
        assert!(
            !(under_verify && is_check) || node["scriptRange"].is_null(),
            "check-under-verify must stay unranged"
        );
        if !(under_verify && is_check) {
            assert!(
                node["scriptRange"].is_array(),
                "{frag} ({}) missing scriptRange",
                node["id"].as_str().unwrap()
            );
        }
        for c in node["children"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            assert_ranged(c, frag.starts_with("verify"));
        }
    }
    assert_ranged(root, false);
}
