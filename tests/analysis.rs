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
