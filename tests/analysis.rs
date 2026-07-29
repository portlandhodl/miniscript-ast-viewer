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
fn forced_modes_are_respected() {
    let policy = format!("and(pk({}),older(100))", KEY_A);
    assert!(analyze_impl(&policy, "descriptor").is_err());
    assert!(analyze_impl(&policy, "policy").is_ok());
}
