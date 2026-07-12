// SPDX-License-Identifier: Apache-2.0

//! ADR-0038 wire-format conformance against the same artifact consumed by the
//! JavaScript verifier. No experimental PQ primitive is linked here.

use serde_json::Value;

const NORMAL_SIGNATURE_COMPONENTS: &[&str] = &["ed25519", "ml-dsa-65"];
const HIGH_ASSURANCE_SIGNATURE_COMPONENTS: &[&str] = &["ed25519", "ml-dsa-87"];

struct EncodedEnvelope {
    unsigned_header: Vec<u8>,
    ciphertext_body: Vec<u8>,
}

fn load_vectors() -> Value {
    serde_json::from_str(include_str!("../../test_vectors/pq_envelope_v1.json"))
        .expect("parse pq_envelope_v1.json")
}

fn str_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field `{field}`"))
}

fn u64_field(value: &Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing integer field `{field}`"))
}

fn suite<'a>(vectors: &'a Value, suite_name: &str) -> &'a Value {
    vectors["suites"]
        .get(suite_name)
        .unwrap_or_else(|| panic!("unsupported-suite:{suite_name}"))
}

fn required_signature_components(suite_name: &str) -> &'static [&'static str] {
    match suite_name {
        "normal" => NORMAL_SIGNATURE_COMPONENTS,
        "high_assurance" => HIGH_ASSURANCE_SIGNATURE_COMPONENTS,
        _ => panic!("unsupported-suite:{suite_name}"),
    }
}

fn lp(value: &[u8]) -> Vec<u8> {
    let length = u32::try_from(value.len()).expect("LP field length fits u32");
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    encoded
}

fn append_lp(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&lp(value));
}

fn u16_be(value: usize) -> [u8; 2] {
    u16::try_from(value).expect("count fits u16").to_be_bytes()
}

fn hash_hex(value: &[u8]) -> String {
    blake3::hash(value).to_hex().to_string()
}

fn fill_byte(value: &Value, field: &str) -> u8 {
    u8::from_str_radix(str_field(value, field), 16).expect("valid fill byte")
}

fn sender_key_id<'a>(vectors: &'a Value, field: &str, suite_name: &str) -> &'a str {
    if field == "sender_ml_dsa_key_id" {
        return str_field(suite(vectors, suite_name), field);
    }
    str_field(&vectors["base"], field)
}

fn recipient(
    vectors: &Value,
    index: usize,
    swapped_kem_key_id: Option<&str>,
    suite_name: &str,
) -> Vec<u8> {
    let template = &vectors["recipient_template"];
    let suite = suite(vectors, suite_name);
    let substitute = |value: &str| value.replace("{index}", &index.to_string());
    let identity_id = substitute(str_field(template, "identity_id"));
    let kem_key_id = swapped_kem_key_id
        .map(str::to_owned)
        .unwrap_or_else(|| substitute(str_field(suite, "recipient_kem_key_id")));
    let fields = [
        identity_id.into_bytes(),
        kem_key_id.into_bytes(),
        vec![fill_byte(template, "public_key_blake3_byte"); 32],
        vec![
            fill_byte(template, "kem_ciphertext_byte");
            u64_field(suite, "kem_ciphertext_length") as usize
        ],
        vec![fill_byte(template, "aead_nonce_byte"); 24],
    ];

    let mut encoded = Vec::new();
    for field in fields {
        append_lp(&mut encoded, &field);
    }
    encoded
}

fn encode(
    vectors: &Value,
    recipient_count: usize,
    swapped_kem_key_id: Option<&str>,
    suite_name: &str,
) -> EncodedEnvelope {
    let base = &vectors["base"];
    let suite = suite(vectors, suite_name);
    let global = [
        str_field(vectors, "wire_schema"),
        str_field(base, "protocol_version"),
        str_field(suite, "signature_suite_id"),
        str_field(suite, "kem_algorithm_id"),
        str_field(suite, "kem_parameter_set"),
        str_field(suite, "kdf_algorithm_id"),
        str_field(suite, "aead_algorithm_id"),
        str_field(base, "sender_identity_id"),
        str_field(base, "sender_ed25519_key_id"),
        str_field(suite, "sender_ml_dsa_key_id"),
        str_field(base, "object_id"),
    ];

    let mut unsigned_header = Vec::new();
    for field in global {
        append_lp(&mut unsigned_header, field.as_bytes());
    }
    unsigned_header.extend_from_slice(&u16_be(recipient_count));

    let mut ciphertext_body = Vec::new();
    ciphertext_body.extend_from_slice(&u16_be(recipient_count));
    for index in 0..recipient_count {
        append_lp(
            &mut unsigned_header,
            &recipient(vectors, index, swapped_kem_key_id, suite_name),
        );
        append_lp(
            &mut ciphertext_body,
            &vec![
                fill_byte(
                    &vectors["recipient_template"],
                    "aead_ciphertext_and_tag_byte"
                );
                48
            ],
        );
    }

    EncodedEnvelope {
        unsigned_header,
        ciphertext_body,
    }
}

fn signed_digest(vectors: &Value, unsigned_header: &[u8], ciphertext_body: &[u8]) -> String {
    let mut input = str_field(vectors, "signature_prefix_utf8")
        .as_bytes()
        .to_vec();
    append_lp(&mut input, unsigned_header);
    append_lp(&mut input, ciphertext_body);
    hash_hex(&input)
}

fn parse_lp<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if input.len().saturating_sub(*offset) < 4 {
        return Err("truncated-length-prefix".to_string());
    }
    let length = u32::from_be_bytes(
        input[*offset..*offset + 4]
            .try_into()
            .expect("four-byte length"),
    ) as usize;
    let start = *offset + 4;
    let end = start
        .checked_add(length)
        .ok_or_else(|| "length-prefix-overrun".to_string())?;
    if end > input.len() {
        return Err("length-prefix-overrun".to_string());
    }
    *offset = end;
    Ok(&input[start..end])
}

fn validate_recipient_count(count: usize) -> Result<(), String> {
    if !(1..=64).contains(&count) {
        return Err("recipient-count-out-of-range".to_string());
    }
    Ok(())
}

fn require_hybrid_signatures(components: &[String], suite_name: &str) -> Result<(), String> {
    let required = required_signature_components(suite_name);
    for component in components {
        if !required.contains(&component.as_str()) {
            return Err(format!("unknown-signature-component:{component}"));
        }
    }
    for required_component in required {
        let count = components
            .iter()
            .filter(|component| component.as_str() == *required_component)
            .count();
        if count == 0 {
            return Err(format!("missing-required-signature:{required_component}"));
        }
        if count > 1 {
            return Err(format!(
                "duplicate-signature-component:{required_component}"
            ));
        }
    }
    if components
        .iter()
        .map(String::as_str)
        .ne(required.iter().copied())
    {
        return Err("non-canonical-signature-component-order".to_string());
    }
    Ok(())
}

fn signature_components(vector: &Value) -> Vec<String> {
    vector["signature_components"]
        .as_array()
        .expect("signature_components array")
        .iter()
        .map(|component| component.as_str().expect("component string").to_string())
        .collect()
}

fn encode_signature_component(vectors: &Value, name: &str, suite_name: &str) -> Vec<u8> {
    let template = vectors["signature_section"]["components"]
        .get(name)
        .unwrap_or_else(|| panic!("unknown-signature-component:{name}"));
    let fields = [
        str_field(template, "algorithm_id").as_bytes().to_vec(),
        str_field(template, "parameter_set").as_bytes().to_vec(),
        sender_key_id(
            vectors,
            str_field(template, "sender_key_id_field"),
            suite_name,
        )
        .as_bytes()
        .to_vec(),
        vec![
            fill_byte(template, "signature_byte");
            u64_field(template, "signature_length") as usize
        ],
    ];
    let mut encoded = Vec::new();
    for field in fields {
        append_lp(&mut encoded, &field);
    }
    encoded
}

fn encode_signature_section(vectors: &Value, components: &[String], suite_name: &str) -> Vec<u8> {
    let mut encoded = u16_be(components.len()).to_vec();
    for component in components {
        append_lp(
            &mut encoded,
            &encode_signature_component(vectors, component, suite_name),
        );
    }
    encoded
}

// Validates signature-component wire framing, metadata, and expected signature
// length only. Static vector signatures are framing fillers; this does not
// verify or imply Ed25519 or ML-DSA authenticity.
fn parse_signature_component(
    vectors: &Value,
    input: &[u8],
    suite_name: &str,
) -> Result<String, String> {
    let mut fields = Vec::with_capacity(4);
    let mut offset = 0;
    for _ in 0..4 {
        fields.push(parse_lp(input, &mut offset)?);
    }
    if offset != input.len() {
        return Err("extra-signature-component-data".to_string());
    }

    let templates = vectors["signature_section"]["components"]
        .as_object()
        .expect("signature components object");
    for (name, template) in templates {
        let key_id = sender_key_id(
            vectors,
            str_field(template, "sender_key_id_field"),
            suite_name,
        );
        if fields[0] == str_field(template, "algorithm_id").as_bytes()
            && fields[1] == str_field(template, "parameter_set").as_bytes()
            && fields[2] == key_id.as_bytes()
            && fields[3].len() == u64_field(template, "signature_length") as usize
        {
            return Ok(name.clone());
        }
    }
    Err("unknown-or-malformed-signature-component".to_string())
}

fn parse_signature_section(
    vectors: &Value,
    input: &[u8],
    suite_name: &str,
) -> Result<Vec<String>, String> {
    if input.len() < 2 {
        return Err("truncated-signature-component-count".to_string());
    }
    let count = u16::from_be_bytes(input[..2].try_into().expect("two-byte count")) as usize;
    let mut components = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        let component = parse_lp(input, &mut offset)?;
        components.push(parse_signature_component(vectors, component, suite_name)?);
    }
    if offset != input.len() {
        return Err("extra-signature-section-data".to_string());
    }
    require_hybrid_signatures(&components, suite_name)?;
    Ok(components)
}

fn validate_suite_definitions(vectors: &Value) {
    let fields = [
        "signature_suite_id",
        "kem_algorithm_id",
        "kem_parameter_set",
        "kdf_algorithm_id",
        "aead_algorithm_id",
    ];
    let suites = vectors["suites"].as_object().expect("suites object");
    for (suite_name, suite) in suites {
        for field in fields {
            assert_eq!(
                hex::encode(lp(str_field(suite, field).as_bytes())),
                str_field(&suite["canonical_lp_hex"], field),
                "canonical LP mismatch for {suite_name}.{field}"
            );
        }
        let component_order: Vec<&str> = vectors["signature_section"]["component_order"]
            [suite_name]
            .as_array()
            .expect("component order array")
            .iter()
            .map(|component| component.as_str().expect("component string"))
            .collect();
        assert_eq!(
            component_order,
            required_signature_components(suite_name),
            "component order mismatch for {suite_name}"
        );
    }

    let normal = suite(vectors, "normal");
    for field in fields {
        assert_eq!(str_field(&vectors["base"], field), str_field(normal, field));
    }
    assert_eq!(
        u64_field(&vectors["signature_section"], "component_count"),
        2
    );
    assert_eq!(
        str_field(&vectors["base"], "sender_ml_dsa_key_id"),
        str_field(normal, "sender_ml_dsa_key_id")
    );
    assert_eq!(
        str_field(&vectors["recipient_template"], "kem_key_id"),
        str_field(normal, "recipient_kem_key_id")
    );
}

fn assert_reject<T>(result: Result<T, String>, expected: &str, vector_id: &str) {
    match result {
        Err(actual) => assert_eq!(actual, expected, "wrong rejection for {vector_id}"),
        Ok(_) => panic!("vector {vector_id} unexpectedly accepted"),
    }
}

fn expected_error(vector: &Value) -> &str {
    str_field(vector, "expected")
        .strip_prefix("reject:")
        .expect("rejection vector")
}

#[test]
fn pq_envelope_vectors_conform() {
    let vectors = load_vectors();
    validate_suite_definitions(&vectors);

    for vector in vectors["vectors"].as_array().expect("vectors array") {
        let vector_id = str_field(vector, "id");
        let suite_name = vector
            .get("suite")
            .and_then(Value::as_str)
            .unwrap_or("normal");
        let expected = str_field(vector, "expected");

        if expected == "accept" {
            let encoded = encode(
                &vectors,
                u64_field(vector, "recipient_count") as usize,
                None,
                suite_name,
            );
            assert_eq!(
                hash_hex(&encoded.unsigned_header),
                str_field(vector, "expected_unsigned_header_blake3_hex"),
                "unsigned-header hash mismatch for {vector_id}"
            );
            assert_eq!(
                hash_hex(&encoded.ciphertext_body),
                str_field(vector, "expected_ciphertext_body_blake3_hex"),
                "ciphertext-body hash mismatch for {vector_id}"
            );
            assert_eq!(
                signed_digest(&vectors, &encoded.unsigned_header, &encoded.ciphertext_body),
                str_field(vector, "expected_signed_digest_hex"),
                "signed digest mismatch for {vector_id}"
            );
        } else if expected.contains("recipient-count-out-of-range") {
            assert_reject(
                validate_recipient_count(u64_field(vector, "recipient_count") as usize),
                expected_error(vector),
                vector_id,
            );
        } else if let Some(raw) = vector
            .get("raw_unsigned_header_hex")
            .and_then(Value::as_str)
        {
            let raw = hex::decode(raw).expect("raw unsigned-header hex");
            let mut offset = 0;
            assert_reject(
                parse_lp(&raw, &mut offset).map(|_| ()),
                expected_error(vector),
                vector_id,
            );
        } else if expected == "reject:signature-digest-mismatch" {
            let recipient_count = u64_field(vector, "recipient_count") as usize;
            let original = encode(&vectors, recipient_count, None, suite_name);
            let swapped = encode(
                &vectors,
                recipient_count,
                Some(str_field(vector, "swap_recipient_kem_key_id")),
                suite_name,
            );
            let original_digest = signed_digest(
                &vectors,
                &original.unsigned_header,
                &original.ciphertext_body,
            );
            let swapped_digest =
                signed_digest(&vectors, &swapped.unsigned_header, &swapped.ciphertext_body);
            assert_eq!(
                original_digest,
                str_field(vector, "expected_original_signed_digest_hex")
            );
            assert_eq!(
                swapped_digest,
                str_field(vector, "expected_swapped_signed_digest_hex")
            );
            assert_ne!(original_digest, swapped_digest);
        } else if expected == "accept:signature-section-framing" {
            let components = signature_components(vector);
            let signature_section = encode_signature_section(&vectors, &components, suite_name);
            let parsed = parse_signature_section(&vectors, &signature_section, suite_name)
                .unwrap_or_else(|error| panic!("{vector_id} rejected: {error}"));
            let required: Vec<String> = required_signature_components(suite_name)
                .iter()
                .map(|component| (*component).to_string())
                .collect();
            assert_eq!(parsed, required);
            assert_eq!(
                hash_hex(&signature_section),
                str_field(vector, "expected_signature_section_blake3_hex")
            );
        } else if vector.get("raw_signature_section_hex").is_some()
            || vector.get("signature_section_mutation").is_some()
        {
            let mut signature_section = if let Some(raw) = vector
                .get("raw_signature_section_hex")
                .and_then(Value::as_str)
            {
                hex::decode(raw).expect("raw signature-section hex")
            } else {
                encode_signature_section(&vectors, &signature_components(vector), suite_name)
            };

            if let Some(mutation) = vector
                .get("signature_section_mutation")
                .and_then(Value::as_str)
            {
                match mutation {
                    "declare-one-component" => {
                        signature_section[..2].copy_from_slice(&1u16.to_be_bytes());
                    }
                    "append-trailing-byte" => signature_section.push(0),
                    "truncate-last-byte" => {
                        signature_section
                            .pop()
                            .expect("non-empty signature section");
                    }
                    _ => panic!("unhandled signature-section mutation: {mutation}"),
                }
            }

            assert_reject(
                parse_signature_section(&vectors, &signature_section, suite_name),
                expected_error(vector),
                vector_id,
            );
        } else if vector.get("signature_components").is_some() {
            assert_reject(
                require_hybrid_signatures(&signature_components(vector), suite_name),
                expected_error(vector),
                vector_id,
            );
        } else {
            panic!("unhandled PQ envelope vector: {vector_id}");
        }
    }
}
