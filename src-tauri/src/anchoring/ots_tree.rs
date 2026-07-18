// SPDX-License-Identifier: Apache-2.0

//! Bounded OpenTimestamps `Timestamp` tree parser and merger.
//!
//! Calendar `/timestamp/<commitment>` responses are serialized Timestamp
//! subtrees rooted at `<commitment>`. They are not complete receipts rooted at
//! the originally submitted digest. A correct upgrade parses that subtree with
//! the pending commitment as its initial message, requires a Bitcoin
//! attestation, then merges the subtree into the matching pending node.

use sha2::{Digest, Sha256};

use super::ots_format::{OtsParseError, MAX_RECEIPT_BYTES};

const MAX_DEPTH: usize = 64;
const MAX_MESSAGE_BYTES: usize = 4096;
const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BitcoinAttestation {
    pub block_height: u64,
    pub merkle_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Timestamp {
    msg: Vec<u8>,
    items: Vec<Item>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Attestation {
        tag: [u8; 8],
        payload: Vec<u8>,
    },
    Operation {
        op: Operation,
        child: Box<Timestamp>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    Sha256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
}

pub(super) fn extract_pending_commitment(
    receipt: &[u8],
    initial_msg: &[u8],
    calendar_url: &str,
) -> Result<Vec<u8>, OtsParseError> {
    let tree = parse_tree(receipt, initial_msg)?;
    let target = calendar_url.trim_end_matches('/').as_bytes();
    find_pending(&tree, target)?
        .cloned()
        .ok_or_else(|| OtsParseError::UrlNotFound {
            url: calendar_url.to_owned(),
        })
}

pub(super) fn require_bitcoin_after(
    receipt: &[u8],
    initial_msg: &[u8],
    required_ancestor: &[u8],
) -> Result<BitcoinAttestation, OtsParseError> {
    let tree = parse_tree(receipt, initial_msg)?;
    find_bitcoin(&tree, required_ancestor, false)?.ok_or(OtsParseError::MissingBitcoinAttestation)
}

/// Merge a calendar response into the original pending receipt and serialize a
/// complete Timestamp body rooted at `original_hash`.
pub(super) fn merge_calendar_upgrade(
    pending_receipt: &[u8],
    original_hash: &[u8],
    calendar_url: &str,
    calendar_response: &[u8],
) -> Result<(Vec<u8>, BitcoinAttestation), OtsParseError> {
    let mut pending = parse_tree(pending_receipt, original_hash)?;
    let target_url = calendar_url.trim_end_matches('/').as_bytes();
    let commitment = find_pending(&pending, target_url)?
        .cloned()
        .ok_or_else(|| OtsParseError::UrlNotFound {
            url: calendar_url.to_owned(),
        })?;

    // The wire response omits its root message. Supplying the commitment here
    // is the protocol binding performed by the reference client's
    // `Timestamp.deserialize(..., commitment)` before `sub_stamp.merge(...)`.
    let upgrade = parse_tree(calendar_response, &commitment)?;
    let bitcoin = find_bitcoin(&upgrade, &commitment, true)?
        .ok_or(OtsParseError::MissingBitcoinAttestation)?;

    let mut upgrade_items = Some(upgrade.items);
    if !merge_at_pending(&mut pending, target_url, &commitment, &mut upgrade_items)? {
        return Err(OtsParseError::Malformed {
            detail: "matching pending node disappeared during merge".to_owned(),
        });
    }

    let mut merged = Vec::new();
    serialize_timestamp(&pending, &mut merged)?;
    if merged.len() > MAX_RECEIPT_BYTES {
        return Err(OtsParseError::AttestationTooLong { len: merged.len() });
    }

    // Defense in depth: round-trip the exact bytes that will be persisted and
    // prove the Bitcoin branch is still reachable from the original digest.
    let reparsed = parse_tree(&merged, original_hash)?;
    let reparsed_bitcoin = find_bitcoin(&reparsed, &commitment, false)?
        .ok_or(OtsParseError::MissingBitcoinAttestation)?;
    if reparsed_bitcoin != bitcoin {
        return Err(OtsParseError::Malformed {
            detail: "Bitcoin attestation changed during receipt merge".to_owned(),
        });
    }
    Ok((merged, bitcoin))
}

fn parse_tree(bytes: &[u8], initial_msg: &[u8]) -> Result<Timestamp, OtsParseError> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(OtsParseError::AttestationTooLong { len: bytes.len() });
    }
    if initial_msg.len() > MAX_MESSAGE_BYTES {
        return Err(OtsParseError::MessageTooLong {
            len: initial_msg.len(),
        });
    }
    let mut cursor = Cursor::new(bytes);
    let tree = parse_timestamp(&mut cursor, initial_msg.to_vec(), 0)?;
    if !cursor.is_eof() {
        return Err(OtsParseError::Malformed {
            detail: format!("trailing data at offset {}", cursor.pos),
        });
    }
    Ok(tree)
}

fn parse_timestamp(
    cursor: &mut Cursor<'_>,
    msg: Vec<u8>,
    depth: usize,
) -> Result<Timestamp, OtsParseError> {
    if depth > MAX_DEPTH {
        return Err(OtsParseError::DepthExceeded {
            max: MAX_DEPTH,
            offset: cursor.pos,
        });
    }
    let mut items = Vec::new();
    let mut tag = cursor.read_u8()?;
    while tag == 0xff {
        let item_tag = cursor.read_u8()?;
        items.push(parse_item(cursor, &msg, item_tag, depth)?);
        tag = cursor.read_u8()?;
    }
    items.push(parse_item(cursor, &msg, tag, depth)?);
    Ok(Timestamp { msg, items })
}

fn parse_item(
    cursor: &mut Cursor<'_>,
    msg: &[u8],
    tag: u8,
    depth: usize,
) -> Result<Item, OtsParseError> {
    if tag == 0x00 {
        let tag: [u8; 8] =
            cursor
                .read_bytes(8)?
                .try_into()
                .map_err(|_| OtsParseError::Malformed {
                    detail: "attestation tag is not 8 bytes".to_owned(),
                })?;
        let payload_len = cursor.read_varint()?;
        if payload_len > MAX_RECEIPT_BYTES {
            return Err(OtsParseError::AttestationTooLong { len: payload_len });
        }
        let payload = cursor.read_bytes(payload_len)?.to_vec();
        return Ok(Item::Attestation { tag, payload });
    }

    let op = match tag {
        0x08 => Operation::Sha256,
        0xf0 | 0xf1 => {
            let arg_len = cursor.read_varint()?;
            if arg_len > MAX_MESSAGE_BYTES {
                return Err(OtsParseError::MessageTooLong { len: arg_len });
            }
            let arg = cursor.read_bytes(arg_len)?.to_vec();
            if tag == 0xf0 {
                Operation::Append(arg)
            } else {
                Operation::Prepend(arg)
            }
        }
        _ => {
            return Err(OtsParseError::UnknownOpTag {
                tag,
                offset: cursor.pos.saturating_sub(1),
            });
        }
    };
    let child_msg = apply_operation(&op, msg)?;
    let child = parse_timestamp(cursor, child_msg, depth + 1)?;
    Ok(Item::Operation {
        op,
        child: Box::new(child),
    })
}

fn apply_operation(op: &Operation, msg: &[u8]) -> Result<Vec<u8>, OtsParseError> {
    let result = match op {
        Operation::Sha256 => Sha256::digest(msg).to_vec(),
        Operation::Append(arg) => {
            let len = msg
                .len()
                .checked_add(arg.len())
                .ok_or(OtsParseError::MessageTooLong { len: usize::MAX })?;
            if len > MAX_MESSAGE_BYTES {
                return Err(OtsParseError::MessageTooLong { len });
            }
            let mut combined = Vec::with_capacity(len);
            combined.extend_from_slice(msg);
            combined.extend_from_slice(arg);
            combined
        }
        Operation::Prepend(arg) => {
            let len = msg
                .len()
                .checked_add(arg.len())
                .ok_or(OtsParseError::MessageTooLong { len: usize::MAX })?;
            if len > MAX_MESSAGE_BYTES {
                return Err(OtsParseError::MessageTooLong { len });
            }
            let mut combined = Vec::with_capacity(len);
            combined.extend_from_slice(arg);
            combined.extend_from_slice(msg);
            combined
        }
    };
    Ok(result)
}

fn pending_url(payload: &[u8]) -> Result<&[u8], OtsParseError> {
    let mut cursor = Cursor::new(payload);
    let len = cursor.read_varint()?;
    let url = cursor.read_bytes(len)?;
    if !cursor.is_eof() {
        return Err(OtsParseError::Malformed {
            detail: "pending-attestation URI payload has trailing bytes".to_owned(),
        });
    }
    Ok(trim_slashes(url))
}

fn find_pending<'a>(
    node: &'a Timestamp,
    target_url: &[u8],
) -> Result<Option<&'a Vec<u8>>, OtsParseError> {
    for item in &node.items {
        if let Item::Attestation { tag, payload } = item {
            if *tag == PENDING_TAG && pending_url(payload)? == target_url {
                return Ok(Some(&node.msg));
            }
        }
    }
    for item in &node.items {
        if let Item::Operation { child, .. } = item {
            if let Some(found) = find_pending(child, target_url)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn parse_bitcoin_height(payload: &[u8]) -> Result<u64, OtsParseError> {
    let mut cursor = Cursor::new(payload);
    let height = cursor
        .read_varint()
        .map_err(|_| OtsParseError::InvalidBitcoinAttestation { len: payload.len() })?;
    if !cursor.is_eof() {
        return Err(OtsParseError::InvalidBitcoinAttestation { len: payload.len() });
    }
    Ok(height as u64)
}

fn find_bitcoin(
    node: &Timestamp,
    required_ancestor: &[u8],
    ancestor_reached: bool,
) -> Result<Option<BitcoinAttestation>, OtsParseError> {
    let reached = ancestor_reached || node.msg == required_ancestor;
    for item in &node.items {
        if let Item::Attestation { tag, payload } = item {
            if *tag == BITCOIN_TAG && reached {
                let merkle_root: [u8; 32] =
                    node.msg
                        .as_slice()
                        .try_into()
                        .map_err(|_| OtsParseError::Malformed {
                            detail: format!(
                                "Bitcoin attestation message is {} bytes, expected 32",
                                node.msg.len()
                            ),
                        })?;
                return Ok(Some(BitcoinAttestation {
                    block_height: parse_bitcoin_height(payload)?,
                    merkle_root,
                }));
            }
        }
    }
    for item in &node.items {
        if let Item::Operation { child, .. } = item {
            if let Some(found) = find_bitcoin(child, required_ancestor, reached)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn merge_at_pending(
    node: &mut Timestamp,
    target_url: &[u8],
    commitment: &[u8],
    upgrade_items: &mut Option<Vec<Item>>,
) -> Result<bool, OtsParseError> {
    let mut has_matching_pending = false;
    if node.msg == commitment {
        for item in &node.items {
            if let Item::Attestation { tag, payload } = item {
                if *tag == PENDING_TAG && pending_url(payload)? == target_url {
                    has_matching_pending = true;
                    break;
                }
            }
        }
    }
    if has_matching_pending {
        let items = upgrade_items
            .take()
            .ok_or_else(|| OtsParseError::Malformed {
                detail: "calendar upgrade matched more than one pending node".to_owned(),
            })?;
        merge_items(node, items)?;
        return Ok(true);
    }
    for item in &mut node.items {
        if let Item::Operation { child, .. } = item {
            if merge_at_pending(child, target_url, commitment, upgrade_items)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Merge a Timestamp subtree without duplicating an operation branch. OTS
/// upgrades may repeat the pending receipt's operations while adding an
/// attestation deeper in the same branch, so matching operations must be
/// merged recursively rather than appended as parallel copies.
fn merge_items(node: &mut Timestamp, incoming: Vec<Item>) -> Result<(), OtsParseError> {
    for item in incoming {
        match item {
            Item::Operation { op, child } => {
                if let Some(Item::Operation {
                    child: existing, ..
                }) = node.items.iter_mut().find(|candidate| {
                    matches!(candidate, Item::Operation { op: existing_op, .. } if *existing_op == op)
                }) {
                    if existing.msg != child.msg {
                        return Err(OtsParseError::Malformed {
                            detail: "matching OTS operation produced a different child message"
                                .to_owned(),
                        });
                    }
                    merge_items(existing, child.items)?;
                } else {
                    node.items.push(Item::Operation { op, child });
                }
            }
            attestation @ Item::Attestation { .. } => {
                if !node.items.contains(&attestation) {
                    node.items.push(attestation);
                }
            }
        }
    }
    Ok(())
}

fn serialize_timestamp(node: &Timestamp, output: &mut Vec<u8>) -> Result<(), OtsParseError> {
    if node.items.is_empty() {
        return Err(OtsParseError::Malformed {
            detail: "cannot serialize an empty Timestamp node".to_owned(),
        });
    }
    for (index, item) in node.items.iter().enumerate() {
        if index + 1 < node.items.len() {
            output.push(0xff);
        }
        serialize_item(item, output)?;
    }
    Ok(())
}

fn serialize_item(item: &Item, output: &mut Vec<u8>) -> Result<(), OtsParseError> {
    match item {
        Item::Attestation { tag, payload } => {
            output.push(0x00);
            output.extend_from_slice(tag);
            write_varint(output, payload.len());
            output.extend_from_slice(payload);
        }
        Item::Operation { op, child } => {
            match op {
                Operation::Sha256 => output.push(0x08),
                Operation::Append(arg) => {
                    output.push(0xf0);
                    write_varint(output, arg.len());
                    output.extend_from_slice(arg);
                }
                Operation::Prepend(arg) => {
                    output.push(0xf1);
                    write_varint(output, arg.len());
                    output.extend_from_slice(arg);
                }
            }
            serialize_timestamp(child, output)?;
        }
    }
    Ok(())
}

fn trim_slashes(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

fn write_varint(output: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_u8(&mut self) -> Result<u8, OtsParseError> {
        let byte = *self.bytes.get(self.pos).ok_or(OtsParseError::Truncated {
            offset: self.pos,
            expected: 1,
        })?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], OtsParseError> {
        let end = self.pos.checked_add(len).ok_or(OtsParseError::Truncated {
            offset: self.pos,
            expected: len,
        })?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or(OtsParseError::Truncated {
                offset: self.pos,
                expected: len,
            })?;
        self.pos = end;
        Ok(bytes)
    }

    fn read_varint(&mut self) -> Result<usize, OtsParseError> {
        let start = self.pos;
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = u64::from(self.read_u8()?);
            if shift == 63 && byte > 1 {
                return Err(OtsParseError::VarintTooLong { offset: start });
            }
            value |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return usize::try_from(value)
                    .map_err(|_| OtsParseError::VarintTooLong { offset: start });
            }
        }
        Err(OtsParseError::VarintTooLong { offset: start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(url: &str, suffix: &[u8]) -> Vec<u8> {
        let mut out = vec![0xf0];
        write_varint(&mut out, suffix.len());
        out.extend_from_slice(suffix);
        out.push(0x00);
        out.extend_from_slice(&PENDING_TAG);
        let mut payload = Vec::new();
        write_varint(&mut payload, url.len());
        payload.extend_from_slice(url.as_bytes());
        write_varint(&mut out, payload.len());
        out.extend_from_slice(&payload);
        out
    }

    fn bitcoin_upgrade(height: usize) -> Vec<u8> {
        let mut out = vec![0x08, 0x00];
        out.extend_from_slice(&BITCOIN_TAG);
        let mut payload = Vec::new();
        write_varint(&mut payload, height);
        write_varint(&mut out, payload.len());
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn merges_commitment_rooted_upgrade_and_round_trips() {
        let initial = [0x42; 32];
        let url = "https://calendar.test";
        let pending = pending(url, b"unhashed-suffix");
        let commitment = extract_pending_commitment(&pending, &initial, url).unwrap();
        assert_eq!(
            commitment.len(),
            47,
            "pending commitments need not be 32 bytes"
        );

        let upgrade = bitcoin_upgrade(840_000);
        let (merged, bitcoin) = merge_calendar_upgrade(&pending, &initial, url, &upgrade).unwrap();
        assert_eq!(bitcoin.block_height, 840_000);
        let reparsed = require_bitcoin_after(&merged, &initial, &commitment).unwrap();
        assert_eq!(reparsed, bitcoin);
    }

    #[test]
    fn pending_only_calendar_response_is_not_an_upgrade() {
        let initial = [0x42; 32];
        let url = "https://calendar.test";
        let pending = pending(url, b"suffix");
        assert!(matches!(
            merge_calendar_upgrade(&pending, &initial, url, &pending),
            Err(OtsParseError::MissingBitcoinAttestation) | Err(OtsParseError::UrlNotFound { .. })
        ));
    }
}
