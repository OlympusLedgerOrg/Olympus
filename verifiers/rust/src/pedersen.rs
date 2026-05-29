//! Pedersen commitments on Baby Jubjub — Rust cross-language verifier leg (issue #992).
//!
//! Mirrors `verifiers/javascript/verifier.js` and the authoritative reference
//! at `src-tauri/src/zk/pedersen.rs`. This is a recompute-and-compare verifier:
//! given an opening `(m, r)` we recompute `C = m*G + r*H` on the Baby Jubjub
//! prime-order subgroup and check the affine coordinates, the
//! iden3/babyjubjub-rs 32-byte compressed form, and subgroup membership against
//! the shared vectors in `verifiers/test_vectors/vectors.json`.
//!
//! Curve (twisted Edwards): `a*x^2 + y^2 = 1 + d*x^2*y^2` over the BN254 scalar
//! field. `G` is the circomlib B8 base point; `H` is the NUMS generator derived
//! from the domain tag `OLY:PEDERSEN:H:V1` (pinned in `zk/pedersen.rs`). Scalars
//! `m, r` are taken in `[0, l)` where `l` is the subgroup order.
//!
//! Implemented with `num-bigint` only (MIT/Apache-2.0, already vendored across
//! the workspace) — no curve/zk crate is pulled into this minimal verifier.

use num_bigint::BigUint;

/// An affine point on Baby Jubjub. Coordinates are kept reduced mod `p`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

/// Baby Jubjub curve parameters plus the Olympus Pedersen generators `G`, `H`.
pub struct Curve {
    /// Field modulus (BN254 scalar field `r`).
    pub p: BigUint,
    /// Twisted-Edwards coefficient `a`.
    pub a: BigUint,
    /// Twisted-Edwards coefficient `d`.
    pub d: BigUint,
    /// Prime-order subgroup order `l`.
    pub l: BigUint,
    /// circomlib B8 base point.
    pub g: Point,
    /// NUMS generator `H` for `OLY:PEDERSEN:H:V1`.
    pub h: Point,
}

// Decimal constants, pinned to `src-tauri/src/zk/pedersen.rs` and to the
// `pedersen_commitment.curve` block of vectors.json (the test below asserts
// these agree, guarding against silent drift on either side).
const P_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const A_DEC: &str = "168700";
const D_DEC: &str = "168696";
const L_DEC: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";
const G_X_DEC: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
const G_Y_DEC: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";
const H_X_DEC: &str =
    "198588470289489729947397318629051280907399291050874530267072873208967148441";
const H_Y_DEC: &str =
    "19238664506574355524861866424113858387196810277823508736174698680331927248315";

/// Parse a base-10 string into a `BigUint`, or `None` on malformed input.
pub fn parse_dec(s: &str) -> Option<BigUint> {
    BigUint::parse_bytes(s.as_bytes(), 10)
}

fn dec(s: &str) -> BigUint {
    parse_dec(s).expect("pinned decimal constant must parse")
}

fn one() -> BigUint {
    BigUint::from(1u32)
}

fn zero() -> BigUint {
    BigUint::from(0u32)
}

impl Curve {
    /// The Baby Jubjub curve with the Olympus Pedersen generators.
    pub fn baby_jubjub() -> Self {
        Curve {
            p: dec(P_DEC),
            a: dec(A_DEC),
            d: dec(D_DEC),
            l: dec(L_DEC),
            g: Point { x: dec(G_X_DEC), y: dec(G_Y_DEC) },
            h: Point { x: dec(H_X_DEC), y: dec(H_Y_DEC) },
        }
    }

    /// The group identity `(0, 1)`.
    pub fn identity(&self) -> Point {
        Point { x: zero(), y: one() }
    }

    // ---- field arithmetic mod p (inputs need not be pre-reduced) ----

    fn f_add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }

    fn f_sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        // (a - b) mod p, computed without going negative.
        ((a % &self.p) + &self.p - (b % &self.p)) % &self.p
    }

    fn f_mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }

    /// Modular inverse via Fermat's little theorem (`p` is prime).
    fn f_inv(&self, a: &BigUint) -> BigUint {
        (a % &self.p).modpow(&(&self.p - 2u32), &self.p)
    }

    // ---- twisted-Edwards group law ----

    /// Unified (complete on Baby Jubjub) point addition.
    pub fn point_add(&self, p1: &Point, p2: &Point) -> Point {
        let x1y2 = self.f_mul(&p1.x, &p2.y);
        let x2y1 = self.f_mul(&p2.x, &p1.y);
        let y1y2 = self.f_mul(&p1.y, &p2.y);
        let x1x2 = self.f_mul(&p1.x, &p2.x);
        let dxy = self.f_mul(&self.f_mul(&self.d, &x1x2), &y1y2);
        let one = one();
        let x3 = self.f_mul(&self.f_add(&x1y2, &x2y1), &self.f_inv(&self.f_add(&one, &dxy)));
        let y3 = self.f_mul(
            &self.f_sub(&y1y2, &self.f_mul(&self.a, &x1x2)),
            &self.f_inv(&self.f_sub(&one, &dxy)),
        );
        Point { x: x3, y: y3 }
    }

    /// Scalar multiplication `k*P` via double-and-add, with `k` reduced mod `l`.
    pub fn scalar_mul(&self, p: &Point, k: &BigUint) -> Point {
        let mut e = k % &self.l;
        let mut acc = self.identity();
        let mut base = p.clone();
        while e != zero() {
            if e.bit(0) {
                acc = self.point_add(&acc, &base);
            }
            base = self.point_add(&base, &base);
            e >>= 1u32;
        }
        acc
    }

    /// True iff `P` satisfies the curve equation.
    pub fn on_curve(&self, p: &Point) -> bool {
        let x2 = self.f_mul(&p.x, &p.x);
        let y2 = self.f_mul(&p.y, &p.y);
        let lhs = self.f_add(&self.f_mul(&self.a, &x2), &y2);
        let rhs = self.f_add(&one(), &self.f_mul(&self.f_mul(&self.d, &x2), &y2));
        lhs == rhs
    }

    /// True iff `P` lies in the prime-order subgroup (`l*P == identity`).
    pub fn in_prime_subgroup(&self, p: &Point) -> bool {
        self.scalar_mul(p, &self.l) == self.identity()
    }

    /// `(p - 1) / 2`, the sign threshold used by point compression.
    fn half(&self) -> BigUint {
        (&self.p - 1u32) >> 1u32
    }

    /// Compress to the iden3/babyjubjub-rs 32-byte form: `y` little-endian, with
    /// bit 255 (MSB of the last byte) set when `x > (p-1)/2`.
    pub fn compress(&self, p: &Point) -> [u8; 32] {
        let mut out = [0u8; 32];
        let yb = (&p.y % &self.p).to_bytes_le();
        for (i, b) in yb.iter().take(32).enumerate() {
            out[i] = *b;
        }
        if (&p.x % &self.p) > self.half() {
            out[31] |= 0x80;
        }
        out
    }

    /// Decompress a 32-byte commitment back to `(x, y)`, recovering `x` from the
    /// curve equation and selecting the root by the encoded sign bit.
    pub fn decompress(&self, bytes: &[u8; 32]) -> Result<Point, &'static str> {
        let mut buf = *bytes;
        let sign = (buf[31] & 0x80) != 0;
        buf[31] &= 0x7f;
        let y = BigUint::from_bytes_le(&buf);
        if y >= self.p {
            return Err("y coordinate out of field range");
        }
        // a*x^2 + y^2 = 1 + d*x^2*y^2  =>  x^2 = (1 - y^2) / (a - d*y^2)
        let y2 = self.f_mul(&y, &y);
        let num = self.f_sub(&one(), &y2);
        let den = self.f_sub(&self.a, &self.f_mul(&self.d, &y2));
        let x2 = self.f_mul(&num, &self.f_inv(&den));
        let mut x = self.sqrt(&x2).ok_or("not a valid curve point")?;
        if (x > self.half()) != sign {
            x = self.f_sub(&zero(), &x); // p - x
        }
        Ok(Point { x, y })
    }

    /// Tonelli–Shanks square root mod `p`. Returns `None` for non-residues.
    fn sqrt(&self, n: &BigUint) -> Option<BigUint> {
        let p = &self.p;
        let n = n % p;
        if n == zero() {
            return Some(zero());
        }
        let one = one();
        let euler = (p - 1u32) >> 1u32;
        if n.modpow(&euler, p) != one {
            return None; // quadratic non-residue
        }
        // Factor p - 1 = q * 2^s with q odd.
        let mut q = p - 1u32;
        let mut s = 0u32;
        while !q.bit(0) {
            q >>= 1u32;
            s += 1;
        }
        // Find a quadratic non-residue z.
        let p_minus_1 = p - 1u32;
        let mut z = BigUint::from(2u32);
        while z.modpow(&euler, p) != p_minus_1 {
            z += 1u32;
        }
        let mut m = s;
        let mut c = z.modpow(&q, p);
        let mut t = n.modpow(&q, p);
        let mut r = n.modpow(&((&q + 1u32) >> 1u32), p);
        while t != one {
            // Least i in (0, m) with t^(2^i) == 1.
            let mut i = 0u32;
            let mut tt = t.clone();
            while tt != one {
                tt = (&tt * &tt) % p;
                i += 1;
            }
            // b = c^(2^(m - i - 1)).
            let mut b = c.clone();
            for _ in 0..(m - i - 1) {
                b = (&b * &b) % p;
            }
            m = i;
            c = (&b * &b) % p;
            t = (&t * &c) % p;
            r = (&r * &b) % p;
        }
        Some(r)
    }

    /// Compute the Pedersen commitment `C = m*G + r*H`.
    pub fn pedersen_commit(&self, m: &BigUint, r: &BigUint) -> Point {
        self.point_add(&self.scalar_mul(&self.g, m), &self.scalar_mul(&self.h, r))
    }
}

/// One opening from `vectors.pedersen_commitment.commitments`.
#[derive(serde::Deserialize)]
pub struct PedersenVector {
    pub m_decimal: String,
    pub r_decimal: String,
    pub commitment_x_decimal: String,
    pub commitment_y_decimal: String,
    pub commitment_compressed_hex: String,
    pub expected_valid: bool,
}

/// Verify a Pedersen opening against a vector entry: recompute `C = m*G + r*H`,
/// then check the coordinates, subgroup membership, the compressed bytes, and a
/// compress→decompress round-trip. Returns `false` (never panics) on malformed
/// input.
pub fn verify_pedersen_commitment(curve: &Curve, vec: &PedersenVector) -> bool {
    let (m, r) = match (parse_dec(&vec.m_decimal), parse_dec(&vec.r_decimal)) {
        (Some(m), Some(r)) => (m, r),
        _ => return false,
    };
    let (ex, ey) = match (
        parse_dec(&vec.commitment_x_decimal),
        parse_dec(&vec.commitment_y_decimal),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => return false,
    };

    let c = curve.pedersen_commit(&m, &r);
    if c.x != ex || c.y != ey {
        return false;
    }

    // Recomputed point must be a valid, in-subgroup curve point.
    if !curve.on_curve(&c) || !curve.in_prime_subgroup(&c) {
        return false;
    }

    // Compressed form must match the committed bytes...
    let compressed = curve.compress(&c);
    if hex::encode(compressed) != vec.commitment_compressed_hex {
        return false;
    }

    // ...and decompress back to the same point.
    match curve.decompress(&compressed) {
        Ok(back) => back == c,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Curve params carried alongside the vectors, used only to assert that the
    // shared file and the pinned constants in this module have not drifted.
    #[derive(serde::Deserialize)]
    struct CurveParams {
        field_modulus_decimal: String,
        subgroup_order_decimal: String,
        a_decimal: String,
        d_decimal: String,
        #[serde(rename = "G_x_decimal")]
        g_x_decimal: String,
        #[serde(rename = "G_y_decimal")]
        g_y_decimal: String,
        #[serde(rename = "H_x_decimal")]
        h_x_decimal: String,
        #[serde(rename = "H_y_decimal")]
        h_y_decimal: String,
    }

    #[derive(serde::Deserialize)]
    struct PedersenBlock {
        curve: CurveParams,
        commitments: Vec<PedersenVector>,
    }

    #[derive(serde::Deserialize)]
    struct VectorsFile {
        pedersen_commitment: PedersenBlock,
    }

    fn load_block() -> PedersenBlock {
        let raw = include_str!("../../test_vectors/vectors.json");
        let file: VectorsFile = serde_json::from_str(raw).expect("parse vectors.json");
        file.pedersen_commitment
    }

    fn by_m(block: &PedersenBlock, m: &str) -> &'static PedersenVector {
        // Leak a clone so callers get a 'static ref; fine in a test helper.
        let v = block
            .commitments
            .iter()
            .find(|v| v.m_decimal == m)
            .unwrap_or_else(|| panic!("fixture m={m} present"));
        Box::leak(Box::new(PedersenVector {
            m_decimal: v.m_decimal.clone(),
            r_decimal: v.r_decimal.clone(),
            commitment_x_decimal: v.commitment_x_decimal.clone(),
            commitment_y_decimal: v.commitment_y_decimal.clone(),
            commitment_compressed_hex: v.commitment_compressed_hex.clone(),
            expected_valid: v.expected_valid,
        }))
    }

    #[test]
    fn curve_params_match_pinned_constants() {
        let block = load_block();
        let c = &block.curve;
        assert_eq!(c.field_modulus_decimal, P_DEC, "field modulus drift");
        assert_eq!(c.subgroup_order_decimal, L_DEC, "subgroup order drift");
        assert_eq!(c.a_decimal, A_DEC, "a drift");
        assert_eq!(c.d_decimal, D_DEC, "d drift");
        assert_eq!(c.g_x_decimal, G_X_DEC, "G.x drift");
        assert_eq!(c.g_y_decimal, G_Y_DEC, "G.y drift");
        assert_eq!(c.h_x_decimal, H_X_DEC, "H.x drift");
        assert_eq!(c.h_y_decimal, H_Y_DEC, "H.y drift");

        // Both generators must themselves be valid in-subgroup points.
        let curve = Curve::baby_jubjub();
        assert!(curve.on_curve(&curve.g) && curve.in_prime_subgroup(&curve.g), "G");
        assert!(curve.on_curve(&curve.h) && curve.in_prime_subgroup(&curve.h), "H");
    }

    #[test]
    fn conformance_pedersen_commitment() {
        let block = load_block();
        assert!(!block.commitments.is_empty(), "no pedersen vectors found");
        let curve = Curve::baby_jubjub();
        for (i, vec) in block.commitments.iter().enumerate() {
            assert_eq!(
                verify_pedersen_commitment(&curve, vec),
                vec.expected_valid,
                "pedersen vector {i} ({})",
                vec.commitment_compressed_hex
            );
        }
    }

    #[test]
    fn homomorphism_point_addition() {
        // C(7,13) + C(11,17) == C(18,30), verified by adding the *points*.
        let block = load_block();
        let curve = Curve::baby_jubjub();
        let left = by_m(&block, "7");
        let right = by_m(&block, "11");
        let sum = by_m(&block, "18");

        let c1 = curve.pedersen_commit(&dec(&left.m_decimal), &dec(&left.r_decimal));
        let c2 = curve.pedersen_commit(&dec(&right.m_decimal), &dec(&right.r_decimal));
        let csum = curve.pedersen_commit(&dec(&sum.m_decimal), &dec(&sum.r_decimal));

        let point_sum = curve.point_add(&c1, &c2);
        assert_eq!(point_sum, csum, "homomorphism: C(m1,r1)+C(m2,r2)==C(m1+m2,r1+r2)");
        assert_eq!(csum.x, dec(&sum.commitment_x_decimal), "sum matches committed x");
        assert_eq!(csum.y, dec(&sum.commitment_y_decimal), "sum matches committed y");
    }

    #[test]
    fn negative_wrong_message() {
        let block = load_block();
        let curve = Curve::baby_jubjub();
        let base = by_m(&block, "7");
        let tampered = PedersenVector {
            m_decimal: "8".to_string(), // wrong message
            r_decimal: base.r_decimal.clone(),
            commitment_x_decimal: base.commitment_x_decimal.clone(),
            commitment_y_decimal: base.commitment_y_decimal.clone(),
            commitment_compressed_hex: base.commitment_compressed_hex.clone(),
            expected_valid: false,
        };
        assert!(!verify_pedersen_commitment(&curve, &tampered), "wrong message must fail (binding)");
    }

    #[test]
    fn negative_wrong_blinding() {
        let block = load_block();
        let curve = Curve::baby_jubjub();
        let base = by_m(&block, "7");
        let tampered = PedersenVector {
            m_decimal: base.m_decimal.clone(),
            r_decimal: "14".to_string(), // wrong blinding
            commitment_x_decimal: base.commitment_x_decimal.clone(),
            commitment_y_decimal: base.commitment_y_decimal.clone(),
            commitment_compressed_hex: base.commitment_compressed_hex.clone(),
            expected_valid: false,
        };
        assert!(!verify_pedersen_commitment(&curve, &tampered), "wrong blinding must fail (hiding)");
    }

    #[test]
    fn negative_corrupted_compressed_bytes() {
        let block = load_block();
        let curve = Curve::baby_jubjub();
        let base = by_m(&block, "42");
        // Flip the low byte of the compressed encoding.
        let mut bytes = hex::decode(&base.commitment_compressed_hex).expect("hex");
        bytes[0] ^= 0x01;
        let tampered = PedersenVector {
            commitment_compressed_hex: hex::encode(&bytes),
            ..PedersenVector {
                m_decimal: base.m_decimal.clone(),
                r_decimal: base.r_decimal.clone(),
                commitment_x_decimal: base.commitment_x_decimal.clone(),
                commitment_y_decimal: base.commitment_y_decimal.clone(),
                commitment_compressed_hex: String::new(),
                expected_valid: false,
            }
        };
        assert!(
            !verify_pedersen_commitment(&curve, &tampered),
            "corrupted compressed bytes must fail"
        );
    }

    #[test]
    fn compress_decompress_round_trip() {
        let block = load_block();
        let curve = Curve::baby_jubjub();
        for vec in &block.commitments {
            if !vec.expected_valid {
                continue;
            }
            let c = curve.pedersen_commit(&dec(&vec.m_decimal), &dec(&vec.r_decimal));
            let compressed = curve.compress(&c);
            let back = curve.decompress(&compressed).expect("decompress valid point");
            assert_eq!(back, c, "round-trip for {}", vec.commitment_compressed_hex);
        }
    }
}
