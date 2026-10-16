//! Independent, deliberately small FindCrypt-style constant scanner.
//!
//! Signatures come from published algorithm specifications, not a FindCrypt
//! database. Matches identify bytes, not functioning cryptographic code or keys.
//! See `docs/crypto-signatures.md` for provenance, ambiguity, and limitations.

use std::sync::OnceLock;

use crate::model::CryptoMatch;

pub const MAX_SIGNATURE_LEN: usize = 64;
pub const MAX_MATCHES: usize = 4096;

struct Signature {
    algorithm: &'static str,
    description: String,
    bytes: Vec<u8>,
}

const AES_SBOX_PREFIX: [u8; 64] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
];
const SHA256_K_PREFIX: [u32; 8] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
];
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA1_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

fn words_bytes(words: &[u32], little: bool) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| {
            if little {
                word.to_le_bytes()
            } else {
                word.to_be_bytes()
            }
        })
        .collect()
}

fn signatures() -> &'static [Signature] {
    static SIGNATURES: OnceLock<Vec<Signature>> = OnceLock::new();
    SIGNATURES.get_or_init(|| {
        let mut signatures = vec![Signature {
            algorithm: "AES / Rijndael",
            description: "Forward S-box prefix (64 of 256 bytes)".into(),
            bytes: AES_SBOX_PREFIX.to_vec(),
        }];
        for (algorithm, description, words) in [
            (
                "SHA-224 / SHA-256",
                "First 8 round constants (32 of 256 bytes)",
                SHA256_K_PREFIX.as_slice(),
            ),
            (
                "SHA-256",
                "Complete initial hash values",
                SHA256_IV.as_slice(),
            ),
            ("SHA-1", "Complete initial hash values", SHA1_IV.as_slice()),
            (
                "MD4 / MD5 / SHA-1 (ambiguous)",
                "Shared first four initial words; cannot distinguish algorithms",
                &SHA1_IV[..4],
            ),
        ] {
            for little in [true, false] {
                signatures.push(Signature {
                    algorithm,
                    description: format!(
                        "{description} ({} words)",
                        if little {
                            "little-endian"
                        } else {
                            "big-endian"
                        }
                    ),
                    bytes: words_bytes(words, little),
                });
            }
        }
        // Sigma is shared by ChaCha20 and Salsa20. Tau is the Salsa20 128-bit
        // constant; related ChaCha variants can also use it, so label broadly.
        for (description, bytes) in [
            ("Sigma 256-bit key expansion constant", b"expand 32-byte k"),
            (
                "Tau 128-bit key expansion constant (Salsa20 / related variants)",
                b"expand 16-byte k",
            ),
        ] {
            signatures.push(Signature {
                algorithm: "ChaCha / Salsa family (ambiguous)",
                description: format!("{description} (ASCII / little-endian words)"),
                bytes: bytes.to_vec(),
            });
            signatures.push(Signature {
                algorithm: "ChaCha / Salsa family (ambiguous)",
                description: format!("{description} (big-endian words)"),
                bytes: bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .flat_map(|word| word.iter().rev().copied())
                    .collect(),
            });
        }
        debug_assert!(
            signatures
                .iter()
                .all(|signature| signature.bytes.len() <= MAX_SIGNATURE_LEN)
        );
        signatures
    })
}

pub fn signature_count() -> usize {
    signatures().len()
}

/// Scan every byte alignment and preserve overlapping hits in address order.
///
/// At most `min(limit, MAX_MATCHES)` entries are allocated. The caller handles
/// region chunk boundaries by overlapping chunks by `MAX_SIGNATURE_LEN - 1`
/// bytes and suppressing repeated hits. A hit whose address range overflows u64
/// is discarded. This function never writes bytes or annotations into a program.
pub fn scan_region(bytes: &[u8], base: u64, limit: usize) -> Vec<CryptoMatch> {
    let limit = limit.min(MAX_MATCHES);
    if limit == 0 {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for (offset, byte) in bytes.iter().enumerate() {
        let Some(address) = u64::try_from(offset)
            .ok()
            .and_then(|offset| base.checked_add(offset))
        else {
            break;
        };
        for signature in signatures() {
            if *byte != signature.bytes[0] || !bytes[offset..].starts_with(&signature.bytes) {
                continue;
            }
            if address
                .checked_add(signature.bytes.len() as u64 - 1)
                .is_none()
            {
                continue;
            }
            matches.push(CryptoMatch {
                address,
                algorithm: signature.algorithm.into(),
                signature: signature.description.clone(),
                length: signature.bytes.len(),
            });
            if matches.len() == limit {
                return matches;
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aes_embedded_at_an_unaligned_virtual_address() {
        let mut region = vec![0; 3];
        region.extend_from_slice(&AES_SBOX_PREFIX);
        region.extend_from_slice(&[0; 9]);
        let matches = scan_region(&region, 0x401000, 100);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x401003);
        assert_eq!(matches[0].length, 64);
        assert!(matches[0].algorithm.contains("AES"));
        region[3 + 48] ^= 1;
        assert!(scan_region(&region, 0, 100).is_empty());
    }

    #[test]
    fn sha256_round_constants_are_found_in_both_word_orders() {
        for little in [false, true] {
            let mut region = vec![0x55];
            // Independent expected input: first eight FIPS 180-4 section 4.2.2 words.
            let be = [
                0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5,
                0xdb, 0xa5, 0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0xf1, 0x92, 0x3f, 0x82, 0xa4,
                0xab, 0x1c, 0x5e, 0xd5,
            ];
            for word in be.as_chunks::<4>().0 {
                if little {
                    region.extend(word.iter().rev());
                } else {
                    region.extend_from_slice(word);
                }
            }
            let matches = scan_region(&region, 0x1000, 100);
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].address, 0x1001);
            assert!(matches[0].algorithm.contains("SHA-256"));
            assert!(matches[0].signature.contains(if little {
                "little-endian"
            } else {
                "big-endian"
            }));
        }
    }

    #[test]
    fn overlapping_iv_signatures_preserve_ambiguity() {
        let region = words_bytes(&SHA1_IV, true);
        let matches = scan_region(&region, 0, 100);
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|hit| hit.address == 0));
        assert!(
            matches
                .iter()
                .any(|hit| hit.algorithm == "SHA-1" && hit.length == 20)
        );
        assert!(
            matches
                .iter()
                .any(|hit| hit.algorithm.contains("ambiguous") && hit.length == 16)
        );
        let shared_only = scan_region(&region[..16], 0, 100);
        assert_eq!(shared_only.len(), 1);
        assert!(shared_only[0].algorithm.contains("MD4 / MD5 / SHA-1"));
    }

    #[test]
    fn detects_shared_sigma_without_claiming_a_specific_algorithm() {
        let matches = scan_region(b"xexpand 32-byte k", 20, 100);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 21);
        assert!(matches[0].algorithm.contains("ambiguous"));
        let be = b"apxe3 dnyb-2k et";
        let matches = scan_region(be, 0, 100);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].signature.contains("big-endian"));
        assert!(scan_region(b"expand 32-byte j", 0, 100).is_empty());
    }

    #[test]
    fn enforces_caps_and_rejects_overflowing_addresses() {
        let mut region = Vec::new();
        for _ in 0..MAX_MATCHES + 2 {
            region.extend_from_slice(b"expand 32-byte k");
        }
        assert!(scan_region(&region, 0, 0).is_empty());
        assert_eq!(scan_region(&region, 0, 3).len(), 3);
        assert_eq!(scan_region(&region, 0, usize::MAX).len(), MAX_MATCHES);
        assert!(scan_region(b"expand 32-byte k", u64::MAX - 14, 100).is_empty());
        assert_eq!(
            scan_region(b"expand 32-byte k", u64::MAX - 15, 100).len(),
            1
        );
        assert!(scan_region(&[0; 1024], u64::MAX, 100).is_empty());
        assert!(scan_region(&[], 0, 100).is_empty());
    }

    #[test]
    fn signature_metadata_matches_streaming_contract() {
        assert_eq!(signature_count(), 13);
        assert_eq!(
            signatures()
                .iter()
                .map(|signature| signature.bytes.len())
                .max(),
            Some(MAX_SIGNATURE_LEN)
        );
        assert!(scan_region(&[0xaa; 1000], 0, 100).is_empty());
        assert!(scan_region(&AES_SBOX_PREFIX[..63], 0, 100).is_empty());
    }
}
