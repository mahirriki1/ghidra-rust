//! Bounded byte transformations for the GUI's built-in decoder.
//!
//! UTF-8 validates and preserves bytes; UTF-16 converts to UTF-8 without silently
//! replacing malformed code units. Hex, Base64, and XOR return arbitrary bytes,
//! which the caller may display as hex or validate with `text_preview`. Explicit
//! endian selection is authoritative, including for any BOM present in the data.
//! Suggestions are heuristics, never evidence that a string has been decrypted.

use base64::{Engine as _, engine::general_purpose::STANDARD};

pub const MAX_INPUT: usize = 64 * 1024;
pub const MAX_OUTPUT: usize = 256 * 1024;
const XOR_CANDIDATES: usize = 5;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Utf8,
    Utf16Le,
    Utf16Be,
    Hex,
    Base64,
    Xor,
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub label: String,
    pub bytes: Vec<u8>,
    /// Relative readability heuristic in [0, 1], not a probability of correctness.
    pub score: f32,
}

pub fn decode(input: &[u8], operation: Operation, key: &[u8]) -> Result<Vec<u8>, String> {
    check_input(input.len())?;
    let output = match operation {
        Operation::Utf8 => {
            std::str::from_utf8(input).map_err(|e| format!("Malformed UTF-8: {e}"))?;
            input.to_vec()
        }
        Operation::Utf16Le | Operation::Utf16Be => {
            if !input.len().is_multiple_of(2) {
                return Err("UTF-16 requires an even number of bytes".into());
            }
            let units: Vec<u16> = input
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    if operation == Operation::Utf16Le {
                        u16::from_le_bytes([pair[0], pair[1]])
                    } else {
                        u16::from_be_bytes([pair[0], pair[1]])
                    }
                })
                .collect();
            String::from_utf16(&units)
                .map_err(|e| format!("Malformed UTF-16: {e}"))?
                .into_bytes()
        }
        Operation::Hex => {
            parse_hex(std::str::from_utf8(input).map_err(|_| "Hex input must contain ASCII text")?)?
        }
        Operation::Base64 => {
            let compact: Vec<u8> = input
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            // STANDARD requires canonical padding and rejects nonzero trailing bits.
            STANDARD
                .decode(compact)
                .map_err(|e| format!("Invalid standard Base64: {e}"))?
        }
        Operation::Xor => {
            if key.is_empty() {
                return Err("XOR requires a nonempty key (hex:41 or text:A)".into());
            }
            check_input(key.len())?;
            input
                .iter()
                .zip(key.iter().cycle())
                .map(|(byte, key_byte)| byte ^ key_byte)
                .collect()
        }
    };
    if output.len() > MAX_OUTPUT {
        return Err("Decoded output exceeds the 256 KiB limit".into());
    }
    Ok(output)
}

fn check_input(length: usize) -> Result<(), String> {
    if length > MAX_INPUT {
        Err("Input exceeds the 64 KiB decoder limit; select a smaller range".into())
    } else {
        Ok(())
    }
}

/// Parse pairs of hex digits with optional ASCII whitespace. No `0x` guessing.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    check_input(text.len())?;
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut high = None;
    for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err("Hex input contains a non-hexadecimal character".into()),
        };
        if let Some(first) = high.take() {
            bytes.push(first * 16 + nibble);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() {
        return Err("Hex input has an odd number of digits".into());
    }
    Ok(bytes)
}

/// Explicit prefixes avoid interpreting a text key like `deadbeef` as hex.
pub fn parse_key(text: &str) -> Result<Vec<u8>, String> {
    check_input(text.len())?;
    let key = if let Some(hex) = text.strip_prefix("hex:") {
        parse_hex(hex)?
    } else if let Some(text) = text.strip_prefix("text:") {
        text.as_bytes().to_vec()
    } else {
        return Err("Prefix the key with hex: or text: (for example hex:41 or text:A)".into());
    };
    if key.is_empty() {
        return Err("The key must not be empty".into());
    }
    Ok(key)
}

/// Strict UTF-8: an invalid sequence is not replaced with misleading text.
pub fn text_preview(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_OUTPUT {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

pub fn common_candidates(input: &[u8]) -> Vec<Candidate> {
    if input.is_empty() || input.len() > MAX_INPUT {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    for (operation, label) in [
        (Operation::Hex, "Hex decoding suggestion"),
        (Operation::Base64, "Base64 decoding suggestion"),
    ] {
        if let Ok(bytes) = decode(input, operation, &[])
            && !bytes.is_empty()
            && bytes != input
        {
            candidates.push(Candidate {
                label: label.into(),
                score: readability(&bytes).unwrap_or(0.0),
                bytes,
            });
        }
    }
    // Require encoding evidence to avoid interpreting arbitrary pairs as Unicode.
    if input.len().is_multiple_of(2) {
        for (operation, label, zero_lane, bom) in [
            (Operation::Utf16Le, "UTF-16 LE suggestion", 1, [0xff, 0xfe]),
            (Operation::Utf16Be, "UTF-16 BE suggestion", 0, [0xfe, 0xff]),
        ] {
            let zeroes = input
                .as_chunks::<2>()
                .0
                .iter()
                .filter(|p| p[zero_lane] == 0)
                .count();
            if (input.starts_with(&bom) || zeroes * 4 >= input.len())
                && let Ok(bytes) = decode(input, operation, &[])
                && let Some(score) = readability(&bytes)
            {
                candidates.push(Candidate {
                    label: label.into(),
                    bytes,
                    score,
                });
            }
        }
    }
    // All 255 nonzero single-byte keys are bounded by MAX_INPUT. Retain only a
    // handful of readable candidates; arbitrary key guessing is deliberately absent.
    if input.len() >= 4 {
        let mut xor = Vec::new();
        for key in 1..=255u8 {
            let bytes: Vec<u8> = input.iter().map(|byte| byte ^ key).collect();
            if let Some(score) = readability(&bytes) {
                xor.push(Candidate {
                    label: format!("XOR hex:{key:02x} suggestion (unverified)"),
                    bytes,
                    score,
                });
                xor.sort_by(|a, b| b.score.total_cmp(&a.score));
                xor.truncate(XOR_CANDIDATES);
            }
        }
        candidates.extend(xor);
    }
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    candidates
}

fn readability(bytes: &[u8]) -> Option<f32> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.is_empty()
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    let count = text.chars().count() as f32;
    let mut score = 0.0;
    for character in text.chars() {
        score += if " etaoinshrdluETAOINSHRDLU".contains(character) {
            1.0
        } else if character.is_alphabetic() || character.is_ascii_digit() {
            0.75
        } else if character.is_ascii_punctuation() || character.is_whitespace() {
            0.4
        } else {
            0.1
        };
    }
    Some(score / count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_canonical_base64_and_rejects_bad_padding() {
        assert_eq!(
            decode(b" SGVs\nbG8=\r\n", Operation::Base64, &[]).unwrap(),
            b"Hello"
        );
        for invalid in [
            b"SGVsbG8".as_slice(),
            b"SGVsbG8===",
            b"Zh==",
            b"a===",
            b"====",
        ] {
            assert!(
                decode(invalid, Operation::Base64, &[]).is_err(),
                "{invalid:?}"
            );
        }
        assert_eq!(decode(b"/w==", Operation::Base64, &[]).unwrap(), [0xff]);
        assert!(text_preview(&[0xff]).is_none());
    }

    #[test]
    fn parses_hex_without_ambiguous_or_lossy_input() {
        assert_eq!(parse_hex("48 65\n6C\t6c 6F").unwrap(), b"Hello");
        for invalid in ["abc", "0x41", "4g", "４１", "a\u{a0}b"] {
            assert!(parse_hex(invalid).is_err(), "{invalid}");
        }
        assert!(parse_hex(" \n").unwrap().is_empty());
        assert_eq!(decode(b"4869", Operation::Hex, &[]).unwrap(), b"Hi");
    }

    #[test]
    fn validates_utf8_and_utf16_surrogate_pairs_in_both_orders() {
        assert_eq!(
            decode("Hi 🦀".as_bytes(), Operation::Utf8, &[]).unwrap(),
            "Hi 🦀".as_bytes()
        );
        assert!(decode(&[0xc0, 0x80], Operation::Utf8, &[]).is_err());
        let le = [0x41, 0x00, 0x3e, 0xd8, 0x80, 0xdd];
        let be = [0x00, 0x41, 0xd8, 0x3e, 0xdd, 0x80];
        assert_eq!(
            decode(&le, Operation::Utf16Le, &[]).unwrap(),
            "A🦀".as_bytes()
        );
        assert_eq!(
            decode(&be, Operation::Utf16Be, &[]).unwrap(),
            "A🦀".as_bytes()
        );
        for malformed in [
            &[0x00, 0xd8][..],
            &[0x00, 0xdc],
            &[0x00, 0xd8, 0x41, 0x00],
            &[0x41],
        ] {
            assert!(decode(malformed, Operation::Utf16Le, &[]).is_err());
        }
        assert!(decode(&[0xd8, 0x00], Operation::Utf16Be, &[]).is_err());
    }

    #[test]
    fn xor_preserves_bytes_and_requires_explicit_nonempty_keys() {
        let key = parse_key("hex:49 43 45").unwrap();
        let ciphertext = decode(b"Burning 'em", Operation::Xor, &key).unwrap();
        assert_eq!(
            ciphertext,
            [
                0x0b, 0x36, 0x37, 0x27, 0x2a, 0x2b, 0x2e, 0x63, 0x62, 0x2c, 0x2e
            ]
        );
        assert_eq!(
            decode(&ciphertext, Operation::Xor, &key).unwrap(),
            b"Burning 'em"
        );
        assert_ne!(
            decode(&ciphertext, Operation::Xor, b"BAD").unwrap(),
            b"Burning 'em"
        );
        assert_eq!(parse_key("text:deadbeef").unwrap(), b"deadbeef");
        for invalid in ["deadbeef", "", "text:", "hex:", "hex:abc"] {
            assert!(parse_key(invalid).is_err());
        }
        assert!(decode(b"hello", Operation::Xor, &[]).is_err());
    }

    #[test]
    fn suggestions_contain_known_decodings_and_bounded_ranked_xor() {
        assert!(
            common_candidates(b"SGVsbG8=")
                .iter()
                .any(|c| c.bytes == b"Hello")
        );
        assert!(
            common_candidates(b"48656c6c6f")
                .iter()
                .any(|c| c.bytes == b"Hello")
        );
        let plaintext = b"the secret string is here";
        let encrypted = decode(plaintext, Operation::Xor, &[0x93]).unwrap();
        let candidates = common_candidates(&encrypted);
        assert!(
            candidates
                .iter()
                .any(|c| c.bytes == plaintext && c.label.contains("93"))
        );
        assert!(candidates.len() <= XOR_CANDIDATES + 4);
        assert!(candidates.windows(2).all(|c| c[0].score >= c[1].score));
        assert!(candidates.iter().all(|c| c.label.contains("suggestion")));
        assert!(common_candidates(&[]).is_empty());
    }

    #[test]
    fn refuses_oversized_inputs_without_silent_truncation() {
        let oversized = vec![b'A'; MAX_INPUT + 1];
        for operation in [
            Operation::Utf8,
            Operation::Utf16Le,
            Operation::Utf16Be,
            Operation::Hex,
            Operation::Base64,
            Operation::Xor,
        ] {
            assert!(decode(&oversized, operation, b"x").is_err());
        }
        assert!(parse_hex(std::str::from_utf8(&oversized).unwrap()).is_err());
        assert!(common_candidates(&oversized).is_empty());
        assert!(text_preview(&vec![b'A'; MAX_OUTPUT + 1]).is_none());
        assert_eq!(
            decode(&vec![b'A'; MAX_INPUT], Operation::Utf8, &[])
                .unwrap()
                .len(),
            MAX_INPUT
        );
        assert!(decode(b"a", Operation::Xor, &oversized).is_err());
    }
}
