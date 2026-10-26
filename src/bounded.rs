//! Untrusted JSON is shape-checked before typed allocation.
//!
//! Collection fields reject excess elements while deserializing, and the
//! streaming preflights bound total nodes before serde materializes a
//! document. Internally tagged worker replies are buffered by serde before
//! their variant is decoded, so their preflight runs on the raw line.
use std::fmt;
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};

use crate::model::*;

/// Deserialize a sequence of at most `N` elements, failing at element `N + 1`.
pub(crate) fn vec<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a sequence of at most {N} elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Vec<T>, A::Error> {
            // Never trust a size hint beyond the bound or a modest preallocation.
            let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0).min(N).min(4096));
            while let Some(value) = access.next_element()? {
                if values.len() == N {
                    return Err(A::Error::custom(format!(
                        "sequence exceeds its {N}-element limit"
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(PhantomData))
}

struct Budget {
    nodes: usize,
    max_string: usize,
}

/// Counts every scalar, key, and container without retaining any of them.
struct Count<'a>(&'a mut Budget);

impl<'de> DeserializeSeed<'de> for Count<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.0.nodes == 0 {
            return Err(D::Error::custom("JSON exceeds its node budget"));
        }
        self.0.nodes -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Count<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<(), E> {
        if value.len() > self.0.max_string {
            Err(E::custom("JSON string exceeds its size limit"))
        } else {
            Ok(())
        }
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        while access.next_element_seed(Count(self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        while access.next_key_seed(Count(self.0))?.is_some() {
            access.next_value_seed(Count(self.0))?;
        }
        Ok(())
    }
}

/// Streams a complete document, bounding nodes and individual string sizes.
pub(crate) fn check_json(bytes: &[u8], nodes: usize, max_string: usize) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Count(&mut Budget { nodes, max_string })
        .deserialize(&mut deserializer)
        .map_err(|e| e.to_string())?;
    deserializer.end().map_err(|e| e.to_string())
}

const OBJECT_SLACK: usize = 64;

/// Node budget for each reply kind, derived from the worker's own result
/// limits. Counts include every container, key, and scalar. Only inventory
/// replies may approach the frame limit.
fn reply_nodes(kind: &str) -> Option<usize> {
    // Objects cost 1 + 2 nodes per field; arrays 1 + their elements.
    const FUNCTION: usize = 5;
    const SECTION: usize = 13;
    const CALL: usize = 7;
    const DATA: usize = 13;
    const ADDRESS: usize = 9;
    const INSTRUCTION: usize = 9 + MAX_INSTRUCTION_BYTES;
    let nodes = match kind {
        "opened" => FUNCTION * MAX_FUNCTIONS + SECTION * MAX_SECTIONS + MAX_WARNINGS + 8,
        "functions" | "discovery_batch" => {
            FUNCTION * MAX_FUNCTIONS
                + CALL * MAX_CALL_REFERENCES
                + DATA * MAX_DATA_REFERENCES
                + ADDRESS * MAX_ADDRESS_REFERENCES
                + 5 * MAX_ANALYSIS_FUNCTIONS
                + 16
        }
        "graph" => {
            5 * MAX_GRAPH_BLOCKS
                + INSTRUCTION * MAX_GRAPH_INSTRUCTIONS
                + 7 * MAX_GRAPH_EDGES
                + 5 * MAX_GRAPH_CALLS
                + MAX_WARNINGS
        }
        "decompiled" => {
            8 * MAX_CODE_MAPPINGS
                + MAX_CODE_ADDRESS_REFS
                + 11 * crate::semantic::MAX_TOKENS
                + 25 * crate::semantic::MAX_LOCALS
                + crate::semantic::MAX_FUNCTION_RENAMES
                + 16 * crate::signatures::MAX_PARAMETERS
                + crate::signatures::MAX_INFERRED_NOTES
        }
        "signatures_synced" => 5 * crate::signatures::MAX_SIGNATURES,
        "bytes" => MAX_BYTE_READ,
        "strings" => 7 * MAX_STRING_RESULTS,
        "crypto" => 9 * MAX_CRYPTO_MATCHES,
        "symbol_names" => 7 * MAX_SYMBOL_NAME_PAGE_RECORDS + 10,
        // The widest record: a tag, eleven scalar fields and nothing nested.
        "linkage" => {
            25 * crate::linkage::MAX_LINKAGE_PAGE_RECORDS + crate::linkage::MAX_LINKAGE_GAPS + 32
        }
        "progress" | "renamed" | "error" | "functions_synced" => 0,
        _ => return None,
    };
    Some(nodes + OBJECT_SLACK)
}

/// Kind and id of a worker reply line that passed its shape preflight.
#[derive(Debug)]
pub(crate) struct ReplyShape {
    pub id: u64,
    pub kind: String,
}

/// Validates `{"id":…, "response":{"kind":…, …}}` with a per-kind node budget
/// before the reply is materialized. The worker always writes the tag first.
pub(crate) fn check_reply(line: &[u8]) -> Result<ReplyShape, String> {
    struct Envelope;
    impl<'de> Visitor<'de> for Envelope {
        type Value = ReplyShape;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a worker reply envelope")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<ReplyShape, A::Error> {
            let (mut id, mut kind) = (None, None);
            while let Some(key) = access.next_key::<Key>()? {
                match key.0.as_str() {
                    "id" if id.is_none() => id = Some(access.next_value::<u64>()?),
                    "response" if kind.is_none() => kind = Some(access.next_value_seed(Body)?),
                    _ => return Err(A::Error::custom("unexpected or repeated reply field")),
                }
            }
            match (id, kind) {
                (Some(id), Some(kind)) => Ok(ReplyShape { id, kind }),
                _ => Err(A::Error::custom("incomplete reply envelope")),
            }
        }
    }
    struct Body;
    impl<'de> DeserializeSeed<'de> for Body {
        type Value = String;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Body {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a tagged worker response")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<String, A::Error> {
            if access.next_key::<Key>()?.is_none_or(|key| key.0 != "kind") {
                return Err(A::Error::custom("reply kind must come first"));
            }
            let kind = access.next_value::<Key>()?.0;
            let nodes = reply_nodes(&kind).ok_or_else(|| A::Error::custom("unknown reply kind"))?;
            let mut budget = Budget {
                nodes,
                max_string: if kind == "symbol_names" {
                    MAX_SYMBOL_RAW_BYTES
                } else if kind == "linkage" {
                    MAX_SYMBOL_RAW_BYTES + crate::linkage::MAX_LINKAGE_LABEL_BYTES
                } else {
                    MAX_DECOMPILED_BYTES
                },
            };
            while access.next_key_seed(Count(&mut budget))?.is_some() {
                access.next_value_seed(Count(&mut budget))?;
            }
            Ok(kind)
        }
    }
    /// A short identifier; longer keys or kinds are rejected without copying.
    struct Key(String);
    impl<'de> serde::Deserialize<'de> for Key {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Short;
            impl Visitor<'_> for Short {
                type Value = Key;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a short identifier")
                }
                fn visit_str<E: Error>(self, value: &str) -> Result<Key, E> {
                    if value.len() > 32 {
                        Err(E::custom("identifier is too long"))
                    } else {
                        Ok(Key(value.to_owned()))
                    }
                }
            }
            d.deserialize_str(Short)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(line);
    let shape = serde::Deserializer::deserialize_map(&mut deserializer, Envelope)
        .map_err(|e| format!("Invalid worker response: {e}"))?;
    deserializer
        .end()
        .map_err(|e| format!("Invalid worker response: {e}"))?;
    // Pages are packed by encoded record size; a page and its envelope fit here.
    if shape.kind == "symbol_names" && line.len() > MAX_SYMBOL_NAME_PAGE_BYTES + 512 {
        return Err("Invalid worker response: symbol-name page exceeds its size limit".into());
    }
    if shape.kind == "linkage" && line.len() > crate::linkage::MAX_LINKAGE_PAGE_BYTES + 512 {
        return Err("Invalid worker response: linkage page exceeds its size limit".into());
    }
    Ok(shape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Pair {
        #[serde(deserialize_with = "vec::<_, _, 2>")]
        values: Vec<u8>,
    }

    #[test]
    fn bounded_sequences_fail_at_the_first_excess_element() {
        assert_eq!(
            serde_json::from_str::<Pair>(r#"{"values":[1,2]}"#)
                .unwrap()
                .values,
            [1, 2]
        );
        let error = serde_json::from_str::<Pair>(r#"{"values":[1,2,3]}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("2-element limit"), "{error}");
    }

    #[test]
    fn complete_signature_acknowledgement_fits_reply_preflight() {
        let reply = WorkerResponse {
            id: 7,
            response: Response::SignaturesSynced {
                binary_sha256: "a".repeat(64),
                context: "b".repeat(64),
                unapplied: (0..crate::signatures::MAX_SIGNATURES)
                    .map(|function| SignatureStatus {
                        function: function as u64,
                        reason: "Incompatible engine or ABI".into(),
                    })
                    .collect(),
            },
        };
        let encoded = serde_json::to_vec(&reply).unwrap();
        let shape = check_reply(&encoded).unwrap();
        assert_eq!((shape.id, shape.kind.as_str()), (7, "signatures_synced"));
        assert!(
            matches!(serde_json::from_slice::<WorkerResponse>(&encoded).unwrap().response,
            Response::SignaturesSynced { unapplied,.. } if unapplied.len() == crate::signatures::MAX_SIGNATURES)
        );
    }

    #[test]
    fn reply_preflight_bounds_each_kind_before_materializing() {
        let shape = check_reply(br#"{"id":7,"response":{"kind":"error","message":"x"}}"#).unwrap();
        assert_eq!((shape.id, shape.kind.as_str()), (7, "error"));
        let graph = |count: usize| {
            format!(
                r#"{{"id":1,"response":{{"kind":"graph","view":{{"address":0,"blocks":[],"edges":[],"calls":[],"warnings":[{}]}}}}}}"#,
                vec!["\"\""; count].join(",")
            )
        };
        assert!(check_reply(graph(1000).as_bytes()).is_ok());
        let nodes = reply_nodes("graph").unwrap();
        assert!(
            check_reply(graph(nodes).as_bytes())
                .unwrap_err()
                .contains("node budget")
        );
        for line in [
            r#"{"id":1,"response":{"message":"x","kind":"error"}}"#,
            r#"{"id":1,"response":{"kind":"surprise"}}"#,
            r#"{"id":1,"id":2,"response":{"kind":"error","message":"x"}}"#,
            r#"{"id":1,"extra":0,"response":{"kind":"error","message":"x"}}"#,
            r#"{"id":1}"#,
            r#"{"id":1,"response":{"kind":"error","message":"x"}} trailing"#,
        ] {
            assert!(check_reply(line.as_bytes()).is_err(), "{line}");
        }
        // Small reply kinds stay small even inside a large frame.
        let progress = format!(
            r#"{{"id":1,"response":{{"kind":"progress","progress":[{}]}}}}"#,
            vec!["0"; 1000].join(",")
        );
        assert!(check_reply(progress.as_bytes()).is_err());
    }

    #[test]
    fn json_preflight_bounds_nodes_and_strings() {
        assert!(check_json(b"[1,2,3]", 4, 8).is_ok());
        assert!(check_json(b"[1,2,3]", 3, 8).is_err());
        assert!(check_json(br#"["123456789"]"#, 4, 8).is_err());
        assert!(check_json(b"[1] [2]", 8, 8).is_err());
    }
}
