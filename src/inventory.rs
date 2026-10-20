//! Worker-side bookkeeping that lets discovery batches publish only inventory
//! changes. The parent reconstructs and validates the complete inventory.
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::model::{FunctionInfo, InventoryChange, MAX_FUNCTIONS};

/// Journaled rows beyond this force a complete replacement instead.
const MAX_JOURNAL_ROWS: usize = 16_384;

#[derive(Debug)]
struct Edit {
    /// The address was in the inventory at the published revision.
    published: bool,
    current: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct Ordinary {
    complete: bool,
    buffer: usize,
    len: usize,
}

/// Owned by one worker process; revisions restart with each worker.
#[derive(Debug, Default)]
pub(crate) struct Inventory {
    revision: u64,
    /// Rows changed since `revision`. `None` until the first publication and
    /// after overflow, either of which requires a replacement.
    journal: Option<BTreeMap<u64, Edit>>,
    ordinary: Option<Ordinary>,
    /// Debug builds verify every publication against the published rows.
    #[cfg(debug_assertions)]
    shadow: Option<(u64, Vec<FunctionInfo>)>,
}

impl Inventory {
    /// Records that `functions` is the selection made without priority owners
    /// for the engine's current functions. `complete` means no candidate was
    /// rejected, so owner priority cannot change that selection either.
    pub fn certify(&mut self, functions: &[FunctionInfo], complete: bool) {
        self.ordinary = Some(Ordinary {
            complete,
            buffer: functions.as_ptr() as usize,
            len: functions.len(),
        });
    }

    /// Clears the certificate, returning whether it still described
    /// `functions` and was complete. Call before any engine mutation.
    pub fn take_certificate(&mut self, functions: &[FunctionInfo]) -> Option<bool> {
        self.ordinary
            .take()
            .filter(|ordinary| {
                ordinary.buffer == functions.as_ptr() as usize && ordinary.len == functions.len()
            })
            .map(|ordinary| ordinary.complete)
    }

    /// Journals the difference between two strictly ordered inventories.
    pub fn record(&mut self, old: &[FunctionInfo], new: &[FunctionInfo]) {
        let mut old = old.iter().peekable();
        let mut new = new.iter().peekable();
        loop {
            let order = match (old.peek(), new.peek()) {
                (None, None) => break,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(before), Some(after)) => before.address.cmp(&after.address),
            };
            match order {
                Ordering::Less => {
                    if let Some(before) = old.next() {
                        self.remove(before.address);
                    }
                }
                Ordering::Greater => {
                    if let Some(after) = new.next() {
                        self.upsert(after.address, &after.name, false);
                    }
                }
                Ordering::Equal => {
                    if let (Some(before), Some(after)) = (old.next(), new.next())
                        && before.name != after.name
                    {
                        self.upsert(after.address, &after.name, true);
                    }
                }
            }
        }
    }

    /// Journals a row that was absent before this change.
    pub fn insert(&mut self, function: &FunctionInfo) {
        self.upsert(function.address, &function.name, false);
    }

    fn upsert(&mut self, address: u64, name: &str, existed: bool) {
        self.edit(address, existed, Some(name.to_owned()));
    }

    fn remove(&mut self, address: u64) {
        self.edit(address, true, None);
    }

    fn edit(&mut self, address: u64, existed: bool, current: Option<String>) {
        let Some(journal) = &mut self.journal else {
            return;
        };
        let edit = journal.entry(address).or_insert(Edit {
            published: existed,
            current: None,
        });
        edit.current = current;
        if !edit.published && edit.current.is_none() {
            journal.remove(&address);
        }
        if journal.len() > MAX_JOURNAL_ROWS {
            self.journal = None;
        }
    }

    /// The change from the parent's adopted `base` to `functions`. A missing or
    /// different base, an overflowed journal, or a delta larger than the
    /// inventory publishes a replacement.
    pub fn publish(
        &mut self,
        base: Option<u64>,
        functions: &[FunctionInfo],
    ) -> Result<InventoryChange, String> {
        let change = self.change(base, functions)?;
        #[cfg(debug_assertions)]
        {
            let shadow = self
                .shadow
                .as_ref()
                .filter(|(revision, _)| Some(*revision) == base)
                .map(|(revision, rows)| (*revision, rows.as_slice()));
            let rebuilt = change.clone().apply(shadow).expect("valid publication");
            assert_eq!(rebuilt.as_deref().unwrap_or(functions), functions);
            self.shadow = Some((change.revision(), functions.to_vec()));
        }
        Ok(change)
    }

    fn change(
        &mut self,
        base: Option<u64>,
        functions: &[FunctionInfo],
    ) -> Result<InventoryChange, String> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or("Inventory revision overflow")?;
        if let (Some(journal), Some(base)) = (&mut self.journal, base)
            && base == self.revision
        {
            if journal.is_empty() {
                return Ok(InventoryChange::Unchanged { revision: base });
            }
            if journal.len() <= functions.len() {
                let mut upserts = Vec::new();
                let mut removals = Vec::new();
                for (address, edit) in std::mem::take(journal) {
                    match edit.current {
                        Some(name) => upserts.push(FunctionInfo { address, name }),
                        None => removals.push(address),
                    }
                }
                self.revision = revision;
                return Ok(InventoryChange::Delta {
                    base,
                    revision,
                    upserts,
                    removals,
                });
            }
        }
        debug_assert!(functions.len() <= MAX_FUNCTIONS);
        self.revision = revision;
        self.journal = Some(BTreeMap::new());
        Ok(InventoryChange::Replace {
            revision,
            functions: functions.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(rows: &[(u64, &str)]) -> Vec<FunctionInfo> {
        rows.iter()
            .map(|&(address, name)| FunctionInfo {
                address,
                name: name.into(),
            })
            .collect()
    }

    fn adopt(base: &mut Option<(u64, Vec<FunctionInfo>)>, change: InventoryChange) {
        let revision = change.revision();
        let previous = base
            .as_ref()
            .map(|(revision, functions)| (*revision, functions.as_slice()));
        if let Some(functions) = change.apply(previous).unwrap() {
            *base = Some((revision, functions));
        }
    }

    #[test]
    fn deltas_reconstruct_renames_insertions_removals_and_reinsertions() {
        let mut worker = Inventory::default();
        let mut parent = None;
        let mut current = rows(&[(0x10, "a"), (0x20, "b"), (0x30, "c")]);
        let change = worker.publish(None, &current).unwrap();
        assert!(matches!(
            change,
            InventoryChange::Replace { revision: 1, .. }
        ));
        adopt(&mut parent, change);

        let base = parent.as_ref().map(|(revision, _)| *revision);
        let change = worker.publish(base, &current).unwrap();
        assert!(matches!(change, InventoryChange::Unchanged { revision: 1 }));
        adopt(&mut parent, change);

        // Rename, insert, remove, and an insert removed again before publication.
        let next = rows(&[
            (0x10, "renamed"),
            (0x18, "new"),
            (0x30, "c"),
            (0x40, "gone"),
        ]);
        worker.record(&current, &next);
        current = next;
        let next = rows(&[(0x10, "renamed"), (0x18, "new"), (0x30, "c")]);
        worker.record(&current, &next);
        current = next;
        let base = parent.as_ref().map(|(revision, _)| *revision);
        let change = worker.publish(base, &current).unwrap();
        let InventoryChange::Delta {
            upserts, removals, ..
        } = &change
        else {
            panic!("expected a delta: {change:?}");
        };
        assert_eq!(upserts.len(), 2);
        assert_eq!(removals, &[0x20]);
        adopt(&mut parent, change);
        assert_eq!(parent.as_ref().unwrap().1, current);

        // Removing and reinserting a published row upserts it.
        let next = rows(&[(0x10, "renamed"), (0x30, "c")]);
        worker.record(&current, &next);
        let mut reinserted = next.clone();
        reinserted.insert(1, rows(&[(0x18, "again")])[0].clone());
        worker.record(&next, &reinserted);
        let base = parent.as_ref().map(|(revision, _)| *revision);
        adopt(&mut parent, worker.publish(base, &reinserted).unwrap());
        assert_eq!(parent.as_ref().unwrap().1, reinserted);
    }

    #[test]
    fn stale_or_missing_bases_and_overflow_publish_replacements() {
        let mut worker = Inventory::default();
        let current = rows(&[(0x10, "a")]);
        worker.publish(None, &current).unwrap();
        assert!(matches!(
            worker.publish(Some(0), &current).unwrap(),
            InventoryChange::Replace { revision: 2, .. }
        ));
        assert!(matches!(
            worker.publish(None, &current).unwrap(),
            InventoryChange::Replace { revision: 3, .. }
        ));
        let large: Vec<_> = (0..=MAX_JOURNAL_ROWS as u64)
            .map(|n| FunctionInfo {
                address: 0x1000 + n,
                name: format!("f{n}"),
            })
            .collect();
        worker.record(&current, &large);
        assert!(matches!(
            worker.publish(Some(3), &large).unwrap(),
            InventoryChange::Replace { revision: 4, .. }
        ));
    }

    #[test]
    fn parent_rejects_mismatched_or_malformed_changes() {
        let base = rows(&[(0x10, "a"), (0x20, "b")]);
        let delta =
            |base, revision, upserts: &[(u64, &str)], removals: &[u64]| InventoryChange::Delta {
                base,
                revision,
                upserts: rows(upserts),
                removals: removals.to_vec(),
            };
        let adopted = Some((4, base.as_slice()));
        for change in [
            InventoryChange::Unchanged { revision: 3 },
            delta(3, 4, &[(0x30, "c")], &[]),
            delta(4, 6, &[(0x30, "c")], &[]),
            delta(4, 5, &[], &[]),
            delta(4, 5, &[], &[0x18]),
            delta(4, 5, &[(0x10, "x")], &[0x10]),
            delta(4, 5, &[(0x30, "c"), (0x30, "d")], &[]),
            delta(4, 5, &[], &[0x20, 0x10]),
        ] {
            assert!(change.clone().apply(adopted).is_err(), "{change:?}");
        }
        assert!(
            InventoryChange::Unchanged { revision: 4 }
                .apply(None)
                .is_err()
        );
        let merged = delta(4, 5, &[(0x10, "x"), (0x18, "new")], &[0x20])
            .apply(adopted)
            .unwrap()
            .unwrap();
        assert_eq!(merged, rows(&[(0x10, "x"), (0x18, "new")]));
    }

    #[test]
    fn certificates_are_bound_to_one_inventory_buffer() {
        let mut inventory = Inventory::default();
        let functions = rows(&[(0x10, "a")]);
        inventory.certify(&functions, true);
        assert_eq!(inventory.take_certificate(&functions), Some(true));
        assert_eq!(inventory.take_certificate(&functions), None);
        inventory.certify(&functions, false);
        let replaced = functions.clone();
        assert_eq!(inventory.take_certificate(&replaced), None);
    }
}
