//! Presentation orders for the analysis tables.
//!
//! Tables keep their rows in native order. A [`TableSort`] holds a sorted
//! copy of the row identities a table shows, rebuilt only when the table's
//! inputs or the requested sort change. Large tables sort on a background
//! thread; the authoritative analysis data is never reordered.
use crate::theme::SortDirection;
use eframe::egui;
use std::cmp::Ordering;
use std::sync::atomic::{AtomicUsize, Ordering as Atomic};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Tables up to this many rows, with at most [`INLINE_TEXT`] bytes of text
/// keys, sort on the GUI thread.
const INLINE_ROWS: usize = 4096;
const INLINE_TEXT: usize = 64 * 1024;
/// Sort threads alive at once across every table, including threads whose
/// table was reset while they ran.
const MAX_SORT_THREADS: usize = 2;
static SORT_THREADS: AtomicUsize = AtomicUsize::new(0);
/// Leading bytes of a text value that take part in comparisons.
const MAX_KEY_TEXT: usize = 1024;
/// GUI time spent per frame collecting sort keys.
const KEY_BUDGET: Duration = Duration::from_millis(2);
/// Upper bound on one copied row, in UTF-8 bytes.
const MAX_COPY_BYTES: usize = 16 * 1024;

/// A sorted column and its direction.
pub(crate) type Active = (usize, SortDirection);
/// The displayed order; `None` is the native order.
pub(crate) type Sort = Option<Active>;

/// Ascending, then descending, then the native order again. Another column
/// starts ascending.
pub(crate) fn cycle(current: Sort, column: usize) -> Sort {
    match current {
        Some((active, SortDirection::Ascending)) if active == column => {
            Some((column, SortDirection::Descending))
        }
        Some((active, SortDirection::Descending)) if active == column => None,
        _ => Some((column, SortDirection::Ascending)),
    }
}

/// One row's value in the sorted column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SortKey {
    Number(u64),
    /// Text and its lowercase form, when that differs. Folding happens once,
    /// while keys are collected, so comparisons are plain byte orders.
    Text {
        folded: Option<Box<str>>,
        exact: Box<str>,
    },
    /// Unknown or empty; always after every known value.
    Missing,
}

impl SortKey {
    pub(crate) fn number(value: Option<u64>) -> Self {
        value.map_or(Self::Missing, Self::Number)
    }

    /// Empty text is missing. Only the leading [`MAX_KEY_TEXT`] bytes are
    /// kept; rows equal in that prefix keep their native order.
    pub(crate) fn text(text: &str) -> Self {
        if text.is_empty() {
            return Self::Missing;
        }
        let mut end = text.len().min(MAX_KEY_TEXT);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let exact = &text[..end];
        let folded = exact.to_lowercase();
        Self::Text {
            folded: (folded != exact).then(|| folded.into()),
            exact: exact.into(),
        }
    }

    /// Text bytes this key holds.
    fn text_bytes(&self) -> usize {
        match self {
            Self::Text { folded, exact } => exact.len() + folded.as_ref().map_or(0, |f| f.len()),
            _ => 0,
        }
    }
}

/// Case-folded, then exact, code-point order. UTF-8 byte order is code-point
/// order.
fn compare_text(
    (left_folded, left): (&Option<Box<str>>, &str),
    (right_folded, right): (&Option<Box<str>>, &str),
) -> Ordering {
    let left_key = left_folded.as_deref().unwrap_or(left);
    let right_key = right_folded.as_deref().unwrap_or(right);
    left_key.cmp(right_key).then_with(|| left.cmp(right))
}

fn compare(left: &SortKey, right: &SortKey, direction: SortDirection) -> Ordering {
    let known = match (left, right) {
        (SortKey::Missing, SortKey::Missing) => return Ordering::Equal,
        (SortKey::Missing, _) => return Ordering::Greater,
        (_, SortKey::Missing) => return Ordering::Less,
        (SortKey::Number(left), SortKey::Number(right)) => left.cmp(right),
        (
            SortKey::Text {
                folded: left_folded,
                exact: left,
            },
            SortKey::Text {
                folded: right_folded,
                exact: right,
            },
        ) => compare_text((left_folded, left), (right_folded, right)),
        (SortKey::Number(_), SortKey::Text { .. }) => Ordering::Less,
        (SortKey::Text { .. }, SortKey::Number(_)) => Ordering::Greater,
    };
    match direction {
        SortDirection::Ascending => known,
        SortDirection::Descending => known.reverse(),
    }
}

/// Positions into `keys` in sorted order. Missing values stay last in both
/// directions and equal values keep their native order.
fn order(keys: &[SortKey], direction: SortDirection) -> Vec<u32> {
    let mut positions: Vec<u32> = (0..keys.len() as u32).collect();
    // Stable, so ties remain in ascending native position.
    positions
        .sort_by(|&left, &right| compare(&keys[left as usize], &keys[right as usize], direction));
    positions
}

/// Whether `positions` is a permutation of `0..len`.
fn is_permutation(positions: &[u32], len: usize) -> bool {
    if positions.len() != len {
        return false;
    }
    let mut seen = vec![false; len];
    positions.iter().all(|&position| {
        seen.get_mut(position as usize)
            .is_some_and(|seen| !std::mem::replace(seen, true))
    })
}

/// Keys collected over frames for one column of the current input.
struct Keys {
    column: usize,
    keys: Vec<SortKey>,
    text: usize,
}

/// One of the [`MAX_SORT_THREADS`] slots, released when its thread ends.
struct ThreadSlot;

impl ThreadSlot {
    fn claim() -> Option<Self> {
        SORT_THREADS
            .fetch_update(Atomic::AcqRel, Atomic::Acquire, |live| {
                (live < MAX_SORT_THREADS).then_some(live + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ThreadSlot {
    fn drop(&mut self) {
        SORT_THREADS.fetch_sub(1, Atomic::AcqRel);
    }
}

/// A background sort. Its result is dropped when the request or the input
/// changed; the thread itself always runs to completion.
struct Job {
    result: Option<(Active, Receiver<Vec<u32>>)>,
    thread: JoinHandle<()>,
}

/// The displayed order of one table whose rows are identities of type `T`.
/// `K` identifies the inputs a native row list was built from: whenever it
/// or the list's length changes, earlier orders are discarded.
pub(crate) struct TableSort<K, T> {
    requested: Sort,
    applied: Sort,
    input: Option<(K, usize)>,
    rows: Vec<T>,
    keys: Option<Keys>,
    job: Option<Job>,
    reveal: bool,
}

impl<K, T> Default for TableSort<K, T> {
    fn default() -> Self {
        Self {
            requested: None,
            applied: None,
            input: None,
            rows: Vec::new(),
            keys: None,
            job: None,
            reveal: false,
        }
    }
}

impl<K: PartialEq + Clone, T: Copy> TableSort<K, T> {
    /// The order the rows are shown in; the header arrow follows this.
    pub(crate) fn applied(&self) -> Sort {
        self.applied
    }

    /// The analyst's latest choice, which may still be in preparation.
    #[cfg(test)]
    pub(crate) fn requested(&self) -> Sort {
        self.requested
    }

    /// A header click on `column`.
    pub(crate) fn click(&mut self, column: usize) {
        self.set(cycle(self.requested, column));
    }

    pub(crate) fn set(&mut self, sort: Sort) {
        if sort != self.requested {
            self.requested = sort;
            self.reveal = true;
        }
    }

    /// Once after an analyst's sort choice takes effect: the caller brings
    /// its selected row into view.
    pub(crate) fn take_reveal(&mut self) -> bool {
        let ready = self.requested.is_none() || self.applied == self.requested;
        ready && std::mem::take(&mut self.reveal)
    }

    /// Advances the order of `baseline`, the table's native rows built from
    /// `input`. `ready` is false while a staged filter is still extending
    /// `baseline`. `key` gives a row's value in a column.
    pub(crate) fn prepare(
        &mut self,
        context: &egui::Context,
        input: &K,
        ready: bool,
        baseline: &[T],
        mut key: impl FnMut(usize, &T) -> SortKey,
    ) {
        if !self
            .input
            .as_ref()
            .is_some_and(|(current, len)| current == input && *len == baseline.len())
        {
            self.input = Some((input.clone(), baseline.len()));
            self.discard();
        }
        let Some(sort) = self.requested else {
            self.discard();
            return;
        };
        if self.applied == Some(sort) {
            return;
        }
        if !ready {
            return;
        }
        if let Some(job) = &mut self.job
            && let Some((wanted, receiver)) = &job.result
        {
            if *wanted == sort {
                match receiver.try_recv() {
                    Ok(positions) => {
                        job.result = None;
                        self.adopt(sort, &positions, baseline);
                        return;
                    }
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => job.result = None,
                }
            } else {
                job.result = None;
            }
        }
        let keys = match &mut self.keys {
            Some(keys) if keys.column == sort.0 => keys,
            slot => slot.insert(Keys {
                column: sort.0,
                keys: Vec::with_capacity(baseline.len()),
                text: 0,
            }),
        };
        let started = Instant::now();
        while let Some(row) = baseline.get(keys.keys.len()) {
            let value = key(sort.0, row);
            keys.text += value.text_bytes();
            keys.keys.push(value);
            if keys.keys.len().is_multiple_of(64) && started.elapsed() >= KEY_BUDGET {
                context.request_repaint();
                return;
            }
        }
        if baseline.len() <= INLINE_ROWS && keys.text <= INLINE_TEXT {
            let positions = order(&keys.keys, sort.1);
            self.adopt(sort, &positions, baseline);
            return;
        }
        // One thread per table, and few overall: a superseded sort, even one
        // from a closed binary, finishes before another starts.
        let slot = if self
            .job
            .as_ref()
            .is_some_and(|job| !job.thread.is_finished())
        {
            None
        } else {
            ThreadSlot::claim()
        };
        let Some(slot) = slot else {
            context.request_repaint_after(Duration::from_millis(15));
            return;
        };
        let keys = self.keys.take().map(|keys| keys.keys).unwrap_or_default();
        let (sender, receiver) = mpsc::channel();
        let repaint = context.clone();
        let spawned = std::thread::Builder::new()
            .name("table-sort".into())
            .spawn(move || {
                let _slot = slot;
                if sender.send(order(&keys, sort.1)).is_ok() {
                    repaint.request_repaint();
                }
            });
        match spawned {
            Ok(thread) => {
                self.job = Some(Job {
                    result: Some((sort, receiver)),
                    thread,
                });
            }
            // Without a thread the table stays in its native order.
            Err(_) => self.requested = None,
        }
    }

    /// The rows to show: the applied order of `baseline`, else `baseline`.
    pub(crate) fn rows<'a>(&'a self, baseline: &'a [T]) -> &'a [T] {
        if self.applied.is_some() && self.rows.len() == baseline.len() {
            &self.rows
        } else {
            baseline
        }
    }

    /// Drops every order derived from earlier input; a running thread's
    /// result is ignored.
    fn discard(&mut self) {
        self.applied = None;
        self.rows = Vec::new();
        self.keys = None;
        if let Some(job) = &mut self.job {
            job.result = None;
        }
    }

    fn adopt(&mut self, sort: Active, positions: &[u32], baseline: &[T]) {
        self.keys = None;
        if !is_permutation(positions, baseline.len()) {
            self.requested = None;
            self.discard();
            return;
        }
        self.rows = positions
            .iter()
            .map(|&position| baseline[position as usize])
            .collect();
        self.applied = Some(sort);
    }
}

/// One table row as tab-separated text, without a trailing newline.
/// Backslashes, tabs and line breaks inside cells are escaped so the row
/// stays one record; overlong rows end in an ellipsis.
pub(crate) fn tsv_row<'a>(cells: impl IntoIterator<Item = &'a str>) -> String {
    let mut row = String::new();
    let limit = MAX_COPY_BYTES - '…'.len_utf8();
    let mut buffer = [0; 4];
    for (index, cell) in cells.into_iter().enumerate() {
        if index > 0 {
            if row.len() + 1 > limit {
                row.push('…');
                return row;
            }
            row.push('\t');
        }
        for c in cell.chars() {
            let piece = match c {
                '\\' => "\\\\",
                '\t' => "\\t",
                '\n' => "\\n",
                '\r' => "\\r",
                c => c.encode_utf8(&mut buffer),
            };
            if row.len() + piece.len() > limit {
                row.push('…');
                return row;
            }
            row.push_str(piece);
        }
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;
    use SortDirection::{Ascending, Descending};

    fn sorted(keys: &[SortKey], direction: SortDirection) -> Vec<u32> {
        order(keys, direction)
    }

    #[test]
    fn missing_values_stay_last_and_ties_keep_native_order() {
        let keys = [
            SortKey::Number(5),
            SortKey::Missing,
            SortKey::Number(1),
            SortKey::Number(5),
            SortKey::Missing,
            SortKey::Number(16),
        ];
        assert_eq!(sorted(&keys, Ascending), [2, 0, 3, 5, 1, 4]);
        assert_eq!(sorted(&keys, Descending), [5, 0, 3, 2, 1, 4]);
    }

    #[test]
    fn text_sorts_case_insensitively_then_exactly() {
        let keys: Vec<_> = ["beta", "Alpha", "alpha", "", "Ärger", "zeta", "beta"]
            .into_iter()
            .map(SortKey::text)
            .collect();
        // Folded "alpha" ties are broken by exact code points: 'A' < 'a'.
        assert_eq!(sorted(&keys, Ascending), [1, 2, 0, 6, 5, 4, 3]);
        assert_eq!(sorted(&keys, Descending), [4, 5, 0, 6, 2, 1, 3]);
    }

    #[test]
    fn long_text_keys_are_bounded_on_a_character_boundary() {
        let text = "é".repeat(MAX_KEY_TEXT);
        let SortKey::Text { exact, .. } = SortKey::text(&text) else {
            panic!("text key expected");
        };
        assert!(exact.len() <= MAX_KEY_TEXT);
        assert!(text.starts_with(&*exact));
    }

    #[test]
    fn header_clicks_cycle_through_native_order() {
        let mut sort = None;
        for expected in [
            Some((1, Ascending)),
            Some((1, Descending)),
            None,
            Some((1, Ascending)),
        ] {
            sort = cycle(sort, 1);
            assert_eq!(sort, expected);
        }
        assert_eq!(cycle(Some((1, Descending)), 0), Some((0, Ascending)));
    }

    fn settle<K: PartialEq + Clone>(
        sort: &mut TableSort<K, u64>,
        input: &K,
        rows: &[u64],
        key: impl Fn(usize, &u64) -> SortKey,
    ) -> Vec<u64> {
        let context = egui::Context::default();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            sort.prepare(&context, input, true, rows, &key);
            let shown = sort.rows(rows).to_vec();
            if sort.applied() == sort.requested() || Instant::now() > deadline {
                return shown;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn large_tables_sort_in_the_background_and_reject_stale_results() {
        let rows: Vec<u64> = (0..20_000u64).map(|i| (i * 7919) % 20_000).collect();
        let by_value = |_: usize, row: &u64| SortKey::Number(*row);
        let mut sort = TableSort::default();
        sort.click(0);
        let context = egui::Context::default();
        // The first frame starts the job and still shows native rows.
        sort.prepare(&context, &1u8, true, &rows, by_value);
        assert_eq!(sort.rows(&rows), rows);
        assert_eq!(sort.applied(), None);
        // A new input arrives before the old sort is adopted.
        let replaced: Vec<u64> = rows.iter().map(|row| row + 1).collect();
        let shown = settle(&mut sort, &2u8, &replaced, by_value);
        assert_eq!(sort.applied(), Some((0, Ascending)));
        assert_eq!(shown, (1..=20_000u64).collect::<Vec<_>>());
        sort.click(0);
        let shown = settle(&mut sort, &2u8, &replaced, by_value);
        assert_eq!(shown, (1..=20_000u64).rev().collect::<Vec<_>>());
        sort.click(0);
        assert_eq!(settle(&mut sort, &2u8, &replaced, by_value), replaced);
    }

    #[test]
    fn long_text_sorts_leave_the_gui_thread_and_resets_cannot_add_threads() {
        let context = egui::Context::default();
        // Few rows, but enough key text to sort in the background.
        let rows: Vec<u64> = (0..200).rev().collect();
        let names: Vec<String> = rows
            .iter()
            .map(|row| format!("{}{row:04}", "Ünïcode".repeat(80)))
            .collect();
        let by_name = |_: usize, row: &u64| SortKey::text(&names[199 - *row as usize]);
        for _ in 0..6 {
            // A closed binary drops its table mid-sort.
            let mut sort = TableSort::<u8, u64>::default();
            sort.click(0);
            sort.prepare(&context, &0, true, &rows, by_name);
            assert_eq!(sort.applied(), None, "not sorted on the GUI thread");
            assert!(SORT_THREADS.load(Atomic::Acquire) <= MAX_SORT_THREADS);
        }
        let mut sort = TableSort::<u8, u64>::default();
        sort.click(0);
        let shown = settle(&mut sort, &0, &rows, by_name);
        assert_eq!(shown, (0..200).collect::<Vec<_>>());
    }

    #[test]
    fn a_staged_filter_shows_native_rows_until_complete() {
        let mut sort = TableSort::default();
        sort.click(0);
        let context = egui::Context::default();
        let by_value = |_: usize, row: &u64| SortKey::Number(*row);
        let mut shown = |ready, rows: &[u64]| {
            sort.prepare(&context, &0u8, ready, rows, by_value);
            sort.rows(rows).to_vec()
        };
        assert_eq!(shown(false, &[3, 1]), [3, 1]);
        assert_eq!(shown(true, &[3, 1, 2]), [1, 2, 3]);
        // A same-input list of another length is new data, not the old order.
        assert_eq!(shown(true, &[9, 4]), [4, 9]);
    }

    #[test]
    fn reveal_follows_only_an_analysts_sort_change() {
        let mut sort = TableSort::<u8, u64>::default();
        let context = egui::Context::default();
        let by_value = |_: usize, row: &u64| SortKey::Number(*row);
        sort.prepare(&context, &0, true, &[2, 1], by_value);
        assert!(!sort.take_reveal());
        sort.click(0);
        assert!(!sort.take_reveal(), "not before the order applies");
        sort.prepare(&context, &0, true, &[2, 1], by_value);
        assert!(sort.take_reveal());
        sort.prepare(&context, &1, true, &[2, 1], by_value);
        assert!(!sort.take_reveal(), "new input re-sorts without scrolling");
    }

    #[test]
    fn copied_rows_stay_one_bounded_record() {
        assert_eq!(
            tsv_row(["401000", "a\tb\\c\r\nd", ""]),
            "401000\ta\\tb\\\\c\\r\\nd\t"
        );
        let long = "ü".repeat(MAX_COPY_BYTES);
        let row = tsv_row(["1", &long]);
        assert!(row.len() <= MAX_COPY_BYTES);
        assert!(row.starts_with("1\tü") && row.ends_with('…'));
    }
}
