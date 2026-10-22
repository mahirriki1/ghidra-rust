//! Bounded defined-string scanning over immutable mapped bytes.
use super::*;

fn printable(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Scan immutable mapped bytes with a bounded result preview and one extra match
/// to distinguish an exactly full result from an actually truncated result.
pub(super) fn scan_strings(
    snapshot: &[u8],
    sections: &[SectionInfo],
    minimum_length: usize,
) -> Result<Response, String> {
    if !(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM).contains(&minimum_length) {
        return Err(format!(
            "Minimum string length must be between {MIN_STRING_LENGTH} and {MAX_STRING_MINIMUM}."
        ));
    }
    let mut strings = Vec::new();
    let mut scanned = 0u64;
    let mut truncated = false;
    'sections: for section in sections {
        let size = section.file_size.min(MAX_SCAN_BYTES - scanned);
        if size < section.file_size {
            truncated = true;
        }
        if size == 0 {
            continue;
        }
        let mut ascii = StringRun::new(minimum_length);
        // Both parities are scanned: packed UTF-16 strings need not be aligned.
        let mut wide = [
            StringRun::new(minimum_length),
            StringRun::new(minimum_length),
        ];
        let mut previous = None;
        let mut offset = 0u64;
        while offset < size {
            let count = (size - offset).min(SCAN_CHUNK as u64) as usize;
            let start = section
                .file_offset
                .checked_add(offset)
                .and_then(|start| usize::try_from(start).ok())
                .ok_or("Section file offset overflows")?;
            let end = start
                .checked_add(count)
                .ok_or("Section file offset overflows")?;
            let chunk = snapshot
                .get(start..end)
                .ok_or("Section extends past immutable image snapshot")?;
            for (index, &byte) in chunk.iter().enumerate() {
                let address = section
                    .address
                    .checked_add(offset + index as u64)
                    .ok_or("Section virtual address overflows")?;
                ascii.feed(
                    printable(byte).then_some(byte as char),
                    address,
                    "ASCII",
                    &mut strings,
                );
                if let Some(low) = previous {
                    let start = address - 1;
                    wide[(start & 1) as usize].feed(
                        (byte == 0 && printable(low)).then_some(low as char),
                        start,
                        "UTF-16LE",
                        &mut strings,
                    );
                }
                previous = Some(byte);
                if strings.len() > MAX_STRING_RESULTS {
                    truncated = true;
                    break 'sections;
                }
            }
            offset += count as u64;
        }
        ascii.flush("ASCII", &mut strings);
        for run in &mut wide {
            run.flush("UTF-16LE", &mut strings);
        }
        scanned += size;
        if strings.len() > MAX_STRING_RESULTS {
            truncated = true;
            break;
        }
    }
    strings.truncate(MAX_STRING_RESULTS);
    strings.sort_by_key(|s| s.address);
    Ok(Response::Strings { strings, truncated })
}

pub(super) struct StringRun {
    minimum_length: usize,
    start: u64,
    count: usize,
    text: String,
}

impl Default for StringRun {
    fn default() -> Self {
        Self::new(MIN_STRING_LENGTH)
    }
}

impl StringRun {
    pub(super) fn new(minimum_length: usize) -> Self {
        Self {
            minimum_length,
            start: 0,
            count: 0,
            text: String::new(),
        }
    }

    pub(super) fn feed(
        &mut self,
        character: Option<char>,
        address: u64,
        encoding: &str,
        output: &mut Vec<StringEntry>,
    ) {
        if let Some(character) = character {
            if self.count == 0 {
                self.start = address;
            }
            self.count += 1;
            if self.text.len() < MAX_STRING_PREVIEW {
                self.text.push(character);
            }
        } else {
            self.flush(encoding, output);
        }
    }

    pub(super) fn flush(&mut self, encoding: &str, output: &mut Vec<StringEntry>) {
        if self.count >= self.minimum_length && output.len() <= MAX_STRING_RESULTS {
            let mut text = std::mem::take(&mut self.text);
            if self.count > MAX_STRING_PREVIEW {
                text.push('…');
            }
            output.push(StringEntry {
                address: self.start,
                text,
                encoding: encoding.into(),
            });
        }
        self.count = 0;
        self.text.clear();
    }
}
