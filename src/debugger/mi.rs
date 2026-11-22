//! The subset of GDB/MI3 used by the local debugger. Keep ordered fields since
//! GDB emits repeated keys in result lists such as `stack=[frame=...,frame=...]`.
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::process::{ChildStdin, ChildStdout};
use std::time::Instant;

use super::Error;

const MAX_LINE: usize = 512 * 1024;
const MAX_VALUES: usize = 16_384;
const MAX_DEPTH: usize = 24;

pub(super) type Fields = Vec<(String, Value)>;

#[derive(Debug)]
pub(super) enum Value {
    Text(String),
    Tuple(Fields),
    List(Vec<Self>),
}

impl Value {
    pub(super) fn text(&self) -> Result<&str, Error> {
        match self {
            Self::Text(text) => Ok(text),
            _ => Err(Error::protocol("Expected MI string")),
        }
    }

    pub(super) fn tuple(&self) -> Result<&Fields, Error> {
        match self {
            Self::Tuple(fields) => Ok(fields),
            _ => Err(Error::protocol("Expected MI tuple")),
        }
    }
}

pub(super) trait FieldAccess {
    fn field(&self, name: &str) -> Result<Option<&Value>, Error>;
    fn required(&self, name: &str) -> Result<&Value, Error> {
        self.field(name)?
            .ok_or_else(|| Error::protocol(format!("Missing MI field {name}")))
    }
    fn text(&self, name: &str) -> Result<&str, Error> {
        self.required(name)?.text()
    }
    fn list(&self, name: &str) -> Result<&[Value], Error> {
        match self.required(name)? {
            Value::List(values) => Ok(values),
            _ => Err(Error::protocol("Expected MI list")),
        }
    }
}

impl FieldAccess for Fields {
    fn field(&self, name: &str) -> Result<Option<&Value>, Error> {
        let mut found = self.iter().filter(|(key, _)| key == name);
        let value = found.next().map(|(_, value)| value);
        if found.next().is_some() {
            return Err(Error::protocol(format!("Duplicate MI field {name}")));
        }
        Ok(value)
    }
}

pub(super) struct Record {
    pub(super) token: Option<u64>,
    pub(super) kind: u8,
    pub(super) class: String,
    pub(super) fields: Fields,
}

fn record(line: &[u8]) -> Result<Option<Record>, Error> {
    let mut parser = Parser {
        rest: line.trim_ascii_end(),
        values: 0,
    };
    if parser.rest.is_empty() || parser.rest == b"(gdb)" {
        return Ok(None);
    }
    if matches!(parser.peek(), Some(b'~' | b'@' | b'&')) {
        // MI console, target and diagnostic streams are display data only.
        return Ok(None);
    }
    let n = parser
        .rest
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let token = if n > 0 {
        let token = std::str::from_utf8(&parser.rest[..n])
            .expect("ASCII digits")
            .parse()
            .map_err(|_| Error::protocol("Invalid MI token"))?;
        parser.rest = &parser.rest[n..];
        Some(token)
    } else {
        None
    };
    let kind = parser.pop()?;
    if !matches!(kind, b'^' | b'*' | b'=' | b'+') {
        return Err(Error::protocol("Invalid MI record type"));
    }
    let class = parser.ident()?;
    let mut fields = Vec::new();
    while parser.take(b',') {
        fields.push(parser.field(0)?);
    }
    if !parser.rest.is_empty() {
        return Err(Error::protocol("Trailing MI record data"));
    }
    Ok(Some(Record {
        token,
        kind,
        class,
        fields,
    }))
}

struct Parser<'a> {
    rest: &'a [u8],
    values: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn pop(&mut self) -> Result<u8, Error> {
        let (&byte, rest) = self
            .rest
            .split_first()
            .ok_or_else(|| Error::protocol("Truncated MI data"))?;
        self.rest = rest;
        Ok(byte)
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.rest = &self.rest[1..];
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(Error::protocol("Invalid MI separator"))
        }
    }

    fn ident(&mut self) -> Result<String, Error> {
        let n = self
            .rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            .count();
        if n == 0 || n > 128 {
            return Err(Error::protocol("Invalid MI identifier"));
        }
        let (ident, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(String::from_utf8(ident.to_vec()).expect("ASCII identifier"))
    }

    fn field(&mut self, depth: usize) -> Result<(String, Value), Error> {
        let name = self.ident()?;
        self.expect(b'=')?;
        Ok((name, self.value(depth)?))
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        self.values += 1;
        if self.values > MAX_VALUES || depth > MAX_DEPTH {
            return Err(Error::protocol("MI record exceeds its structure limit"));
        }
        match self.peek() {
            Some(b'"') => self.string().map(Value::Text),
            Some(b'{') => {
                self.pop()?;
                let mut fields = Vec::new();
                if !self.take(b'}') {
                    loop {
                        fields.push(self.field(depth + 1)?);
                        if !self.take(b',') {
                            break;
                        }
                    }
                    self.expect(b'}')?;
                }
                Ok(Value::Tuple(fields))
            }
            Some(b'[') => {
                self.pop()?;
                let mut items = Vec::new();
                if !self.take(b']') {
                    loop {
                        let value = match self.peek() {
                            Some(b'"' | b'[' | b'{') => self.value(depth + 1)?,
                            _ => self.field(depth + 1)?.1,
                        };
                        items.push(value);
                        if !self.take(b',') {
                            break;
                        }
                    }
                    self.expect(b']')?;
                }
                Ok(Value::List(items))
            }
            _ => Err(Error::protocol("Invalid MI value")),
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        self.expect(b'"')?;
        let mut bytes = Vec::new();
        loop {
            match self.pop()? {
                b'"' => return Ok(String::from_utf8_lossy(&bytes).into_owned()),
                b'\\' => {
                    let byte = match self.pop()? {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'a' => 7,
                        b'b' => 8,
                        b'f' => 12,
                        b'v' => 11,
                        b'"' => b'"',
                        b'\\' => b'\\',
                        digit @ b'0'..=b'7' => {
                            let mut value = u16::from(digit - b'0');
                            for _ in 0..2 {
                                let Some(digit @ b'0'..=b'7') = self.peek() else {
                                    break;
                                };
                                self.pop()?;
                                value = value * 8 + u16::from(digit - b'0');
                            }
                            u8::try_from(value)
                                .map_err(|_| Error::protocol("Invalid MI byte escape"))?
                        }
                        _ => return Err(Error::protocol("Unknown MI string escape")),
                    };
                    bytes.push(byte);
                }
                byte => bytes.push(byte),
            }
        }
    }
}

pub(super) fn quote(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut quoted = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                quoted.push('\\');
                quoted.push(char::from(byte));
            }
            b' '..=b'~' => quoted.push(char::from(byte)),
            _ => write!(quoted, "\\{byte:03o}").expect("writing to String"),
        }
    }
    quoted.push('"');
    quoted
}

pub(super) struct Transport {
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    pending: Vec<u8>,
}

impl Transport {
    pub(super) fn new(input: ChildStdin, output: ChildStdout) -> Result<Self, Error> {
        nonblocking(&input)?;
        nonblocking(&output)?;
        Ok(Self {
            input,
            output: BufReader::new(output),
            pending: Vec::new(),
        })
    }

    pub(super) fn send(&mut self, token: u64, command: &str) -> Result<(), Error> {
        let line = format!("{token}{command}\n");
        // Linux pipe writes up to PIPE_BUF are atomic. Nonblocking keeps a
        // stuck debugger from delaying the caller even while sending a command.
        if line.len() > libc::PIPE_BUF || command.contains(['\n', '\r', '\0']) {
            return Err(Error::Invalid(
                "GDB command is too long or contains a line break".into(),
            ));
        }
        match self.input.write(line.as_bytes()) {
            Ok(n) if n == line.len() => Ok(()),
            Ok(_) => Err(Error::protocol("Incomplete GDB command write")),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn next(&mut self, deadline: Instant) -> Result<Option<Record>, Error> {
        loop {
            if Instant::now() >= deadline {
                return Ok(None);
            }
            match self.output.fill_buf() {
                Ok([]) => return Err(Error::protocol("GDB closed its output")),
                Ok(data) => {
                    let end = data.iter().position(|&byte| byte == b'\n');
                    let count = end.map_or(data.len(), |i| i + 1);
                    if count > MAX_LINE.saturating_sub(self.pending.len()) {
                        return Err(Error::protocol("GDB output line exceeded the size limit"));
                    }
                    self.pending.extend_from_slice(&data[..count]);
                    self.output.consume(count);
                    if end.is_some() {
                        let parsed = record(&self.pending);
                        self.pending.clear();
                        if let Some(record) = parsed? {
                            return Ok(Some(record));
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut fd = libc::pollfd {
                        fd: self.output.get_ref().as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let millis = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis();
                    let timeout = i32::try_from(millis.saturating_add(1)).unwrap_or(i32::MAX);
                    // SAFETY: poll borrows one initialized entry for this call.
                    let result = unsafe { libc::poll(&mut fd, 1, timeout) };
                    if result == -1 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error.into());
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let fd = fd.as_fd();
    // SAFETY: fd stays open throughout the fcntl call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is still open and F_SETFL accepts the integer status flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stack_lists_and_c_string_escapes() {
        let data = br#"17^done,stack=[frame={level="0",func="spaced \"name\""},frame={level="1",func="\303\251"}],ignored=[]"#;
        let record = record(data).unwrap().unwrap();
        let stack = record.fields.list("stack").unwrap();
        assert_eq!(record.token, Some(17));
        assert_eq!(
            stack[0].tuple().unwrap().text("func").unwrap(),
            "spaced \"name\""
        );
        assert_eq!(stack[1].tuple().unwrap().text("func").unwrap(), "é");
        let encoded = quote(b"x\"\\\n\xff");
        assert_eq!(encoded, r#""x\"\\\012\377""#);
    }

    #[test]
    fn rejects_bad_and_excessively_nested_records() {
        assert!(record(br#"1^done,foo="unclosed"#).is_err());
        let data = format!(
            "1^done,foo={}\"x\"{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(record(data.as_bytes()).is_err());
        assert!(
            record(br#"1^done,foo="x",foo="y""#)
                .unwrap()
                .unwrap()
                .fields
                .text("foo")
                .is_err()
        );
    }
}
