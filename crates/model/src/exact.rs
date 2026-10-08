// SPDX-License-Identifier: GPL-3.0-or-later

//! Exact-capacity rendering of secret-bearing output (design §12): the one
//! implementation every renderer and emitter uses.
//!
//! A growing `String` or `Vec` reallocates by copying and frees the old
//! buffer without zeroizing it, so rendered key material could survive in
//! freed memory. [`text`] and [`bytes`] therefore run the renderer twice:
//! once into a counter, then into a zeroizing buffer allocated with exactly
//! the counted capacity, which the second run fills without reallocating.
//! Renderers must be deterministic, as every Mooring renderer is pure.

use std::fmt::Display;
use std::io;

use zeroize::Zeroizing;

/// Where a text renderer writes.
pub trait TextSink {
    /// Appends `text`.
    fn put(&mut self, text: &str);

    /// Appends the `Display` form of a value that is not secret.
    fn show(&mut self, value: &dyn Display) {
        self.put(&value.to_string());
    }
}

/// A plain string sink, for output that holds no secret.
impl TextSink for String {
    fn put(&mut self, text: &str) {
        self.push_str(text);
    }
}

/// Counts the bytes a rendering produces.
struct Count(usize);

impl TextSink for Count {
    fn put(&mut self, text: &str) {
        self.0 += text.len();
    }
}

impl io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fills a zeroizing buffer that [`Count`] sized.
struct Fill(Zeroizing<String>);

impl TextSink for Fill {
    fn put(&mut self, text: &str) {
        self.0.push_str(text);
    }
}

/// Runs `render` twice and returns its text in a zeroizing buffer of
/// exactly the needed capacity.
pub fn text(render: impl Fn(&mut dyn TextSink)) -> Zeroizing<String> {
    let mut count = Count(0);
    render(&mut count);
    let mut fill = Fill(Zeroizing::new(String::with_capacity(count.0)));
    render(&mut fill);
    fill.0
}

/// Runs `write` twice and returns its bytes in a zeroizing buffer of
/// exactly the needed capacity. `write` fails only with its own error: the
/// counter and the buffer never refuse bytes.
pub fn bytes<E>(
    write: impl Fn(&mut dyn io::Write) -> Result<(), E>,
) -> Result<Zeroizing<Vec<u8>>, E> {
    let mut count = Count(0);
    write(&mut count)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(count.0));
    write(&mut *buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_written_into_an_exactly_sized_buffer() {
        let rendered = text(|sink| {
            sink.put("a = ");
            sink.show(&42);
            sink.put("\n");
        });
        assert_eq!(rendered.as_str(), "a = 42\n");
        assert_eq!(rendered.capacity(), rendered.len());
    }

    #[test]
    fn bytes_are_written_into_an_exactly_sized_buffer() {
        let rendered = bytes(|out| {
            out.write_all(b"secret")?;
            write!(out, "-{}", 7)
        })
        .unwrap();
        assert_eq!(rendered.as_slice(), b"secret-7");
        assert_eq!(rendered.capacity(), rendered.len());
    }

    #[test]
    fn a_failing_writer_reports_its_own_error() {
        let error = bytes(|_| Err::<(), _>(io::Error::other("refused"))).unwrap_err();
        assert_eq!(error.to_string(), "refused");
    }

    #[test]
    fn a_plain_string_is_a_sink() {
        let mut out = String::new();
        out.put("x");
        out.show(&1);
        assert_eq!(out, "x1");
    }
}
