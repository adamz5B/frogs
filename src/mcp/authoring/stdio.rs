//! The two threads at the edges of `frogs mcp`: a reader that frames newline-delimited input under a
//! byte cap, and a writer that owns stdout. Both are plain `std::thread`s: a blocking `read` on stdin
//! can't be cancelled, so shutdown must never wait for the reader.

use std::io::{BufRead, Write};

use tokio::sync::{mpsc, oneshot};

/// One framed unit of input.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Input {
    Line(Vec<u8>),
    /// A line over the byte cap: its bytes were discarded up to the newline.
    TooLong,
    Eof,
}

/// Splits `input` on `\n`, dropping a trailing `\r` and blank lines, discarding any line over `max_line_bytes`.
/// Returns when the input ends or the receiver is gone.
pub(super) fn read_lines<R: BufRead>(mut input: R, max_line_bytes: usize, tx: &mpsc::Sender<Input>) {
    let mut line: Vec<u8> = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = match input.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if chunk.is_empty() {
            break;
        }
        let newline = chunk.iter().position(|b| *b == b'\n');
        let end = newline.unwrap_or(chunk.len());
        if !too_long {
            line.extend_from_slice(&chunk[..end]);
            if line.len() > max_line_bytes {
                too_long = true;
                line = Vec::new();
            }
        }
        let consumed = newline.map_or(end, |pos| pos + 1);
        input.consume(consumed);
        if newline.is_some() && !finish_line(&mut line, &mut too_long, tx) {
            return;
        }
    }
    if (too_long || !line.is_empty()) && !finish_line(&mut line, &mut too_long, tx) {
        return;
    }
    let _ = tx.blocking_send(Input::Eof);
}

/// `false` when the receiver is gone.
fn finish_line(line: &mut Vec<u8>, too_long: &mut bool, tx: &mpsc::Sender<Input>) -> bool {
    let item = if *too_long {
        Some(Input::TooLong)
    } else {
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        (!line.iter().all(u8::is_ascii_whitespace)).then(|| Input::Line(std::mem::take(line)))
    };
    line.clear();
    *too_long = false;
    match item {
        Some(item) => tx.blocking_send(item).is_ok(),
        None => true,
    }
}

/// Spawns the writer thread. It writes each received line plus `\n` and flushes, so a response is never half-written.
/// On a write error it reports once on `failed` and stops; `done` fires when it exits for any reason.
pub(super) fn spawn_writer<W: Write + Send + 'static>(mut out: W, mut rx: mpsc::Receiver<String>, failed: oneshot::Sender<()>, done: oneshot::Sender<()>) {
    std::thread::Builder::new()
        .name("frogs-mcp-writer".to_string())
        .spawn(move || {
            while let Some(line) = rx.blocking_recv() {
                let mut framed = line.into_bytes();
                framed.push(b'\n');
                if let Err(e) = out.write_all(&framed).and_then(|()| out.flush()) {
                    tracing::error!("cannot write to stdout: {e}");
                    let _ = failed.send(());
                    break;
                }
            }
            let _ = done.send(());
        })
        .expect("spawning the stdout writer thread should succeed");
}

pub(super) fn spawn_reader<R: BufRead + Send + 'static>(input: R, max_line_bytes: usize, tx: mpsc::Sender<Input>) {
    std::thread::Builder::new()
        .name("frogs-mcp-stdin".to_string())
        .spawn(move || read_lines(input, max_line_bytes, &tx))
        .expect("spawning the stdin reader thread should succeed");
}
