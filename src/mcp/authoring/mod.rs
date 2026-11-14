//! `frogs mcp`: a local, stdio MCP server that lets an agent author a frogs project — read the
//! project, run the validator and the mock tests — without ever binding a port. Read-only (Phase 3a):
//! nothing here writes to the project. It shares only `protocol.rs` with the runtime `/mcp` server.
//! See `docs/frogs-mcp-m3-plan.md`.

mod describe;
pub(crate) mod redact;
mod stdio;
mod tools;

#[cfg(test)]
mod authoring_tests;

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::sync::{RwLock, Semaphore, mpsc, oneshot};

use super::protocol::{self, Era, ParamsView, ProtoError, Request};
use crate::config::DEFAULT_MCP_LIST_TTL_MS;
use stdio::Input;
use tools::ToolContext;

pub(crate) const MAX_MCP_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 8;
const READER_QUEUE: usize = 16;
const WRITER_QUEUE: usize = 64;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const WRITER_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_NAME: &str = "frogs";

pub(crate) struct AuthoringOptions {
    pub root: PathBuf,
    pub allow_connections: bool,
}

/// Everything a request needs that does not change after startup.
pub(crate) struct Server {
    ctx: ToolContext,
    initialize: HashMap<&'static str, Box<RawValue>>,
    discover: Box<RawValue>,
    list_legacy: Box<RawValue>,
    list_modern: Box<RawValue>,
    /// The read-only tools take it in read mode (concurrent); `generate` and `errors_freeze` take it in write mode.
    lock: RwLock<()>,
}

fn raw(value: &Value) -> Box<RawValue> {
    serde_json::value::to_raw_value(value).expect("a serde_json::Value always serialises")
}

impl Server {
    #[cfg(test)]
    pub(crate) fn new(options: AuthoringOptions) -> Arc<Self> {
        Self::new_with_writes(options, false)
    }

    /// `allow_writes` adds the two tools that write to the project (`generate`, `errors_freeze`).
    pub(crate) fn new_with_writes(options: AuthoringOptions, allow_writes: bool) -> Arc<Self> {
        let info = json!({ "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") });
        let mut initialize = HashMap::new();
        for version in protocol::LEGACY_VERSIONS {
            initialize.insert(
                version,
                raw(&json!({ "protocolVersion": version, "capabilities": { "tools": { "listChanged": false } }, "serverInfo": info })),
            );
        }
        let discover = raw(&json!({
            "supportedVersions": protocol::supported_versions(),
            "capabilities": { "tools": {} },
            "_meta": { protocol::META_SERVER_INFO_KEY: info },
            "ttlMs": DEFAULT_MCP_LIST_TTL_MS,
            "cacheScope": "private",
            "resultType": "complete",
        }));
        let definitions = tools::definitions(options.allow_connections, allow_writes);
        let list_legacy = raw(&json!({ "tools": definitions }));
        let list_modern = raw(&json!({ "tools": definitions, "ttlMs": DEFAULT_MCP_LIST_TTL_MS, "cacheScope": "private", "resultType": "complete" }));
        Arc::new(Server {
            ctx: ToolContext {
                root: options.root,
                allow_connections: options.allow_connections,
                allow_writes,
            },
            initialize,
            discover,
            list_legacy,
            list_modern,
            lock: RwLock::new(()),
        })
    }

    /// Handles one input line and returns the response line, or `None` for a notification. Never panics on bad input;
    /// a panic inside a tool is caught by the caller and becomes `-32603`.
    pub(crate) async fn handle_line(self: &Arc<Self>, bytes: &[u8]) -> Option<String> {
        let request = match protocol::parse_envelope(bytes) {
            Ok(protocol::Parsed::Notification) => return None,
            Ok(protocol::Parsed::Request(request)) => request,
            Err(error) => return Some(error.into_line(None)),
        };
        let id = request.id.clone();
        // The work runs in its own task so a panic in a tool is a `JoinError` here, not a dead connection.
        let server = self.clone();
        match tokio::spawn(async move { server.dispatch(&request).await }).await {
            Ok(line) => Some(line),
            Err(join_error) => {
                tracing::error!("a request handler panicked: {join_error}");
                Some(ProtoError::internal_error().into_line(Some(&id)))
            }
        }
    }

    async fn dispatch(&self, request: &Request) -> String {
        let id: &RawValue = &request.id;
        let params = match protocol::parse_params(request.params.as_deref()) {
            Ok(params) => params,
            Err(error) => return error.into_line(Some(id)),
        };
        let era = match protocol::negotiate_for(protocol::Transport::Stdio, request, &params) {
            Ok(era) => era,
            Err(error) => return error.into_line(Some(id)),
        };
        let result = |value: &RawValue| protocol::result_line(id, value).unwrap_or_else(|| ProtoError::internal_error().into_line(Some(id)));
        match (era, request.method.as_str()) {
            (Era::Legacy, "initialize") => {
                let requested = params.protocol_version.as_ref().and_then(Value::as_str);
                let version = protocol::LEGACY_VERSIONS
                    .iter()
                    .copied()
                    .find(|v| Some(*v) == requested)
                    .unwrap_or(protocol::LEGACY_VERSIONS[0]);
                match self.initialize.get(version) {
                    Some(value) => result(value),
                    None => ProtoError::method_not_found().into_line(Some(id)),
                }
            }
            (Era::Legacy, "ping") => result(&raw(&json!({}))),
            (Era::Modern, "server/discover") => result(&self.discover),
            (_, "tools/list") => result(if era == Era::Modern { &self.list_modern } else { &self.list_legacy }),
            (_, "tools/call") => match self.call_tool(&params).await {
                Ok(value) => result(&raw(&with_result_type(era, value))),
                Err(error) => error.into_line(Some(id)),
            },
            _ => ProtoError::method_not_found().into_line(Some(id)),
        }
    }

    async fn call_tool(&self, params: &ParamsView) -> Result<Value, ProtoError> {
        let Some(name) = params.name.as_ref().and_then(Value::as_str) else {
            return Err(ProtoError::invalid_params());
        };
        // The writing tools exclude everything else while they run; the read-only tools share the lock.
        let (_read, _write);
        if tools::is_mutating(name) && self.ctx.allow_writes {
            _write = Some(self.lock.write().await);
            _read = None;
        } else {
            _read = Some(self.lock.read().await);
            _write = None;
        }
        let outcome = tools::call(&self.ctx, name, params.arguments.as_deref()).await?;
        Ok(match outcome {
            Ok(value) => text_result(&value, false),
            Err(failure) => text_result(&failure.to_value(), true),
        })
    }
}

fn with_result_type(era: Era, mut value: Value) -> Value {
    if era == Era::Modern {
        value["resultType"] = json!("complete");
    }
    value
}

fn text_result(value: &Value, is_error: bool) -> Value {
    let mut result = json!({ "content": [{ "type": "text", "text": value.to_string() }] });
    if is_error {
        result["isError"] = json!(true);
    }
    result
}

/// Runs the server on the real stdin/stdout until stdin closes, Ctrl+C, or SIGTERM.
pub(crate) async fn serve(options: AuthoringOptions, allow_writes: bool) -> io::Result<()> {
    let server = Server::new_with_writes(options, allow_writes);
    serve_streams(server, io::BufReader::new(io::stdin()), io::stdout(), shutdown_signal()).await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("registering a SIGTERM handler should succeed");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The transport loop, generic over its streams so it can be driven in process. `Ok(())` is a clean end (EOF or
/// `shutdown`); `Err` means stdout broke.
pub(crate) async fn serve_streams<R, W, S>(server: Arc<Server>, reader: R, writer: W, shutdown: S) -> io::Result<()>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
    S: Future<Output = ()>,
{
    let (line_tx, mut line_rx) = mpsc::channel::<Input>(READER_QUEUE);
    stdio::spawn_reader(reader, MAX_MCP_REQUEST_BYTES, line_tx);
    let (out_tx, out_rx) = mpsc::channel::<String>(WRITER_QUEUE);
    let (failed_tx, mut failed_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    stdio::spawn_writer(writer, out_rx, failed_tx, done_tx);

    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    tokio::pin!(shutdown);
    let mut broken = false;
    loop {
        let input = tokio::select! {
            _ = &mut shutdown => break,
            outcome = &mut failed_rx => {
                broken = outcome.is_ok();
                break;
            }
            input = line_rx.recv() => input,
        };
        let bytes = match input {
            None | Some(Input::Eof) => break,
            Some(Input::TooLong) => {
                let line = ProtoError::new(protocol::INVALID_REQUEST, "Request too large").into_line(None);
                let _ = out_tx.send(line).await;
                continue;
            }
            Some(Input::Line(bytes)) => bytes,
        };
        // The reader waits here when eight requests are already running.
        let permit = tokio::select! {
            permit = in_flight.clone().acquire_owned() => permit.expect("the in-flight semaphore is never closed"),
            _ = &mut shutdown => break,
            outcome = &mut failed_rx => {
                broken = outcome.is_ok();
                break;
            }
        };
        let server = server.clone();
        let out = out_tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(line) = server.handle_line(&bytes).await {
                let _ = out.send(line).await;
            }
        });
    }

    // Finish what is running, then let the writer flush; the stdin thread is abandoned on purpose (it cannot be cancelled).
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, in_flight.acquire_many(MAX_IN_FLIGHT as u32)).await;
    drop(out_tx);
    let _ = tokio::time::timeout(WRITER_FLUSH_TIMEOUT, done_rx).await;
    if broken {
        tracing::error!("stdout closed — shutting down");
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdout closed"));
    }
    Ok(())
}
