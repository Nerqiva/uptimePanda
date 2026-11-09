//! Minimal CDP (Chrome DevTools Protocol) client for Lightpanda.
//!
//! Design (see `docs/phase0-validation.md` for the verified wire behavior):
//!
//! - One WebSocket connection per [`Cdp`], to the CDP endpoint at the **root
//!   path** (`ws://127.0.0.1:<port>/`). Only loopback hosts are accepted;
//!   anything else is rejected at construction time with [`CdpError::UrlRejected`].
//! - A single read task dispatches messages:
//!   - a message carrying `id` plus `result`/`error` completes the matching
//!     pending request (JSON-RPC correlation via `HashMap<u64, oneshot::Sender<_>>`);
//!   - a message carrying `method` is an event, wrapped in [`CdpEvent`] and
//!     fanned out to every subscriber registered through [`CdpHandle::subscribe`].
//!     The fan-out is non-blocking and bounded; when a subscriber's channel is
//!     full the event is **dropped** and the `events_dropped` counter is
//!     incremented (never blocks the read loop, never overwrites).
//! - Session flattening: `Target.attachToTarget { flatten: true }` yields a
//!   `sessionId` that is then passed as `sessionId` on page-session commands;
//!   events echo that `sessionId`, and consumers filter on it.
//! - If the connection closes or the read task errors, the connection is
//!   considered **terminal**: the `closed` watch flips to `true` and *all*
//!   pending requests fail with [`CdpError::Disconnected`]. Reconnect logic is
//!   the browser process manager's job (SEG-06), not this client's.
//!
//! Secrets policy: params may carry cookie values, so raw params are never
//! logged and are never printed by any `Debug` impl in this module. Debug
//! representations print the method name (and session id, when known) only.
//!
//! Lightpanda quirks (Phase 0, 1.0.3):
//! - `Emulation.setUserAgentOverride` / `Network.setUserAgentOverride` are
//!   accepted but have **no effect** on the wire or in JS. [`CdpHandle::open_page`]
//!   still sends the override when asked for it (forward compatibility) and
//!   logs a single debug line, but callers must not rely on it.
//! - `Network.responseReceived` for documents carries `response.status` as an
//!   integer; `response.protocol` is `null`. `type == "Document"` is the
//!   reliable main-frame filter (SEG-10 captures `http_status` from it).
//! - Only one browser context exists at a time. `targetId` may equal the frame
//!   id; do not assume distinct id spaces.
//! - `Page.loadEventFired` works and is the primary navigation-completion
//!   signal; [`PageSession::wait_load`] additionally polls
//!   `document.readyState` as a fallback so a load that races event
//!   subscription still completes successfully.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{debug, warn};

/// Default per-command timeout for CDP RPCs.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for [`PageSession::evaluate`] (awaited promise included).
pub const DEFAULT_EVALUATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounded capacity of every event subscription channel.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Poll interval used by [`PageSession::wait_for_selector`] and
/// [`PageSession::wait_load`]'s readyState fallback.
const SELECTOR_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Errors surfaced by the CDP client. Cookie payloads are never embedded.
#[derive(Error)]
pub enum CdpError {
    /// The WebSocket transport failed (connect, send, or receive).
    #[error("cdp websocket error: {0}")]
    Ws(String),
    /// The peer replied with a JSON-RPC error object.
    #[error("cdp protocol error (code {code}): {message}")]
    Protocol {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable error message from the peer (no params echoed).
        message: String,
    },
    /// A command/response pair exceeded its deadline.
    #[error("cdp operation timed out")]
    Timeout,
    /// The connection closed; every pending and future request fails with this.
    #[error("cdp connection disconnected")]
    Disconnected,
    /// The connection URL is not a `ws://` URL on a loopback host.
    #[error(
        "rejected CDP url: only ws:// on loopback hosts (127.0.0.0/8, ::1, localhost) is allowed"
    )]
    UrlRejected(String),
    /// A response was structurally unusable (e.g. missing `targetId`).
    #[error("invalid cdp target: {0}")]
    InvalidTarget(String),
    /// JSON (de)serialization failed.
    #[error("cdp json error: {0}")]
    Json(#[from] serde_json::Error),
    /// I/O error.
    #[error("cdp io error: {0}")]
    Io(#[from] std::io::Error),
}

impl fmt::Debug for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redaction policy: this error type never carries request params, so a
        // full print is safe. Keep it exhaustive so a future variant cannot
        // smuggle params in unnoticed.
        match self {
            CdpError::Ws(m) => f.debug_tuple("Ws").field(m).finish(),
            CdpError::Protocol { code, message } => f
                .debug_struct("Protocol")
                .field("code", code)
                .field("message", message)
                .finish(),
            CdpError::Timeout => write!(f, "Timeout"),
            CdpError::Disconnected => write!(f, "Disconnected"),
            CdpError::UrlRejected(m) => f.debug_tuple("UrlRejected").field(m).finish(),
            CdpError::InvalidTarget(m) => f.debug_tuple("InvalidTarget").field(m).finish(),
            CdpError::Json(e) => f.debug_tuple("Json").field(e).finish(),
            CdpError::Io(e) => f.debug_tuple("Io").field(e).finish(),
        }
    }
}

/// A CDP event (a message with `method` and no `id`), redaction-safe.
#[derive(Clone)]
pub struct CdpEvent {
    /// Session the event belongs to, when flattened sessions are in use.
    pub session_id: Option<String>,
    /// Fully-qualified method name, e.g. `Page.loadEventFired`.
    pub method: String,
    /// Raw params object. **Never printed by Debug**; may contain sensitive data.
    pub params: Value,
}

impl CdpEvent {
    /// For `Network.responseReceived`: the numeric HTTP status, if present.
    pub fn response_status(&self) -> Option<i64> {
        if self.method != "Network.responseReceived" {
            return None;
        }
        self.params.pointer("/response/status")?.as_i64()
    }

    /// For `Network.responseReceived`: the resource type (`Document`, `XHR`, …).
    pub fn response_type(&self) -> Option<&str> {
        if self.method != "Network.responseReceived" {
            return None;
        }
        self.params.get("type")?.as_str()
    }
}

impl fmt::Debug for CdpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Params are elided entirely: they may carry headers, cookie data or
        // bodies we do not want in logs.
        f.debug_struct("CdpEvent")
            .field("session_id", &self.session_id)
            .field("method", &self.method)
            .field("params", &"[redacted]")
            .finish()
    }
}

/// A cookie as read back from the browser (`Network.getCookies`).
///
/// `Debug` prints everything **except** the value.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value. Redacted in `Debug`.
    pub value: String,
    /// Domain the cookie applies to.
    pub domain: String,
    /// Path scope.
    pub path: String,
    /// Expiry, seconds since the Unix epoch. `0.0` means a session cookie.
    pub expires: f64,
    /// `HttpOnly` attribute.
    pub http_only: bool,
    /// `Secure` attribute.
    pub secure: bool,
    /// `SameSite` value (`Strict` | `Lax` | `None`), when reported.
    pub same_site: Option<String>,
    /// Whether this is a session cookie (Chromium/Lightpanda report this).
    pub session: bool,
}

impl Default for Cookie {
    fn default() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
            domain: String::new(),
            path: String::new(),
            expires: 0.0,
            http_only: false,
            secure: false,
            same_site: None,
            session: false,
        }
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookie")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("expires", &self.expires)
            .field("http_only", &self.http_only)
            .field("secure", &self.secure)
            .field("same_site", &self.same_site)
            .field("session", &self.session)
            .finish()
    }
}

/// A cookie to be installed in the browser (`Network.setCookies`).
///
/// `Debug` prints everything **except** the value. `url` may be used instead
/// of `domain`/`path` (exactly as CDP defines it); empty `domain`/`path` are
/// omitted from the wire payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CookieInput {
    /// Cookie name.
    pub name: String,
    /// Cookie value. Redacted in `Debug`.
    pub value: String,
    /// Optional URL the cookie should be scoped to (CDP `url` attribute).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Domain; omitted when empty (use `url` or set an explicit domain).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Path; omitted when empty (defaults to `/` server-side).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Expiry, seconds since the Unix epoch. Omitted when `0.0` (session cookie).
    #[serde(skip_serializing_if = "f64_is_zero")]
    pub expires: f64,
    /// `HttpOnly` attribute.
    pub http_only: bool,
    /// `Secure` attribute.
    pub secure: bool,
    /// `SameSite` value (`Strict` | `Lax` | `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

impl Default for CookieInput {
    fn default() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
            url: None,
            domain: String::new(),
            path: String::new(),
            expires: 0.0,
            http_only: false,
            secure: false,
            same_site: None,
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn f64_is_zero(v: &f64) -> bool {
    *v == 0.0
}

impl fmt::Debug for CookieInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieInput")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("url", &self.url)
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("expires", &self.expires)
            .field("http_only", &self.http_only)
            .field("secure", &self.secure)
            .field("same_site", &self.same_site)
            .finish()
    }
}

struct CdpInner {
    /// JSON-RPC correlation map: request id → response sender.
    pending: StdMutex<HashMap<u64, oneshot::Sender<Result<Value, CdpError>>>>,
    /// Monotonic request id source (starts at 1).
    next_id: AtomicU64,
    /// Event fan-out subscribers; every entry is a bounded (256) channel.
    subscribers: StdMutex<Vec<mpsc::Sender<CdpEvent>>>,
    /// Count of events dropped because a subscriber's channel was full.
    events_dropped: AtomicU64,
    /// Write half of the socket; only ever held for the duration of one send.
    write: TokioMutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    /// Terminal flag; flips to `true` once, on connection close/error.
    closed: watch::Sender<bool>,
}

/// Cloneable handle to the shared CDP connection. Safe to clone for axum
/// state; every clone observes the same pending map, event fan-out and
/// `closed` signal.
#[derive(Clone)]
pub struct CdpHandle {
    inner: Arc<CdpInner>,
}

impl fmt::Debug for CdpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdpHandle")
            .field("closed", &*self.inner.closed.borrow())
            .finish_non_exhaustive()
    }
}

/// Owning end of a CDP connection. Returned by [`connect`].
///
/// Dropping `Cdp` does **not** actively close the socket; the read task keeps
/// running until the peer closes or the process exits. Obtain the cloneable
/// [`CdpHandle`] via [`Cdp::handle`] for long-lived use.
pub struct Cdp {
    handle: CdpHandle,
    /// Read-task handle. Detached on drop (never abort: pending callers rely
    /// on the terminal `Disconnected` fan-out from the read loop).
    #[allow(dead_code)]
    reader: JoinHandle<()>,
}

impl fmt::Debug for Cdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cdp")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl Cdp {
    /// The cloneable handle for this connection.
    pub fn handle(&self) -> CdpHandle {
        self.handle.clone()
    }

    /// Consume the owner and keep only the handle (read task keeps running).
    pub fn into_handle(self) -> CdpHandle {
        self.handle
    }
}

/// Reject anything that is not `ws://<loopback>[:port][/...]`.
///
/// Accepted loopback forms: `127.0.0.0/8`, `::1`, and the literal host
/// `localhost`. IP literals are evaluated after WHATWG normalization, so
/// e.g. `ws://0x7f.1/` is parsed as `127.0.0.1` and accepted, while any
/// routable address is rejected. The raw input is never echoed back in the
/// error (it could carry userinfo); only the reason is.
pub fn validate_ws_url(url: &str) -> Result<(), CdpError> {
    let parsed =
        url::Url::parse(url).map_err(|_| CdpError::UrlRejected("unparseable url".to_string()))?;
    if parsed.scheme() != "ws" {
        return Err(CdpError::UrlRejected("scheme must be ws".to_string()));
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        None => false,
    };
    if !loopback {
        return Err(CdpError::UrlRejected(
            "host is not loopback (127.0.0.0/8, ::1, localhost)".to_string(),
        ));
    }
    Ok(())
}

/// Connect to a CDP endpoint. Only loopback `ws://` URLs are accepted;
/// anything else fails with [`CdpError::UrlRejected`] before any I/O happens.
///
/// Spawns the read task. The connection is terminal: on close/error the
/// `closed` watch flips and all pending requests fail with
/// [`CdpError::Disconnected`]. Restart is SEG-06's responsibility.
pub async fn connect(url: &str) -> Result<Cdp, CdpError> {
    validate_ws_url(url)?;
    let (ws, _response) = connect_async(url)
        .await
        .map_err(|e| CdpError::Ws(e.to_string()))?;
    let (write, mut read) = ws.split();
    let (closed_tx, _closed_rx) = watch::channel(false);
    let inner = Arc::new(CdpInner {
        pending: StdMutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        subscribers: StdMutex::new(Vec::new()),
        events_dropped: AtomicU64::new(0),
        write: TokioMutex::new(write),
        closed: closed_tx,
    });

    let reader_inner = Arc::clone(&inner);
    let reader = tokio::spawn(async move {
        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => handle_message(&reader_inner, text.as_str()),
                Some(Ok(Message::Binary(_))) => debug!("cdp: ignoring binary frame"),
                Some(Ok(Message::Close(_))) => {
                    warn!("cdp connection closed by peer");
                    break;
                }
                Some(Ok(_)) => {} // ping/pong are handled by the transport
                Some(Err(e)) => {
                    warn!(error = %e, "cdp read error; connection is terminal");
                    break;
                }
                None => {
                    warn!("cdp connection ended; connection is terminal");
                    break;
                }
            }
        }
        terminate(&reader_inner);
    });

    Ok(Cdp {
        handle: CdpHandle { inner },
        reader,
    })
}

/// Flip the terminal flag and fail every pending request with
/// [`CdpError::Disconnected`]. Also drops all subscription senders so event
/// receivers observe a clean channel close.
fn terminate(inner: &CdpInner) {
    let _ = inner.closed.send(true);
    let drained: Vec<_> = {
        let mut pending = inner.pending.lock().expect("pending mutex poisoned");
        std::mem::take(&mut *pending).into_values().collect()
    };
    for tx in drained {
        let _ = tx.send(Err(CdpError::Disconnected));
    }
    inner
        .subscribers
        .lock()
        .expect("subscribers mutex poisoned")
        .clear();
}

/// Dispatch one text frame from the peer.
fn handle_message(inner: &CdpInner, text: &str) {
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            debug!("cdp: dropping unparseable frame");
            return;
        }
    };
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            debug!("cdp: dropping non-object frame");
            return;
        }
    };

    // Response to a pending request? (Responses never carry `method`.)
    if let Some(id) = obj.get("id").and_then(Value::as_u64)
        && (obj.contains_key("result") || obj.contains_key("error"))
    {
        let tx = inner
            .pending
            .lock()
            .expect("pending mutex poisoned")
            .remove(&id);
        if let Some(tx) = tx {
            let res = if let Some(err) = obj.get("error") {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(-32000);
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown cdp error")
                    .to_owned();
                Err(CdpError::Protocol { code, message })
            } else {
                Ok(obj.get("result").cloned().unwrap_or(Value::Null))
            };
            let _ = tx.send(res);
        }
        return;
    }

    // Event? Fan out non-blocking; drop-on-full and count.
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        let event = CdpEvent {
            session_id: obj
                .get("sessionId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            method: method.to_owned(),
            params: obj.get("params").cloned().unwrap_or(Value::Null),
        };
        let mut subs = inner
            .subscribers
            .lock()
            .expect("subscribers mutex poisoned");
        subs.retain(|tx| match tx.try_send(event.clone()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                inner.events_dropped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    method = event.method,
                    "cdp: subscriber lagged; event dropped"
                );
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        });
    }
}

impl CdpHandle {
    /// Whether the connection has terminated (closed or read error).
    pub fn is_closed(&self) -> bool {
        *self.inner.closed.borrow()
    }

    /// Subscribe to the terminal signal (`true` once the connection dies).
    /// SEG-06 uses this to trigger browser restarts.
    pub fn closed_watch(&self) -> watch::Receiver<bool> {
        self.inner.closed.subscribe()
    }

    /// Number of events dropped because a subscriber's channel was full.
    pub fn events_dropped(&self) -> u64 {
        self.inner.events_dropped.load(Ordering::Relaxed)
    }

    /// Subscribe to the CDP event stream. Each subscriber gets its own
    /// bounded (256) channel; a slow subscriber loses events instead of
    /// applying backpressure to the read loop. Receivers yield `None` once
    /// the connection terminates.
    ///
    /// Filter by `event.session_id` to scope events to one attached target.
    pub fn subscribe(&self) -> mpsc::Receiver<CdpEvent> {
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        self.inner
            .subscribers
            .lock()
            .expect("subscribers mutex poisoned")
            .push(tx);
        rx
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value, CdpError> {
        self.call_with_timeout(method, params, session_id, DEFAULT_COMMAND_TIMEOUT)
            .await
    }

    async fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        if *self.inner.closed.borrow() {
            return Err(CdpError::Disconnected);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().expect("pending mutex poisoned");
            pending.insert(id, tx);
        }

        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(sid) = session_id {
            message["sessionId"] = json!(sid);
        }

        // Never log `message`: params may contain cookie values.
        debug!(method, id, "cdp: send");
        let text = serde_json::to_string(&message)?;
        let send_result = {
            let mut write = self.inner.write.lock().await;
            write.send(Message::Text(text.into())).await
        };
        if let Err(e) = send_result {
            self.inner
                .pending
                .lock()
                .expect("pending mutex poisoned")
                .remove(&id);
            return Err(CdpError::Ws(e.to_string()));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_canceled)) => Err(CdpError::Disconnected),
            Err(_elapsed) => {
                self.inner
                    .pending
                    .lock()
                    .expect("pending mutex poisoned")
                    .remove(&id);
                Err(CdpError::Timeout)
            }
        }
    }

    /// `Target.createTarget`; resolves to the new `targetId`.
    pub async fn create_target(&self, url: &str) -> Result<String, CdpError> {
        let res = self
            .call("Target.createTarget", json!({ "url": url }), None)
            .await?;
        res.get("targetId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| CdpError::InvalidTarget("createTarget: missing targetId".to_string()))
    }

    /// `Target.attachToTarget`; with `flatten == true` returns the flattened
    /// `sessionId` to scope page-session commands and to filter events.
    pub async fn attach(&self, target_id: &str, flatten: bool) -> Result<String, CdpError> {
        let res = self
            .call(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": flatten }),
                None,
            )
            .await?;
        res.get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| CdpError::InvalidTarget("attachToTarget: missing sessionId".to_string()))
    }

    /// `Target.closeTarget`.
    pub async fn close_target(&self, target_id: &str) -> Result<(), CdpError> {
        let res = self
            .call("Target.closeTarget", json!({ "targetId": target_id }), None)
            .await?;
        if let Some(false) = res.get("success").and_then(Value::as_bool) {
            return Err(CdpError::InvalidTarget(
                "closeTarget: peer reported failure".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a page target at `url`, attach with session flattening, enable
    /// `Page` and `Network`, and return the session. On any failure the
    /// target is closed best-effort before the error is returned.
    ///
    /// If `ua` is provided, `Network.setUserAgentOverride` is sent — **but
    /// note Phase 0 verified this is a no-op on Lightpanda 1.0.3** (the
    /// command returns `{}` and the UA on the wire and in JS does not
    /// change). It is sent anyway for forward compatibility and is logged
    /// once at debug level. Callers must not rely on the override.
    pub async fn open_page(&self, url: &str, ua: Option<&str>) -> Result<PageSession, CdpError> {
        let target_id = self.create_target(url).await?;
        let session_id = match self.attach(&target_id, true).await {
            Ok(sid) => sid,
            Err(e) => {
                let _ = self.close_target(&target_id).await;
                return Err(e);
            }
        };
        let session = PageSession {
            handle: self.clone(),
            target_id,
            session_id,
        };
        if let Err(e) = session.call("Page.enable", json!({})).await {
            let _ = self.close_target(&session.target_id).await;
            return Err(e);
        }
        if let Err(e) = session.call("Network.enable", json!({})).await {
            let _ = self.close_target(&session.target_id).await;
            return Err(e);
        }
        if let Some(ua) = ua
            && let Err(e) = session.set_user_agent_override(ua).await
        {
            // The override is a no-op on 1.0.3 anyway; UA must never fail a visit.
            debug!(error = %e, "ua override command failed; continuing without it");
        }
        Ok(session)
    }
}

/// A page target with an attached, flattened session. Cheap to hold;
/// not clonable by design (one session, one owner).
pub struct PageSession {
    handle: CdpHandle,
    target_id: String,
    session_id: String,
}

impl fmt::Debug for PageSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageSession")
            .field("target_id", &self.target_id)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl PageSession {
    /// CDP target id of this page.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Flattened session id; events for this page carry it as `session_id`.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Subscribe to the raw event stream (shared with every other subscriber,
    /// each with its own bounded channel). SEG-10 consumes
    /// `Network.responseReceived` this way; see [`CdpEvent::response_status`]
    /// and [`CdpEvent::response_type`].
    pub fn subscribe(&self) -> mpsc::Receiver<CdpEvent> {
        self.handle.subscribe()
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.call_with_timeout(method, params, DEFAULT_COMMAND_TIMEOUT)
            .await
    }

    async fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        self.handle
            .call_with_timeout(method, params, Some(&self.session_id), timeout)
            .await
    }

    /// `Page.navigate`; resolves to the raw result (`frameId`, `loaderId?`).
    pub async fn navigate(&self, url: &str) -> Result<Value, CdpError> {
        self.call("Page.navigate", json!({ "url": url })).await
    }

    /// Wait for `Page.loadEventFired` for **this session**, with a
    /// `document.readyState == "complete"` polling fallback (150 ms interval)
    /// so a load that raced event subscription still counts as loaded.
    ///
    /// Fails with [`CdpError::Timeout`] after `timeout`;
    /// [`CdpError::Disconnected`] if the connection dies meanwhile.
    pub async fn wait_load(&self, timeout: Duration) -> Result<(), CdpError> {
        let mut rx = self.handle.subscribe();
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(CdpError::Timeout);
            }
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(ev) => {
                            if ev.session_id.as_deref() == Some(self.session_id.as_str())
                                && ev.method == "Page.loadEventFired"
                            {
                                return Ok(());
                            }
                        }
                        None => return Err(CdpError::Disconnected),
                    }
                }
                _ = tokio::time::sleep(SELECTOR_POLL_INTERVAL) => {
                    match self
                        .evaluate_with_timeout("document.readyState", Duration::from_secs(2))
                        .await
                    {
                        Ok(v) if v.as_str() == Some("complete") => return Ok(()),
                        Ok(_) => {}
                        // Mid-navigation evaluation can fail; keep polling.
                        Err(CdpError::Protocol { .. }) | Err(CdpError::Timeout) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// `Runtime.evaluate` with `returnByValue: true` and `awaitPromise: true`.
    /// Resolves to the JS value (`null` for `undefined`).
    /// A JS exception throws [`CdpError::Protocol`] with the exception text.
    pub async fn evaluate(&self, expression: &str) -> Result<Value, CdpError> {
        self.evaluate_with_timeout(expression, DEFAULT_EVALUATE_TIMEOUT)
            .await
    }

    /// [`PageSession::evaluate`] with a configurable client-side timeout; the
    /// same value (as milliseconds) is sent as the CDP protocol `timeout`.
    pub async fn evaluate_with_timeout(
        &self,
        expression: &str,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        let res = self
            .call_with_timeout(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                    "timeout": timeout.as_millis() as u64,
                }),
                timeout,
            )
            .await?;
        if let Some(details) = res.get("exceptionDetails") {
            let message = details
                .pointer("/exception/description")
                .and_then(Value::as_str)
                .or_else(|| details.get("text").and_then(Value::as_str))
                .unwrap_or("javascript exception")
                .to_owned();
            return Err(CdpError::Protocol {
                code: -32000,
                message,
            });
        }
        Ok(res.pointer("/result/value").cloned().unwrap_or(Value::Null))
    }

    /// Scroll the window by `(dx, dy)` per step, `count` times, sleeping
    /// `delay_ms` between steps. Non-finite deltas are rejected.
    pub async fn scroll_by(
        &self,
        dy: f64,
        dx: f64,
        count: u32,
        delay_ms: u64,
    ) -> Result<(), CdpError> {
        if !dy.is_finite() || !dx.is_finite() {
            return Err(CdpError::Protocol {
                code: -32602,
                message: "scroll delta must be finite".to_string(),
            });
        }
        for step in 0..count {
            self.evaluate(&format!("window.scrollBy({dx}, {dy})"))
                .await?;
            if step + 1 < count {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
        Ok(())
    }

    /// Poll `!!document.querySelector(selector)` every 150 ms until it is
    /// truthy or `timeout` elapses. Returns `Ok(true)` when found,
    /// `Ok(false)` on timeout.
    pub async fn wait_for_selector(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<bool, CdpError> {
        let lit = serde_json::to_string(selector)?; // safe JS string literal
        let expression = format!("!!document.querySelector({lit})");
        let deadline = Instant::now() + timeout;
        loop {
            match self.evaluate(&expression).await {
                Ok(v) => {
                    if v.as_bool() == Some(true) {
                        return Ok(true);
                    }
                }
                // Mid-navigation evaluation can fail; keep polling.
                Err(CdpError::Protocol { .. }) => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(SELECTOR_POLL_INTERVAL).await;
        }
    }

    /// `Input.dispatchMouseEvent` left button, viewport coordinates.
    pub async fn dispatch_left_click(&self, x: f64, y: f64) -> Result<(), CdpError> {
        if !x.is_finite() || !y.is_finite() {
            return Err(CdpError::Protocol {
                code: -32602,
                message: "click coordinates must be finite".to_string(),
            });
        }
        for kind in ["mousePressed", "mouseReleased"] {
            self.call(
                "Input.dispatchMouseEvent",
                json!({
                    "type": kind,
                    "x": x,
                    "y": y,
                    "button": "left",
                    "clickCount": 1,
                    "pointerType": "mouse",
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// Click the element matching `selector` at the center of its bounding
    /// box (viewport coordinates, as `Input.dispatchMouseEvent` expects).
    /// Returns `Ok(false)` when no element matches.
    pub async fn click_element(&self, selector: &str) -> Result<bool, CdpError> {
        let lit = serde_json::to_string(selector)?; // safe JS string literal
        let expression = format!(
            "(function(){{const el=document.querySelector({lit});\
             if(!el)return null;const r=el.getBoundingClientRect();\
             return {{x:r.x+r.width/2,y:r.y+r.height/2}};}})()"
        );
        match self.evaluate(&expression).await? {
            Value::Null => Ok(false),
            value => {
                let x = value.get("x").and_then(Value::as_f64);
                let y = value.get("y").and_then(Value::as_f64);
                match (x, y) {
                    (Some(x), Some(y)) => {
                        self.dispatch_left_click(x, y).await?;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        }
    }

    /// Send `Network.setUserAgentOverride` for this page's session.
    ///
    /// **Verified no-op on Lightpanda 1.0.3**: the command returns `{}`
    /// but the UA on the wire and in JS does not change (see
    /// `docs/phase0-validation.md` §5). The command is sent anyway for
    /// forward compatibility and logs a single debug line. The wire result
    /// is returned verbatim; callers that consider the override best-effort
    /// (open-time wiring, `apply_identity`) log and swallow errors.
    ///
    /// Callers must not rely on the override (SEG-07 emits the same label
    /// everywhere a preset is shown).
    pub async fn set_user_agent_override(&self, ua: &str) -> Result<(), CdpError> {
        // NOTE: verified no-op on Lightpanda 1.0.3; sent for forward compat.
        debug!("ua override sent (compat; engine may ignore)");
        self.call("Network.setUserAgentOverride", json!({ "userAgent": ua }))
            .await?;
        Ok(())
    }

    /// `Network.getCookies` with **no** `urls` filter: returns every cookie
    /// in the browser's jar for this session's context.
    pub async fn get_cookies(&self) -> Result<Vec<Cookie>, CdpError> {
        let res = self.call("Network.getCookies", json!({})).await?;
        let cookies = res.get("cookies").cloned().unwrap_or_else(|| json!([]));
        Ok(serde_json::from_value(cookies)?)
    }

    /// `Network.setCookies`. Values pass through verbatim; nothing about
    /// them is logged by this client.
    pub async fn set_cookies(&self, cookies: &[CookieInput]) -> Result<(), CdpError> {
        let list = serde_json::to_value(cookies)?;
        self.call("Network.setCookies", json!({ "cookies": list }))
            .await?;
        Ok(())
    }

    /// `Network.deleteCookies` for one name in one domain.
    pub async fn delete_cookies(&self, name: &str, domain: &str) -> Result<(), CdpError> {
        self.call(
            "Network.deleteCookies",
            json!({ "name": name, "domain": domain }),
        )
        .await?;
        Ok(())
    }

    /// Wipe the browser-context-global cookie jar.
    ///
    /// Lightpanda 1.0.3 has exactly one (context-global) cookie jar shared
    /// across all targets; SEG-10 clears it before restoring a profile's jar
    /// and after the visit's jar has been captured and persisted, so no
    /// cookie can leak from one profile's visit into the next visit. On any
    /// error the fallback deletes cookie-by-cookie; callers treat this as
    /// best-effort hygiene (warn, never fail the visit).
    pub async fn clear_cookies(&self) -> Result<(), CdpError> {
        match self.call("Network.clearBrowserCookies", json!({})).await {
            Ok(_) => Ok(()),
            Err(primary) => {
                // Fallback: delete every cookie individually.
                let cookies = self.get_cookies().await?;
                let mut last_err = primary;
                let mut failures = 0usize;
                for cookie in &cookies {
                    if let Err(e) = self.delete_cookies(&cookie.name, &cookie.domain).await {
                        failures += 1;
                        last_err = e;
                    }
                }
                if cookies.is_empty() || failures == cookies.len() {
                    // Nothing was cleared; surface the error.
                    return Err(last_err);
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! In-memory mock CDP server. No live Lightpanda here — that is the
    //! `#[ignore]`d `cdp_live` test below.
    use super::*;
    use futures_util::future::BoxFuture;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Async responder: takes the parsed request, returns zero or more full
    /// messages to write back to the client.
    type Responder = Arc<dyn Fn(Value) -> BoxFuture<'static, Vec<Value>> + Send + Sync>;

    struct MockCdp {
        addr: SocketAddr,
        requests: Arc<StdMutex<Vec<Value>>>,
        #[allow(dead_code)]
        join: JoinHandle<()>,
    }

    impl MockCdp {
        fn url(&self) -> String {
            format!("ws://127.0.0.1:{}/", self.addr.port())
        }
        fn requests(&self) -> Vec<Value> {
            self.requests.lock().expect("requests poisoned").clone()
        }
    }

    /// Synchronous responder helper for the common case (no delays).
    fn respond_with(f: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static) -> Responder {
        Arc::new(move |req: Value| {
            let outs = f(&req);
            Box::pin(async move { outs })
        })
    }

    /// Canned result for the target-flow methods every page test needs.
    /// Returns `None` for methods this helper does not know about.
    fn flow_result(method: &str) -> Option<Value> {
        match method {
            "Target.createTarget" => Some(json!({ "targetId": "TGT-1" })),
            "Target.attachToTarget" => Some(json!({ "sessionId": "SID-1" })),
            "Page.enable" | "Network.enable" | "Page.navigate" => Some(json!({})),
            _ => None,
        }
    }

    /// Canned responder for the happy-path page flow.
    fn flow_responder() -> Responder {
        respond_with(|req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            let result = flow_result(method).unwrap_or_else(|| match method {
                "Runtime.evaluate" => {
                    json!({ "result": { "type": "string", "value": "Example Domain" } })
                }
                "Target.closeTarget" => json!({ "success": true }),
                _ => json!({}),
            });
            vec![json!({ "id": id, "result": result })]
        })
    }

    async fn start_mock(responder: Responder) -> MockCdp {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        let join = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(_) => return,
            };
            while let Some(Ok(msg)) = ws.next().await {
                let text = match msg {
                    Message::Text(t) => t.as_str().to_owned(),
                    _ => continue,
                };
                let parsed: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let close_after =
                    parsed.get("method").and_then(Value::as_str) == Some("__test_close");
                reqs.lock().expect("requests poisoned").push(parsed.clone());
                let outs = responder(parsed).await;
                for out in outs {
                    let _ = ws.send(Message::Text(out.to_string().into())).await;
                }
                if close_after {
                    let _ = ws.send(Message::Close(None)).await;
                    break;
                }
            }
        });
        MockCdp {
            addr,
            requests,
            join,
        }
    }

    fn params_of(req: &Value) -> &Value {
        req.get("params").expect("request has params")
    }

    #[test]
    fn validate_ws_url_matrix() {
        assert!(validate_ws_url("ws://127.0.0.1:9222/").is_ok());
        assert!(validate_ws_url("ws://127.1.2.3/").is_ok());
        assert!(validate_ws_url("ws://localhost:9222/").is_ok());
        assert!(validate_ws_url("ws://[::1]:9222/").is_ok());
        assert!(validate_ws_url("ws://0x7f.1/").is_ok()); // WHATWG-normalized to 127.0.0.1
        assert!(validate_ws_url(":: not-a-url").is_err());
        assert!(validate_ws_url("ws://example.com/").is_err());
        assert!(validate_ws_url("ws://192.168.1.10:9222/").is_err());
        assert!(validate_ws_url("ws://10.0.0.1/").is_err());
        assert!(validate_ws_url("ws://[::2]/").is_err());
        assert!(validate_ws_url("http://127.0.0.1:9222/").is_err());
        assert!(validate_ws_url("wss://127.0.0.1:9222/").is_err());
        assert!(validate_ws_url("file:///etc/passwd").is_err());
        let err = validate_ws_url("ws://203.0.113.9/").unwrap_err();
        assert!(matches!(err, CdpError::UrlRejected(_)));
    }

    #[tokio::test]
    async fn connect_rejects_non_loopback_before_io() {
        let err = connect("ws://example.com:9222/").await.unwrap_err();
        assert!(matches!(err, CdpError::UrlRejected(_)));
        let err = connect("http://127.0.0.1:9222/").await.unwrap_err();
        assert!(matches!(err, CdpError::UrlRejected(_)));
    }

    #[tokio::test]
    async fn request_responses_correlate_out_of_order() {
        let responder: Responder = Arc::new(|req: Value| {
            Box::pin(async move {
                let id = req["id"].clone();
                match id.as_u64().unwrap_or(0) {
                    1 => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        vec![json!({ "id": id, "result": { "first": true } })]
                    }
                    _ => vec![json!({ "id": id, "result": { "second": true } })],
                }
            })
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let handle = cdp.handle();
        let h2 = handle.clone();
        let a = tokio::spawn(async move { handle.call("Slow.methodOne", json!({}), None).await });
        let b = tokio::spawn(async move { h2.call("Fast.methodTwo", json!({}), None).await });
        let ra = a.await.unwrap().expect("first succeeds");
        let rb = b.await.unwrap().expect("second succeeds");
        assert_eq!(ra["first"], json!(true));
        assert_eq!(rb["second"], json!(true));
    }

    #[tokio::test]
    async fn request_times_out_when_peer_never_responds() {
        let responder: Responder = Arc::new(|_req: Value| Box::pin(async { vec![] }));
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let err = cdp
            .handle()
            .call_with_timeout(
                "Slow.neverResponds",
                json!({}),
                None,
                Duration::from_millis(150),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Timeout));
    }

    #[tokio::test]
    async fn disconnect_fails_pending_request_fast() {
        // The mock answers every method with nothing and closes the socket
        // when it sees the sentinel method "__test_close".
        let responder: Responder = Arc::new(|_req: Value| Box::pin(async { vec![] }));
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let handle = cdp.handle();
        let mut watched = handle.closed_watch();
        let pending = tokio::spawn({
            let handle = handle.clone();
            async move {
                handle
                    .call_with_timeout("__test_close", json!({}), None, Duration::from_secs(10))
                    .await
            }
        });
        let err = pending.await.unwrap().unwrap_err();
        assert!(matches!(err, CdpError::Disconnected));
        // The terminal flag flipped for watchers.
        watched.changed().await.expect("watch flips");
        assert!(*watched.borrow());
        assert!(handle.is_closed());
    }

    #[tokio::test]
    async fn events_are_fanned_out_to_subscribers() {
        let responder = respond_with(|req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            match method {
                "Network.enable" => vec![
                    json!({ "id": id, "result": {} }),
                    json!({
                        "method": "Network.responseReceived",
                        "sessionId": "SID-1",
                        "params": {
                            "type": "Document",
                            "response": { "status": 200, "url": "https://example.com/" }
                        }
                    }),
                ],
                _ => vec![json!({ "id": id, "result": flow_result(method).unwrap_or(json!({})) })],
            }
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let handle = cdp.handle();
        let mut rx = handle.subscribe();
        handle
            .call(
                "Target.attachToTarget",
                json!({ "targetId": "TGT-1", "flatten": true }),
                None,
            )
            .await
            .expect("attach");
        handle
            .call("Network.enable", json!({}), Some("SID-1"))
            .await
            .expect("enable");
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event arrives")
            .expect("channel open");
        assert_eq!(event.method, "Network.responseReceived");
        assert_eq!(event.session_id.as_deref(), Some("SID-1"));
        assert_eq!(event.response_status(), Some(200));
        assert_eq!(event.response_type(), Some("Document"));
        // Debug must not leak params.
        let dbg = format!("{event:?}");
        assert!(
            !dbg.contains("example.com"),
            "params leaked in Debug: {dbg}"
        );
    }

    #[tokio::test]
    async fn open_page_flow_create_attach_evaluate_close() {
        let mock = start_mock(flow_responder()).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let page = cdp
            .handle()
            .open_page("https://example.com/", None)
            .await
            .expect("open page");
        assert_eq!(page.target_id(), "TGT-1");
        assert_eq!(page.session_id(), "SID-1");
        let title = page.evaluate("document.title").await.expect("evaluate");
        assert_eq!(title, json!("Example Domain"));
        cdp.handle().close_target("TGT-1").await.expect("close");
        let reqs = mock.requests();
        let methods: Vec<&str> = reqs.iter().filter_map(|r| r["method"].as_str()).collect();
        let expected = [
            "Target.createTarget",
            "Target.attachToTarget",
            "Page.enable",
            "Network.enable",
            "Runtime.evaluate",
            "Target.closeTarget",
        ];
        assert_eq!(methods, expected);
        // Session-scoped commands carry the flatten session id.
        for req in &reqs {
            match req["method"].as_str().unwrap_or("") {
                "Runtime.evaluate" | "Page.enable" | "Network.enable" => {
                    assert_eq!(req["sessionId"], json!("SID-1"));
                }
                _ => assert!(req.get("sessionId").is_none()),
            }
        }
    }

    #[tokio::test]
    async fn evaluate_surfaces_js_exception_as_protocol_error() {
        let responder = respond_with(|req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            if method == "Runtime.evaluate" {
                return vec![json!({
                    "id": id,
                    "result": {
                        "result": { "type": "object", "subtype": "error" },
                        "exceptionDetails": {
                            "text": "Uncaught",
                            "exception": { "description": "ReferenceError: boom is not defined" }
                        }
                    }
                })];
            }
            vec![json!({ "id": id, "result": flow_result(method).unwrap_or(json!({})) })]
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let page = cdp
            .handle()
            .open_page("about:blank", None)
            .await
            .expect("open");
        let err = page.evaluate("boom").await.unwrap_err();
        match err {
            CdpError::Protocol { code, message } => {
                assert_eq!(code, -32000);
                assert!(message.contains("boom"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_load_completes_via_readystate_fallback() {
        let responder = respond_with(|req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            let result = match method {
                "Runtime.evaluate" => {
                    json!({ "result": { "type": "string", "value": "complete" } })
                }
                _ => flow_result(method).unwrap_or(json!({})),
            };
            vec![json!({ "id": id, "result": result })]
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let page = cdp
            .handle()
            .open_page("about:blank", None)
            .await
            .expect("open");
        page.wait_load(Duration::from_secs(2))
            .await
            .expect("loaded");
    }

    #[tokio::test]
    async fn wait_load_times_out_when_never_complete() {
        let responder = respond_with(|req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            let result = match method {
                "Runtime.evaluate" => {
                    json!({ "result": { "type": "string", "value": "loading" } })
                }
                _ => flow_result(method).unwrap_or(json!({})),
            };
            vec![json!({ "id": id, "result": result })]
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let page = cdp
            .handle()
            .open_page("about:blank", None)
            .await
            .expect("open");
        let err = page
            .wait_load(Duration::from_millis(400))
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Timeout));
    }

    #[tokio::test]
    async fn cookie_round_trip_and_debug_redaction() {
        let secret = "s3cr3t-cookie-value";
        let responder = respond_with(move |req: &Value| {
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            match method {
                "Network.getCookies" => vec![json!({
                    "id": id,
                    "result": { "cookies": [{
                        "name": "session",
                        "value": secret,
                        "domain": "example.com",
                        "path": "/",
                        "expires": 1893456000.0,
                        "httpOnly": true,
                        "secure": true,
                        "sameSite": "Lax",
                        "session": false
                    }] }
                })],
                "Network.setCookies" | "Network.deleteCookies" => {
                    vec![json!({ "id": id, "result": {} })]
                }
                _ => vec![json!({ "id": id, "result": flow_result(method).unwrap_or(json!({})) })],
            }
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let handle = cdp.handle();
        let page = handle
            .open_page("https://example.com/", None)
            .await
            .expect("open");

        let cookies = page.get_cookies().await.expect("get cookies");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, secret); // passthrough; never inspected/logged
        assert_eq!(cookies[0].domain, "example.com");
        assert_eq!(cookies[0].same_site.as_deref(), Some("Lax"));

        // Debug impls must not contain the value.
        let cookie_dbg = format!("{:?}", cookies[0]);
        assert!(!cookie_dbg.contains(secret), "cookie Debug leaks value");
        let input_dbg = format!(
            "{:?}",
            CookieInput {
                name: "session".into(),
                value: secret.into(),
                domain: "example.com".into(),
                path: "/".into(),
                ..CookieInput::default()
            }
        );
        assert!(
            !input_dbg.contains(secret),
            "cookie input Debug leaks value"
        );
        let event_dbg = format!(
            "{:?}",
            CdpEvent {
                session_id: Some("SID-1".into()),
                method: "Network.responseReceived".into(),
                params: json!({ "cookie": secret }),
            }
        );
        assert!(!event_dbg.contains(secret), "event Debug leaks params");

        let input = CookieInput {
            name: "session".into(),
            value: secret.into(),
            domain: "example.com".into(),
            path: "/".into(),
            http_only: true,
            secure: true,
            same_site: Some("Lax".into()),
            ..CookieInput::default()
        };
        page.set_cookies(std::slice::from_ref(&input))
            .await
            .expect("set cookies");
        page.delete_cookies("session", "example.com")
            .await
            .expect("delete cookies");

        let reqs = mock.requests();
        let set_req = reqs
            .iter()
            .find(|r| r["method"] == "Network.setCookies")
            .expect("setCookies recorded");
        let wire_cookie = &params_of(set_req)["cookies"][0];
        assert_eq!(wire_cookie["value"], json!(secret)); // exact passthrough
        assert_eq!(wire_cookie["name"], json!("session"));
        assert_eq!(wire_cookie["httpOnly"], json!(true));
        let delete_req = reqs
            .iter()
            .find(|r| r["method"] == "Network.deleteCookies")
            .expect("deleteCookies recorded");
        assert_eq!(params_of(delete_req)["name"], json!("session"));
        assert_eq!(params_of(delete_req)["domain"], json!("example.com"));
    }

    #[tokio::test]
    async fn wait_for_selector_polls_until_found() {
        let hits = Arc::new(AtomicU64::new(0));
        let hits_clone = Arc::clone(&hits);
        let responder: Responder = Arc::new(move |req: Value| {
            let hits = Arc::clone(&hits_clone);
            Box::pin(async move {
                let id = req["id"].clone();
                let method = req["method"].as_str().unwrap_or("");
                let result = if method == "Runtime.evaluate" {
                    // Not found twice, then found.
                    let n = hits.fetch_add(1, Ordering::SeqCst);
                    json!({ "result": { "type": "boolean", "value": n >= 2 } })
                } else {
                    flow_result(method).unwrap_or(json!({}))
                };
                vec![json!({ "id": id, "result": result })]
            })
        });
        let mock = start_mock(responder).await;
        let cdp = connect(&mock.url()).await.expect("connect");
        let page = cdp
            .handle()
            .open_page("about:blank", None)
            .await
            .expect("open");
        let found = page
            .wait_for_selector("#app", Duration::from_secs(5))
            .await
            .expect("wait");
        assert!(found);
        // The mock must have received a properly-quoted querySelector literal.
        let reqs = mock.requests();
        let eval_req = reqs.iter().find(|r| {
            r["method"] == "Runtime.evaluate"
                && r["params"]["expression"]
                    .as_str()
                    .is_some_and(|e| e.contains("querySelector(\"#app\")"))
        });
        assert!(eval_req.is_some(), "selector was not JS-quoted: {reqs:?}");
    }

    #[tokio::test]
    #[ignore = "spawns a real lightpanda and navigates to example.com; requires /usr/local/bin/lightpanda + network. Run: cargo test --locked -- --ignored cdp_live"]
    async fn cdp_live() {
        if std::process::Command::new("lightpanda")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("cdp_live: lightpanda not on PATH; skipping");
            return;
        }
        // Pick a free ephemeral port by binding and releasing.
        let port = {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("ephemeral port");
            listener.local_addr().expect("addr").port()
        };
        let child = std::process::Command::new("lightpanda")
            .args([
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--log-level",
                "warn",
            ])
            .env("LIGHTPANDA_DISABLE_TELEMETRY", "true")
            .spawn()
            .expect("spawn lightpanda");
        struct KillGuard(std::process::Child);
        impl Drop for KillGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = KillGuard(child);

        // Wait for the WS endpoint to answer (about 75 ms steady-state; allow 5 s).
        let mut ready = false;
        for _ in 0..100 {
            if std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready, "lightpanda did not start listening on {port}");

        let url = format!("ws://127.0.0.1:{port}/");
        let cdp = connect(&url).await.expect("connect to live lightpanda");
        let page = cdp
            .handle()
            .open_page("https://example.com/", None)
            .await
            .expect("open page");
        page.wait_load(Duration::from_secs(15)).await.expect("load");
        let title = page.evaluate("document.title").await.expect("evaluate");
        println!("cdp_live: document.title = {title}");
        cdp.handle()
            .close_target(page.target_id())
            .await
            .expect("close target");
    }
}
