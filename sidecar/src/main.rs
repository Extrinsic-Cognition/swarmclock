//! EC iroh sidecar — native iroh I/O process for the Python daemon.
//!
//! Why this exists:
//!   - Python `iroh-ffi` bindings are frozen at 0.35.0 (PyPI ceiling).
//!   - Native iroh is at 0.97+, with substantial gossip wire-format
//!     refactors that are not back-compatible with 0.35.
//!   - To talk to native iroh peers (e.g. Perplexity's Rust bridge),
//!     we need a recent iroh, which is only available natively.
//!
//! Architecture:
//!   The Python daemon spawns this binary as a subprocess. All iroh I/O
//!   happens here in Rust against iroh ~0.97. Communication with Python
//!   is line-delimited JSON over stdin (commands → sidecar) and stdout
//!   (events → daemon). Stderr is human-readable trace logs.
//!
//!   The Python daemon retains: membrane (ingress_inspector), policy,
//!   ECMemberCredential store, receipt ledger, Suite F injection scan,
//!   ACK/COMMAND dispatch logic.
//!
//! Identity:
//!   Loads the 32-byte ed25519 secret from ~/.ec-daemon/iroh/node_secret.hex
//!   so the iroh NodeID matches what the Python iroh-ffi 0.35 daemon was
//!   producing — same stable identity across the migration.
//!
//! Topic:
//!   BLAKE3("ec/ingress/announcements") = 32-byte gossip topic id.
//!   Configurable via EC_TOPIC env var.
//!
//! Wire format (stdout, one JSON per line):
//!   {"event": "ready",    "node_id": "<hex>", "topic": "<hex>",
//!                         "alpns": ["/iroh-gossip/1", "ec/ingress/v1"], "iroh_version": "<str>"}
//!   {"event": "envelope", "from": "<hex>", "raw_b64": "<base64>",
//!                         "transport": "gossip" | "quic_direct"}
//!   {"event": "peer",     "kind": "neighbor_up"|"neighbor_down"|"joined", "node_id": "<hex>"}
//!   {"event": "error",    "context": "<str>", "detail": "<str>"}
//!
//! Wire format (stdin, one JSON command per line):
//!   {"op": "broadcast", "raw_b64": "<base64>"}                                    // gossip broadcast
//!   {"op": "shutdown"}
//!
//! Why we have two ingress substrates:
//!   - Gossip (Part 9.2 ALPN /iroh-gossip/1): right for swarm-scoped publish/subscribe
//!     (TraceNet, Zeitgeist, ModuleNet, ClawNet per Parts 13-16). Wrong for 1:1 claw→daemon
//!     ingress: PlumTree + HyParView are designed for ≥100-peer swarms; in 2-peer topologies
//!     broadcast_neighbors() bypasses PlumTree's cache/repair entirely and drops silently on
//!     the active_send_tx mpsc channel when the connection loop terminates before the sender
//!     notices. Measured ~20% delivery.
//!   - Direct ALPN (ec/ingress/v1): reliable per-envelope QUIC bi-streams, invite-seeded
//!     point-to-point per Part 9.4, with transport-level ACK. This is the canonical primitive
//!     for brokered-worker-style claw→daemon ingress (Part 23.1). 99.9%+ delivery.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use iroh::{
    address_lookup::memory::MemoryLookup,
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointAddr, RelayUrl, SecretKey,
};
use iroh_blobs::{
    api::{downloader::Shuffled, Store},
    format::collection::Collection,
    store::mem::MemStore,
    ticket::BlobTicket,
    BlobFormat, BlobsProtocol, HashAndFormat, ALPN as BLOBS_ALPN,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, oneshot, Mutex};

/// ALPN for the spec-aligned direct-ingress protocol. Peers dial this ALPN,
/// open a bi-directional QUIC stream, write [u32 big-endian length N][N bytes
/// canonical GossipEnvelope JSON], then read a 1-byte transport ACK
/// (0x01 = accepted for membrane processing, 0x00 = rejected at transport
/// layer e.g. malformed framing). Membrane outcome is persisted as a
/// DISCLOSURE or BLOCK receipt in the daemon's ledger (Part 21.A.1 /
/// obligation matrix ingress row); receipt-level confirmation can be
/// queried separately via the existing COMMAND dispatcher.
const EC_INGRESS_ALPN: &[u8] = b"ec/ingress/v1";

/// Sanity cap on a single direct-ingress envelope. Beyond this we reject
/// at the transport layer to protect against adversarial length-prefix
/// attacks. 16 MiB is comfortably above the largest canonical envelope we
/// expect (~1-10 KiB typical), below anything that would strain memory on
/// the sidecar.
const EC_INGRESS_MAX_ENVELOPE_BYTES: u32 = 16 * 1024 * 1024;

// ── Output events (sidecar → Python over stdout) ─────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "event")]
enum OutEvent {
    #[serde(rename = "ready")]
    Ready {
        node_id: String,
        topic: String,
        /// Legacy single-ALPN field; kept for backward compat with older
        /// Python bridges that only read "alpn".
        alpn: String,
        /// Canonical list of all ALPNs the sidecar accepts.
        alpns: Vec<String>,
        /// Whether stdin op=send is implemented for direct ec/ingress/v1 sends.
        send_supported: bool,
        /// Direct socket addresses the local endpoint advertises (if any).
        ip_addrs: Vec<String>,
        /// Relay URLs the local endpoint advertises (typically one home relay).
        relay_urls: Vec<String>,
        iroh_version: String,
    },
    #[serde(rename = "envelope")]
    Envelope {
        from: String,
        raw_b64: String,
        /// "gossip" for messages delivered via /iroh-gossip/1 PlumTree,
        /// "quic_direct" for messages delivered via ec/ingress/v1.
        /// Propagated onto the receipt so the ledger records which substrate
        /// crossed the membrane (Part 21.A lineage).
        transport: String,
        /// Present for request/response messages whose QUIC bi-stream is
        /// intentionally held open until Python supplies a framed response.
        ingress_request_id: Option<String>,
    },
    #[serde(rename = "peer")]
    Peer { kind: String, node_id: String },
    #[serde(rename = "error")]
    Error { context: String, detail: String },
    /// Result of a daemon-initiated outbound Send via ec/ingress/v1.
    /// `reply_id` matches the InCmd::Send that initiated it so the Python
    /// side can correlate async send results to pending requests (necromancer
    /// request/response, ENROLLMENT_RESPONSE, etc.). `status` is "ok" when
    /// the peer ACK'd 0x01, "nack" when peer ACK'd 0x00, "error" for any
    /// dial / write / read / timeout failure.
    #[serde(rename = "send_result")]
    SendResult {
        reply_id: String,
        status: String,
        detail: Option<String>,
        target_node_id: String,
    },
    /// Result of a same-stream request. The peer first ACKs transport, then
    /// returns [u32 BE response length][canonical response envelope].
    #[serde(rename = "request_result")]
    RequestResult {
        request_id: String,
        status: String,
        detail: Option<String>,
        target_node_id: String,
        response_b64: Option<String>,
    },
    /// Result of a daemon-initiated iroh-blobs HASH_SEQ fetch for a
    /// TICKET_ANNOUNCEMENT. This returns the two canonical collection
    /// members the Python membrane expects: atom.json and payload.
    #[serde(rename = "fetch_result")]
    FetchResult {
        request_id: String,
        status: String,
        detail: Option<String>,
        ticket_hash: Option<String>,
        atom_json_b64: Option<String>,
        payload_b64: Option<String>,
        provider_node_id: Option<String>,
    },
    /// Result of publishing atom.json + payload as a local iroh-blobs
    /// HASH_SEQ collection. Used by claw-side agents so publish and fetch
    /// run on the same native iroh-blobs wire version.
    #[serde(rename = "publish_result")]
    PublishResult {
        request_id: String,
        status: String,
        detail: Option<String>,
        ticket: Option<String>,
        collection_hash: Option<String>,
        atom_hash: Option<String>,
        payload_hash: Option<String>,
        node_id: Option<String>,
    },
}

// ── Input commands (Python → sidecar over stdin) ─────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum InCmd {
    #[serde(rename = "broadcast")]
    Broadcast { raw_b64: String },
    /// Daemon-initiated outbound envelope over ec/ingress/v1 (Parts 9.4,
    /// 23.1). The sidecar opens a QUIC connection to `target_node_id` on
    /// the given ALPN (defaults to ec/ingress/v1), opens a bi-stream,
    /// writes [u32 BE len][envelope bytes], reads the 1-byte ACK, emits
    /// an OutEvent::SendResult tagged with `reply_id` so the Python side
    /// can correlate. This is the substrate for:
    ///   - Mac controller → VPS device push of credential updates
    ///     (ENROLLMENT_RESPONSE, REVOKE, ROTATE)
    ///   - necromancerd → soulless claw inference responses
    ///     (NECROMANCER_RESPONSE)
    /// Cf. specs/necromancer-protocol-v1.md.
    #[serde(rename = "send")]
    Send {
        /// Correlation id chosen by the Python caller. Echoed back in the
        /// SendResult event so multiple in-flight sends can demux.
        reply_id: String,
        /// Target's iroh NodeID (hex).
        target_node_id: String,
        /// Optional direct socket addresses (`ip:port`) for deterministic
        /// dialing when PKARR/relay lookup is unavailable. When provided,
        /// sidecar builds an EndpointAddr with these IP paths and dials it
        /// directly instead of relying on discovery-only `connect(node_id, ...)`.
        /// Example: ["203.0.113.7:7169"].
        target_addrs: Option<Vec<String>>,
        /// Optional explicit relay URL (`https://...`) to include in the
        /// dial address. Useful when the caller already knows peer home relay.
        relay_url: Option<String>,
        /// Optional ALPN; defaults to "ec/ingress/v1".
        alpn: Option<String>,
        /// Base64 of the canonical envelope bytes.
        raw_b64: String,
        /// Optional per-send timeout in seconds. Default 30s.
        timeout_s: Option<u64>,
    },
    /// Same framing as Send, but keep the stream open for a response envelope.
    #[serde(rename = "request")]
    Request {
        request_id: String,
        target_node_id: String,
        target_addrs: Option<Vec<String>>,
        relay_url: Option<String>,
        alpn: Option<String>,
        raw_b64: String,
        timeout_s: Option<u64>,
    },
    /// Complete a pending inbound same-stream request.
    #[serde(rename = "reply_ingress")]
    ReplyIngress { request_id: String, raw_b64: String },
    /// Fetch a ContextAtom collection from an iroh BlobTicket. The ticket
    /// must point at a HASH_SEQ collection with named blobs:
    ///   - atom.json
    ///   - payload
    /// The sidecar downloads content-addressed bytes; Python handles policy,
    /// signature, labels, receipts, and ACKs.
    #[serde(rename = "fetch_atom")]
    FetchAtom {
        request_id: String,
        ticket: String,
        timeout_s: Option<u64>,
    },
    /// Publish a signed ContextAtom into this sidecar's local iroh-blobs
    /// store as a HASH_SEQ collection with "atom.json" and "payload".
    /// The sidecar returns a BlobTicket that another native sidecar can fetch.
    #[serde(rename = "publish_atom")]
    PublishAtom {
        request_id: String,
        atom_json_b64: String,
        payload_b64: String,
    },
    #[serde(rename = "shutdown")]
    Shutdown,
}

// ── Helpers ──────────────────────────────────────────────────────

fn emit(ev: OutEvent) {
    match serde_json::to_string(&ev) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("[sidecar] failed to serialize event: {}", e),
    }
}

// Tiny base64 codec to avoid pulling another crate.
fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let (b0, b1, b2) = match chunk.len() {
            1 => (chunk[0], 0, 0),
            2 => (chunk[0], chunk[1], 0),
            _ => (chunk[0], chunk[1], chunk[2]),
        };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() == 3 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    const T: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0;
        while i < 64 {
            let c = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i];
            t[c as usize] = i as i8;
            i += 1;
        }
        t['=' as usize] = -2;
        t
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let v0 = T[bytes[i] as usize];
        let v1 = T[bytes[i + 1] as usize];
        let v2 = T[bytes[i + 2] as usize];
        let v3 = T[bytes[i + 3] as usize];
        if v0 < 0 || v1 < 0 {
            anyhow::bail!("bad base64");
        }
        let n = ((v0 as u32) << 18)
            | ((v1 as u32) << 12)
            | ((if v2 >= 0 { v2 as u32 } else { 0 }) << 6)
            | (if v3 >= 0 { v3 as u32 } else { 0 });
        out.push((n >> 16) as u8);
        if v2 >= 0 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if v3 >= 0 {
            out.push((n & 0xff) as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn load_secret_key() -> Result<SecretKey> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = PathBuf::from(home).join(".ec-daemon/iroh/node_secret.hex");
    if !path.exists() {
        anyhow::bail!(
            "iroh secret not found at {}; generate a 32-byte hex secret \
             and place it there first",
            path.display()
        );
    }
    let hex_str =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let bytes = hex::decode(hex_str.trim())
        .with_context(|| format!("decode hex from {}", path.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "iroh secret at {} must be 32 bytes, got {}",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(&arr))
}

fn derive_topic(name: &str) -> TopicId {
    let h = blake3::hash(name.as_bytes());
    let bytes: [u8; 32] = *h.as_bytes();
    TopicId::from_bytes(bytes)
}

// ── Direct-ALPN ingress handler (ec/ingress/v1) ───────────────────
//
// Per Part 9.4 (invite-seeded point-to-point for private flows) and Part 23.1
// (brokered-worker-style direct protocol handlers). Runs alongside the gossip
// handler on the same Endpoint via the Router's ALPN-based dispatch.
//
// Flow for an inbound envelope:
//   1. accept_bi() — open a bi-directional QUIC stream
//   2. read 4-byte big-endian length prefix
//   3. sanity check the length vs EC_INGRESS_MAX_ENVELOPE_BYTES
//   4. read that many bytes = the canonical GossipEnvelope JSON
//   5. emit {"event":"envelope","transport":"quic_direct",...} to Python
//   6. write 1-byte transport ACK (0x01 = received-and-queued) and finish
//
// The Python daemon's membrane then produces a DISCLOSURE or BLOCK receipt
// asynchronously. Transport-level ACK is orthogonal to membrane outcome —
// it means "bytes received intact, queued for processing," matching QUIC's
// reliable delivery semantics and the spec's expectation that one boundary
// crossing = at least one receipt (Part 3.3 gate taxonomy, Part 21.A.1).
type IngressReplyMap = Arc<Mutex<HashMap<String, oneshot::Sender<Vec<u8>>>>>;
const MAX_PENDING_INGRESS_REQUESTS: usize = 64;

#[derive(Clone, Debug)]
struct EcIngressHandler {
    pending_replies: IngressReplyMap,
}

impl EcIngressHandler {
    fn new(pending_replies: IngressReplyMap) -> Self {
        Self { pending_replies }
    }
}

async fn handle_ingress_stream(
    remote_id: String,
    mut send: SendStream,
    mut recv: RecvStream,
    pending_replies: IngressReplyMap,
) {
    // Read length prefix (4 bytes BE u32)
    let mut len_buf = [0u8; 4];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        eprintln!(
            "[sidecar:ingress] len-prefix read failed from {}: {:?}",
            &remote_id[..16.min(remote_id.len())],
            e
        );
        let _ = send.write_all(&[0x00]).await;
        let _ = send.finish();
        return;
    }
    let len = u32::from_be_bytes(len_buf);

    // Bounds check
    if len == 0 || len > EC_INGRESS_MAX_ENVELOPE_BYTES {
        eprintln!(
            "[sidecar:ingress] rejecting envelope size={} from {} (cap={})",
            len,
            &remote_id[..16.min(remote_id.len())],
            EC_INGRESS_MAX_ENVELOPE_BYTES
        );
        let _ = send.write_all(&[0x00]).await;
        let _ = send.finish();
        return;
    }

    // Read envelope body
    let mut buf = vec![0u8; len as usize];
    if let Err(e) = recv.read_exact(&mut buf).await {
        eprintln!(
            "[sidecar:ingress] body read failed (size={}) from {}: {:?}",
            len,
            &remote_id[..16.min(remote_id.len())],
            e
        );
        let _ = send.write_all(&[0x00]).await;
        let _ = send.finish();
        return;
    }

    eprintln!(
        "[sidecar:ingress] received envelope size={} from {}",
        len,
        &remote_id[..16.min(remote_id.len())]
    );

    // Enrollment is the only v1 same-stream RPC. Determine this from the
    // untrusted outer JSON solely to choose transport behavior; Python still
    // verifies the canonical envelope, self-signature, token, and policy.
    let wants_response = serde_json::from_slice::<serde_json::Value>(&buf)
        .ok()
        .and_then(|v| {
            v.get("msg_type")
                .and_then(|x| x.as_str())
                .map(str::to_owned)
        })
        .as_deref()
        == Some("enrollment_handshake");
    let ingress_request_id = if wants_response {
        let mut material = Vec::with_capacity(remote_id.len() + buf.len() + 32);
        material.extend_from_slice(remote_id.as_bytes());
        material.extend_from_slice(&buf);
        material.extend_from_slice(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_be_bytes(),
        );
        Some(blake3::hash(&material).to_hex().to_string())
    } else {
        None
    };

    let response_rx = if let Some(request_id) = ingress_request_id.as_ref() {
        let (tx, rx) = oneshot::channel();
        let mut pending = pending_replies.lock().await;
        if pending.len() >= MAX_PENDING_INGRESS_REQUESTS {
            drop(pending);
            eprintln!("[sidecar:ingress] rejecting same-stream request: capacity reached");
            let _ = send.write_all(&[0x00]).await;
            let _ = send.finish();
            return;
        }
        pending.insert(request_id.clone(), tx);
        Some(rx)
    } else {
        None
    };

    // Forward to Python. Uses the shared stdout writer; println! is
    // atomic on Unix for writes below PIPE_BUF, which our short JSON
    // line + base64 envelope fits comfortably within.
    emit(OutEvent::Envelope {
        from: remote_id,
        raw_b64: b64_encode(&buf),
        transport: "quic_direct".to_string(),
        ingress_request_id: ingress_request_id.clone(),
    });

    // Transport-level ACK: 0x01 = bytes received intact, queued for
    // membrane processing. Does NOT signal membrane acceptance — that
    // outcome lands in the receipt ledger as a DISCLOSURE or BLOCK.
    if let Err(e) = send.write_all(&[0x01]).await {
        eprintln!("[sidecar:ingress] ACK write failed: {:?}", e);
    }
    if let Some(response_rx) = response_rx {
        let response = tokio::time::timeout(std::time::Duration::from_secs(45), response_rx).await;
        let response_bytes = match response {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => Vec::new(),
            Err(_) => {
                if let Some(request_id) = ingress_request_id.as_ref() {
                    pending_replies.lock().await.remove(request_id);
                }
                eprintln!("[sidecar:ingress] same-stream response timeout");
                Vec::new()
            }
        };
        if response_bytes.len() <= EC_INGRESS_MAX_ENVELOPE_BYTES as usize {
            let len = response_bytes.len() as u32;
            if let Err(e) = send.write_all(&len.to_be_bytes()).await {
                eprintln!("[sidecar:ingress] response len write failed: {:?}", e);
            } else if !response_bytes.is_empty() {
                if let Err(e) = send.write_all(&response_bytes).await {
                    eprintln!("[sidecar:ingress] response body write failed: {:?}", e);
                }
            }
        }
    }
    if let Err(e) = send.finish() {
        eprintln!("[sidecar:ingress] send.finish err: {:?}", e);
    }
}

impl ProtocolHandler for EcIngressHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // Read remote endpoint id for provenance. On an established
        // Connection (post-handshake), iroh 0.97 returns the PublicKey
        // directly (not a Result).
        let remote_id = conn.remote_id().to_string();

        // iroh best practice: protocols with repeated requests should reuse a
        // connection and open a cheap new bi-stream per request. Keep this
        // accept future alive until the peer closes the connection.
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    let rid = remote_id.clone();
                    let pending = self.pending_replies.clone();
                    tokio::spawn(async move {
                        handle_ingress_stream(rid, send, recv, pending).await;
                    });
                }
                Err(e) => {
                    eprintln!(
                        "[sidecar:ingress] accept_bi ended for {}: {:?}",
                        &remote_id[..16.min(remote_id.len())],
                        e
                    );
                    break;
                }
            }
        }
        conn.closed().await;

        Ok(())
    }
}

// ── Main ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Tracing subscriber — emits to stderr (which Python pipes through
    // as [sidecar:err] tagged lines). Honor RUST_LOG env var; default to
    // info level for the sidecar itself, warn for noisy iroh subsystems.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("ec_iroh_sidecar=info,iroh_gossip=warn,iroh=warn")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();

    eprintln!("[sidecar] starting (iroh ~0.97)");

    // 1. Load persistent identity
    let secret = load_secret_key()?;
    eprintln!("[sidecar] loaded persistent ed25519 secret");

    // 2. Build endpoint with the n0 preset (n0 DNS discovery + default relay).
    // MemoryLookup lets us inject provider addressing info from BlobTickets
    // into this endpoint before downloading iroh-blobs content.
    let address_lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::N0)
        .address_lookup(address_lookup.clone())
        .secret_key(secret)
        .bind()
        .await
        .context("Endpoint::bind failed")?;
    let node_id = endpoint.id();
    eprintln!("[sidecar] node_id: {}", node_id);

    // 3. Spawn gossip + blobs protocols on this endpoint
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let store: Store = MemStore::new().into();
    let blobs = BlobsProtocol::new(&store, None);
    let pending_ingress_replies: IngressReplyMap = Arc::new(Mutex::new(HashMap::new()));

    // 4. Wire ALPN handlers through the Router. Two protocols live here:
    //      - GOSSIP_ALPN (/iroh-gossip/1): swarm-scoped pub/sub, for future
    //        TraceNet / Zeitgeist / ModuleNet / ClawNet (Parts 13-16).
    //      - EC_INGRESS_ALPN (ec/ingress/v1): direct 1:1 claw→daemon ingress
    //        with per-envelope QUIC bi-stream ACK. Canonical primitive for
    //        point-to-point ingress per Part 9.4 and Part 23.1.
    //    Router dispatches incoming connections by the ALPN they negotiate.
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(BLOBS_ALPN, blobs.clone())
        .accept(
            EC_INGRESS_ALPN,
            EcIngressHandler::new(pending_ingress_replies.clone()),
        )
        .spawn();

    // 5. Wait until we have a relay home (better discoverability)
    endpoint.online().await;
    eprintln!("[sidecar] endpoint online (relay home assigned)");

    // 6. Subscribe to the EC ingress topic — empty bootstrap, we're the seed
    let topic_name =
        std::env::var("EC_TOPIC").unwrap_or_else(|_| "ec/ingress/announcements".to_string());
    let topic = derive_topic(&topic_name);
    let topic_hex = hex::encode(topic.as_bytes());
    eprintln!("[sidecar] topic: {}", topic_hex);

    // We are the seed — subscribe without waiting for peers to join
    // (subscribe_and_join would block until at least one neighbor connects).
    let bootstrap: Vec<iroh::PublicKey> = Vec::new();
    let topic_handle = gossip
        .subscribe(topic, bootstrap)
        .await
        .context("subscribe failed")?;
    let (sender, receiver) = topic_handle.split();
    eprintln!("[sidecar] subscribed to topic, ready (seed mode, no bootstrap)");

    let gossip_alpn = String::from_utf8_lossy(GOSSIP_ALPN).to_string();
    let blobs_alpn = String::from_utf8_lossy(BLOBS_ALPN).to_string();
    let ingress_alpn = String::from_utf8_lossy(EC_INGRESS_ALPN).to_string();
    eprintln!(
        "[sidecar] accepting ALPNs: {} (gossip) + {} (blobs) + {} (direct ingress)",
        gossip_alpn, blobs_alpn, ingress_alpn
    );
    emit(OutEvent::Ready {
        node_id: node_id.to_string(),
        topic: topic_hex,
        // Legacy single-ALPN field points at gossip for backward compat.
        alpn: gossip_alpn.clone(),
        alpns: vec![gossip_alpn, blobs_alpn, ingress_alpn],
        send_supported: true,
        ip_addrs: endpoint.addr().ip_addrs().map(|a| a.to_string()).collect(),
        relay_urls: endpoint
            .addr()
            .relay_urls()
            .map(|u| u.to_string())
            .collect(),
        iroh_version: "iroh 0.97 (sidecar)".to_string(),
    });

    // 7. stdin command channel
    let (tx_cmd, mut rx_cmd) = mpsc::unbounded_channel::<InCmd>();
    spawn_stdin_reader(tx_cmd);

    // 8. Main loop
    run_loop(
        endpoint.clone(),
        store.clone(),
        address_lookup.clone(),
        sender,
        receiver,
        &mut rx_cmd,
        pending_ingress_replies,
    )
    .await?;

    eprintln!("[sidecar] exiting");
    Ok(())
}

fn spawn_stdin_reader(tx: mpsc::UnboundedSender<InCmd>) {
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<InCmd>(line) {
                Ok(cmd) => {
                    if tx.send(cmd).is_err() {
                        break;
                    }
                }
                Err(e) => emit(OutEvent::Error {
                    context: "stdin parse".to_string(),
                    detail: e.to_string(),
                }),
            }
        }
        eprintln!("[sidecar] stdin closed");
    });
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct SendTargetKey {
    target_node_id: String,
    target_addrs: Vec<String>,
    relay_url: String,
    alpn: String,
}

type ConnectionCache = Arc<Mutex<HashMap<SendTargetKey, Connection>>>;

fn build_endpoint_addr(key: &SendTargetKey) -> std::result::Result<EndpointAddr, String> {
    let node_id = key
        .target_node_id
        .parse::<iroh::PublicKey>()
        .map_err(|e| format!("parse node_id: {:?}", e))?;

    let mut endpoint_addr = EndpointAddr::new(node_id);
    for raw in &key.target_addrs {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let sa = raw
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("parse target_addrs entry '{}': {:?}", raw, e))?;
        endpoint_addr = endpoint_addr.with_ip_addr(sa);
    }
    let relay_raw = key.relay_url.trim();
    if !relay_raw.is_empty() {
        let r = relay_raw
            .parse::<RelayUrl>()
            .map_err(|e| format!("parse relay_url '{}': {:?}", relay_raw, e))?;
        endpoint_addr = endpoint_addr.with_relay_url(r);
    }
    Ok(endpoint_addr)
}

async fn get_or_connect(
    endpoint: &Endpoint,
    cache: &ConnectionCache,
    key: &SendTargetKey,
) -> std::result::Result<Connection, String> {
    {
        let mut guard = cache.lock().await;
        if let Some(conn) = guard.get(key) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            guard.remove(key);
        }
    }

    let endpoint_addr = build_endpoint_addr(key)?;
    let conn = endpoint
        .connect(endpoint_addr, key.alpn.as_bytes())
        .await
        .map_err(|e| format!("connect: {:?}", e))?;

    let mut guard = cache.lock().await;
    guard.insert(key.clone(), conn.clone());
    Ok(conn)
}

async fn remove_cached_connection(cache: &ConnectionCache, key: &SendTargetKey) {
    let mut guard = cache.lock().await;
    if let Some(conn) = guard.remove(key) {
        conn.close(0u32.into(), b"send-error");
    }
}

async fn send_frame_on_connection(
    conn: Connection,
    envelope_bytes: &[u8],
) -> std::result::Result<u8, String> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open_bi: {:?}", e))?;

    if envelope_bytes.len() > EC_INGRESS_MAX_ENVELOPE_BYTES as usize {
        return Err(format!(
            "envelope too large: {} bytes (cap {})",
            envelope_bytes.len(),
            EC_INGRESS_MAX_ENVELOPE_BYTES
        ));
    }

    let len = envelope_bytes.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write len: {:?}", e))?;
    send.write_all(envelope_bytes)
        .await
        .map_err(|e| format!("write body: {:?}", e))?;
    send.finish().map_err(|e| format!("send.finish: {:?}", e))?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack)
        .await
        .map_err(|e| format!("read ack: {:?}", e))?;
    Ok(ack[0])
}

async fn request_frame_on_connection(
    conn: Connection,
    envelope_bytes: &[u8],
) -> std::result::Result<(u8, Vec<u8>), String> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open_bi: {:?}", e))?;
    if envelope_bytes.len() > EC_INGRESS_MAX_ENVELOPE_BYTES as usize {
        return Err(format!("envelope too large: {}", envelope_bytes.len()));
    }
    let len = envelope_bytes.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write len: {:?}", e))?;
    send.write_all(envelope_bytes)
        .await
        .map_err(|e| format!("write body: {:?}", e))?;
    send.finish().map_err(|e| format!("send.finish: {:?}", e))?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack)
        .await
        .map_err(|e| format!("read ack: {:?}", e))?;
    if ack[0] != 0x01 {
        return Ok((ack[0], Vec::new()));
    }
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read response len: {:?}", e))?;
    let response_len = u32::from_be_bytes(len_buf);
    if response_len == 0 || response_len > EC_INGRESS_MAX_ENVELOPE_BYTES {
        return Err(format!("invalid response length {}", response_len));
    }
    let mut response = vec![0u8; response_len as usize];
    recv.read_exact(&mut response)
        .await
        .map_err(|e| format!("read response: {:?}", e))?;
    Ok((ack[0], response))
}

/// Dial `target_node_id` on `alpn` and push a single envelope via the
/// ec/ingress/v1 wire format: [u32 BE length][N bytes envelope] → 1-byte ACK.
/// Emits a SendResult event with the outcome.
async fn do_outbound_send(
    endpoint: Endpoint,
    cache: ConnectionCache,
    reply_id: String,
    target_node_id: String,
    target_addrs: Option<Vec<String>>,
    relay_url: Option<String>,
    alpn: String,
    envelope_bytes: Vec<u8>,
    timeout_s: u64,
) {
    let key = SendTargetKey {
        target_node_id: target_node_id.clone(),
        target_addrs: target_addrs
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        relay_url: relay_url.unwrap_or_default().trim().to_string(),
        alpn,
    };

    let mut final_result: std::result::Result<u8, String> = Err("send not attempted".to_string());

    // iroh best practice: keep the QUIC connection warm, open a fresh
    // bi-stream per envelope. If a cached connection fails, discard it and
    // retry once on a freshly-dialed connection.
    for attempt in 1..=2 {
        let op = async {
            let conn = get_or_connect(&endpoint, &cache, &key).await?;
            let ack = send_frame_on_connection(conn.clone(), &envelope_bytes).await;
            if ack.is_err() {
                conn.close(0u32.into(), b"stream-error");
            }
            ack
        };

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_s), op).await {
            Ok(Ok(ack)) => {
                final_result = Ok(ack);
                break;
            }
            Ok(Err(e)) => {
                remove_cached_connection(&cache, &key).await;
                final_result = Err(e);
                if attempt == 2 {
                    break;
                }
            }
            Err(_) => {
                remove_cached_connection(&cache, &key).await;
                final_result = Err(format!("timeout after {}s", timeout_s));
                if attempt == 2 {
                    break;
                }
            }
        }
    }

    let (status, detail) = match final_result {
        Err(e) => ("error".to_string(), Some(e)),
        Ok(0x01) => ("ok".to_string(), None),
        Ok(0x00) => (
            "nack".to_string(),
            Some("peer rejected at transport layer".to_string()),
        ),
        Ok(b) => (
            "error".to_string(),
            Some(format!("unexpected ACK byte 0x{:02x}", b)),
        ),
    };

    emit(OutEvent::SendResult {
        reply_id,
        status,
        detail,
        target_node_id,
    });
}

async fn do_outbound_request(
    endpoint: Endpoint,
    cache: ConnectionCache,
    request_id: String,
    target_node_id: String,
    target_addrs: Option<Vec<String>>,
    relay_url: Option<String>,
    alpn: String,
    envelope_bytes: Vec<u8>,
    timeout_s: u64,
) {
    let key = SendTargetKey {
        target_node_id: target_node_id.clone(),
        target_addrs: target_addrs
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        relay_url: relay_url.unwrap_or_default().trim().to_string(),
        alpn,
    };
    let op = async {
        let conn = get_or_connect(&endpoint, &cache, &key).await?;
        request_frame_on_connection(conn, &envelope_bytes).await
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(timeout_s), op).await;
    match result {
        Ok(Ok((0x01, response))) => emit(OutEvent::RequestResult {
            request_id,
            status: "ok".to_string(),
            detail: None,
            target_node_id,
            response_b64: Some(b64_encode(&response)),
        }),
        Ok(Ok((ack, _))) => emit(OutEvent::RequestResult {
            request_id,
            status: "nack".to_string(),
            detail: Some(format!("peer ACK 0x{:02x}", ack)),
            target_node_id,
            response_b64: None,
        }),
        Ok(Err(e)) => {
            remove_cached_connection(&cache, &key).await;
            emit(OutEvent::RequestResult {
                request_id,
                status: "error".to_string(),
                detail: Some(e),
                target_node_id,
                response_b64: None,
            });
        }
        Err(_) => {
            remove_cached_connection(&cache, &key).await;
            emit(OutEvent::RequestResult {
                request_id,
                status: "error".to_string(),
                detail: Some(format!("timeout after {}s", timeout_s)),
                target_node_id,
                response_b64: None,
            });
        }
    }
}

/// Fetch a ContextAtom HASH_SEQ collection from an iroh BlobTicket and emit
/// the canonical members for Python's IngressInspector. This is the
/// sidecar half of TICKET_ANNOUNCEMENT ingestion.
async fn do_fetch_atom(
    endpoint: Endpoint,
    store: Store,
    address_lookup: MemoryLookup,
    request_id: String,
    ticket_string: String,
    timeout_s: u64,
) {
    let fetch_result = async {
        let ticket = ticket_string
            .parse::<BlobTicket>()
            .map_err(|e| format!("parse BlobTicket: {:?}", e))?;

        if !ticket.recursive() {
            return Err("BlobTicket is not recursive HASH_SEQ collection".to_string());
        }

        let provider_node_id = ticket.addr().id.to_string();
        address_lookup.add_endpoint_info(ticket.addr().clone());

        let req = HashAndFormat::hash_seq(ticket.hash());
        let providers = Shuffled::new(vec![ticket.addr().id]);
        store
            .downloader(&endpoint)
            .download(req, providers)
            .await
            .map_err(|e| format!("download collection: {:?}", e))?;

        let collection = Collection::load(ticket.hash(), &store)
            .await
            .map_err(|e| format!("load collection: {:?}", e))?;

        let mut atom_json: Option<Vec<u8>> = None;
        let mut payload: Option<Vec<u8>> = None;

        for (name, hash) in collection {
            let bytes = store
                .get_bytes(hash)
                .await
                .map_err(|e| format!("read collection member '{}': {:?}", name, e))?;
            match name.as_str() {
                "atom.json" => atom_json = Some(bytes.to_vec()),
                "payload" => payload = Some(bytes.to_vec()),
                _ => {
                    // Forward-compatible: unknown collection members are
                    // ignored by sidecar; membrane only needs canonical pair.
                }
            }
        }

        let atom_json = atom_json.ok_or_else(|| "collection missing atom.json".to_string())?;
        let payload = payload.ok_or_else(|| "collection missing payload".to_string())?;

        Ok::<(String, String, Vec<u8>, Vec<u8>), String>((
            ticket.hash().to_string(),
            provider_node_id,
            atom_json,
            payload,
        ))
    };

    let outcome =
        tokio::time::timeout(std::time::Duration::from_secs(timeout_s), fetch_result).await;

    match outcome {
        Err(_) => emit(OutEvent::FetchResult {
            request_id,
            status: "error".to_string(),
            detail: Some(format!("timeout after {}s", timeout_s)),
            ticket_hash: None,
            atom_json_b64: None,
            payload_b64: None,
            provider_node_id: None,
        }),
        Ok(Err(e)) => emit(OutEvent::FetchResult {
            request_id,
            status: "error".to_string(),
            detail: Some(e),
            ticket_hash: None,
            atom_json_b64: None,
            payload_b64: None,
            provider_node_id: None,
        }),
        Ok(Ok((ticket_hash, provider_node_id, atom_json, payload))) => {
            emit(OutEvent::FetchResult {
                request_id,
                status: "ok".to_string(),
                detail: None,
                ticket_hash: Some(ticket_hash),
                atom_json_b64: Some(b64_encode(&atom_json)),
                payload_b64: Some(b64_encode(&payload)),
                provider_node_id: Some(provider_node_id),
            });
        }
    }
}

/// Publish atom.json + payload into the sidecar's iroh-blobs store and emit
/// a BlobTicket for native peers to fetch. This is the claw-side mirror of
/// do_fetch_atom and avoids Python iroh-ffi 0.35 / native iroh-blobs wire
/// incompatibility.
async fn do_publish_atom(
    endpoint: Endpoint,
    store: Store,
    request_id: String,
    atom_json: Vec<u8>,
    payload: Vec<u8>,
) {
    let publish_result = async {
        let mut atom_tag = store
            .add_bytes(atom_json)
            .temp_tag()
            .await
            .map_err(|e| format!("add atom.json: {:?}", e))?;
        let mut payload_tag = store
            .add_bytes(payload)
            .temp_tag()
            .await
            .map_err(|e| format!("add payload: {:?}", e))?;

        let mut collection = Collection::default();
        collection.push("atom.json".to_string(), atom_tag.hash());
        collection.push("payload".to_string(), payload_tag.hash());
        let mut collection_tag = collection
            .store(&store)
            .await
            .map_err(|e| format!("store collection: {:?}", e))?;

        let atom_hash = atom_tag.hash().to_string();
        let payload_hash = payload_tag.hash().to_string();
        let collection_hash = collection_tag.hash().to_string();
        let ticket = BlobTicket::new(endpoint.addr(), collection_tag.hash(), BlobFormat::HashSeq)
            .to_string();

        // Keep the blobs alive until the sidecar process exits. Without this,
        // temp tags can drop immediately after returning the ticket and the
        // provider may GC content before the master fetches it.
        atom_tag.leak();
        payload_tag.leak();
        collection_tag.leak();

        Ok::<(String, String, String, String, String), String>((
            ticket,
            collection_hash,
            atom_hash,
            payload_hash,
            endpoint.id().to_string(),
        ))
    };

    match publish_result.await {
        Err(e) => emit(OutEvent::PublishResult {
            request_id,
            status: "error".to_string(),
            detail: Some(e),
            ticket: None,
            collection_hash: None,
            atom_hash: None,
            payload_hash: None,
            node_id: None,
        }),
        Ok((ticket, collection_hash, atom_hash, payload_hash, node_id)) => {
            emit(OutEvent::PublishResult {
                request_id,
                status: "ok".to_string(),
                detail: None,
                ticket: Some(ticket),
                collection_hash: Some(collection_hash),
                atom_hash: Some(atom_hash),
                payload_hash: Some(payload_hash),
                node_id: Some(node_id),
            });
        }
    }
}

async fn run_loop(
    endpoint: Endpoint,
    store: Store,
    address_lookup: MemoryLookup,
    sender: GossipSender,
    mut receiver: GossipReceiver,
    rx_cmd: &mut mpsc::UnboundedReceiver<InCmd>,
    pending_ingress_replies: IngressReplyMap,
) -> Result<()> {
    let connection_cache: ConnectionCache = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            biased;

            cmd = rx_cmd.recv() => match cmd {
                Some(InCmd::Shutdown) => {
                    eprintln!("[sidecar] shutdown requested");
                    return Ok(());
                }
                Some(InCmd::Broadcast { raw_b64 }) => {
                    match b64_decode(&raw_b64) {
                        Ok(bytes) => {
                            if let Err(e) = sender.broadcast(bytes.into()).await {
                                emit(OutEvent::Error {
                                    context: "broadcast".to_string(),
                                    detail: e.to_string(),
                                });
                            }
                        }
                        Err(e) => emit(OutEvent::Error {
                            context: "broadcast b64 decode".to_string(),
                            detail: e.to_string(),
                        }),
                    }
                }
                Some(InCmd::Send {
                    reply_id,
                    target_node_id,
                    target_addrs,
                    relay_url,
                    alpn,
                    raw_b64,
                    timeout_s,
                }) => {
                    let alpn = alpn.unwrap_or_else(|| {
                        String::from_utf8_lossy(EC_INGRESS_ALPN).to_string()
                    });
                    let timeout_s = timeout_s.unwrap_or(30);
                    match b64_decode(&raw_b64) {
                        Ok(envelope_bytes) => {
                            // Spawn so we don't block the select loop on a slow peer.
                            let ep = endpoint.clone();
                            let cache = connection_cache.clone();
                            let tn = target_node_id.clone();
                            tokio::spawn(async move {
                                do_outbound_send(
                                    ep,
                                    cache,
                                    reply_id,
                                    tn,
                                    target_addrs,
                                    relay_url,
                                    alpn,
                                    envelope_bytes,
                                    timeout_s,
                                )
                                .await;
                            });
                        }
                        Err(e) => {
                            emit(OutEvent::SendResult {
                                reply_id,
                                status: "error".to_string(),
                                detail: Some(format!("b64 decode: {}", e)),
                                target_node_id,
                            });
                        }
                    }
                }
                Some(InCmd::Request {
                    request_id,
                    target_node_id,
                    target_addrs,
                    relay_url,
                    alpn,
                    raw_b64,
                    timeout_s,
                }) => {
                    let alpn = alpn.unwrap_or_else(|| String::from_utf8_lossy(EC_INGRESS_ALPN).to_string());
                    let timeout_s = timeout_s.unwrap_or(45);
                    match b64_decode(&raw_b64) {
                        Ok(envelope_bytes) => {
                            let ep = endpoint.clone();
                            let cache = connection_cache.clone();
                            tokio::spawn(async move {
                                do_outbound_request(
                                    ep, cache, request_id, target_node_id,
                                    target_addrs, relay_url, alpn, envelope_bytes, timeout_s,
                                ).await;
                            });
                        }
                        Err(e) => emit(OutEvent::RequestResult {
                            request_id,
                            status: "error".to_string(),
                            detail: Some(format!("b64 decode: {}", e)),
                            target_node_id,
                            response_b64: None,
                        }),
                    }
                }
                Some(InCmd::ReplyIngress { request_id, raw_b64 }) => {
                    match b64_decode(&raw_b64) {
                        Ok(bytes) => {
                            let sender = pending_ingress_replies.lock().await.remove(&request_id);
                            match sender {
                                Some(tx) => {
                                    if tx.send(bytes).is_err() {
                                        emit(OutEvent::Error {
                                            context: "reply_ingress".to_string(),
                                            detail: format!("request {} receiver already closed", request_id),
                                        });
                                    }
                                }
                                None => emit(OutEvent::Error {
                                    context: "reply_ingress".to_string(),
                                    detail: format!("unknown or expired request_id {}", request_id),
                                }),
                            }
                        }
                        Err(e) => emit(OutEvent::Error {
                            context: "reply_ingress b64 decode".to_string(),
                            detail: e.to_string(),
                        }),
                    }
                }
                Some(InCmd::FetchAtom {
                    request_id,
                    ticket,
                    timeout_s,
                }) => {
                    let ep = endpoint.clone();
                    let st = store.clone();
                    let lookup = address_lookup.clone();
                    let timeout_s = timeout_s.unwrap_or(60);
                    tokio::spawn(async move {
                        do_fetch_atom(
                            ep,
                            st,
                            lookup,
                            request_id,
                            ticket,
                            timeout_s,
                        )
                        .await;
                    });
                }
                Some(InCmd::PublishAtom {
                    request_id,
                    atom_json_b64,
                    payload_b64,
                }) => {
                    let atom_json = match b64_decode(&atom_json_b64) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            emit(OutEvent::PublishResult {
                                request_id,
                                status: "error".to_string(),
                                detail: Some(format!("atom_json b64 decode: {}", e)),
                                ticket: None,
                                collection_hash: None,
                                atom_hash: None,
                                payload_hash: None,
                                node_id: None,
                            });
                            continue;
                        }
                    };
                    let payload = match b64_decode(&payload_b64) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            emit(OutEvent::PublishResult {
                                request_id,
                                status: "error".to_string(),
                                detail: Some(format!("payload b64 decode: {}", e)),
                                ticket: None,
                                collection_hash: None,
                                atom_hash: None,
                                payload_hash: None,
                                node_id: None,
                            });
                            continue;
                        }
                    };
                    let ep = endpoint.clone();
                    let st = store.clone();
                    tokio::spawn(async move {
                        do_publish_atom(ep, st, request_id, atom_json, payload).await;
                    });
                }
                None => {
                    // Parent (Python daemon) closed stdin — exit cleanly so we
                    // don't loop forever printing this message. Daemon shutdown
                    // path always sends {"op":"shutdown"} first; reaching here
                    // means parent died without grace.
                    eprintln!("[sidecar] stdin closed — parent likely gone, exiting");
                    return Ok(());
                }
            },

            event = receiver.next() => {
                // Trace every event before processing so we can see if
                // the gossip layer is yielding messages we're then
                // failing to forward.
                eprintln!("[sidecar:trace] receiver yielded: {:?}",
                    event.as_ref().map(|r| r.as_ref().map(|e| match e {
                        Event::Received(m) => format!("Received({} bytes from {})", m.content.len(), m.delivered_from),
                        Event::NeighborUp(id) => format!("NeighborUp({})", id),
                        Event::NeighborDown(id) => format!("NeighborDown({})", id),
                        Event::Lagged => "Lagged".to_string(),
                    })));
                match event {
                    Some(Ok(Event::Received(msg))) => {
                        // Gossip-delivered envelope. Mark transport explicitly
                        // so the Python bridge can distinguish from direct-ALPN
                        // ingress and persist it on the receipt for lineage.
                        emit(OutEvent::Envelope {
                            from: msg.delivered_from.to_string(),
                            raw_b64: b64_encode(&msg.content),
                            transport: "gossip".to_string(),
                            ingress_request_id: None,
                        });
                    }
                    Some(Ok(Event::NeighborUp(id))) => {
                        emit(OutEvent::Peer {
                            kind: "neighbor_up".to_string(),
                            node_id: id.to_string(),
                        });
                    }
                    Some(Ok(Event::NeighborDown(id))) => {
                        emit(OutEvent::Peer {
                            kind: "neighbor_down".to_string(),
                            node_id: id.to_string(),
                        });
                    }
                    Some(Ok(Event::Lagged)) => {
                        emit(OutEvent::Error {
                            context: "gossip".to_string(),
                            detail: "lagged".to_string(),
                        });
                    }
                    Some(Err(e)) => {
                        emit(OutEvent::Error {
                            context: "gossip recv".to_string(),
                            detail: e.to_string(),
                        });
                    }
                    None => {
                        eprintln!("[sidecar] gossip stream ended");
                        return Ok(());
                    }
                }
            },
        }
    }
}
