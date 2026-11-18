//! Kitty clipboard protocol (`OSC 5522`) and `DECSET 5522` paste event encoding.
//!
//! Modeled on Ghostty's `src/terminal/kitty/clipboard.zig` and the Kitty
//! clipboard specification (`https://sw.kovidgoyal.net/kitty/clipboard/`):
//! - Metadata is `key=value` pairs separated by `:` before the first `;`.
//! - `mime`, `name`, and `pw` metadata values are strict RFC 4648 base64-encoded UTF-8.
//! - `id` is sanitized to `[a-zA-Z0-9-_+.]` and truncated to 512 bytes, then echoed
//!   verbatim in response packets when non-empty.
//! - Unsolicited paste events (`DECSET 5522`) emit `OK`, a targets (`.`) `DATA`
//!   listing of available MIME types, and `DONE`, all carrying a one-time `pw`.
//! - Read responses chunk each requested MIME payload into at most 4096 pre-base64
//!   bytes per `DATA` packet, followed by `DONE`.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::TerminalEffects;

/// Maximum raw (pre-base64) bytes per `DATA` packet in read responses.
pub const READ_CHUNK_SIZE: usize = 4096;

/// Maximum requested MIME types served by a single read request.
pub const MAX_READ_MIMES: usize = 4;

/// Maximum MIME types reported in a paste event's targets listing.
pub const MAX_LISTING_MIMES: usize = 16;

/// Special MIME type that requests the space-separated list of available types.
pub const TARGETS_MIME: &str = ".";

/// Maximum sanitized correlation `id` length echoed in responses.
pub const MAX_ID_LEN: usize = 512;

/// Maximum decoded `pw` length.
pub const MAX_PW_LEN: usize = 256;

/// Maximum decoded MIME type length.
pub const MAX_MIME_LEN: usize = 256;

/// Maximum total bytes buffered in an in-flight `write` transaction.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum distinct MIME representations in a single `write` transaction.
pub const MAX_WRITE_MIMES: usize = 16;

/// Maximum MIME aliases (`walias`) in a single `write` transaction.
pub const MAX_WRITE_ALIASES: usize = 16;

/// OSC terminator echoed in response packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KittyClipboardTerminator {
    #[default]
    St,
    Bel,
}

impl KittyClipboardTerminator {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::St => b"\x1b\\",
            Self::Bel => b"\x07",
        }
    }
}

/// Operation echoed in `type=` response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KittyClipboardOperation {
    Read,
    Write,
}

impl KittyClipboardOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Status code echoed in `status=` response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KittyClipboardStatus {
    Ok,
    Data,
    Done,
    Einval,
    Eperm,
    Eio,
    Enosys,
}

impl KittyClipboardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Data => "DATA",
            Self::Done => "DONE",
            Self::Einval => "EINVAL",
            Self::Eperm => "EPERM",
            Self::Eio => "EIO",
            Self::Enosys => "ENOSYS",
        }
    }
}

/// A single clipboard MIME representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KittyClipboardContent {
    pub mime: String,
    pub data: Vec<u8>,
}

/// Parsed `OSC 5522;type=read` request forwarded to the host clipboard adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KittyClipboardReadRequest {
    pub id: String,
    pub primary: bool,
    pub pw: Option<String>,
    pub list_targets: bool,
    pub requested_mimes: Vec<String>,
    pub terminator: KittyClipboardTerminator,
}

/// Committed `OSC 5522` write transaction forwarded to the host clipboard adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KittyClipboardWriteCommit {
    pub primary: bool,
    pub contents: Vec<KittyClipboardContent>,
    pub text: Option<String>,
}

/// Encode a single `OSC 5522` response packet.
pub fn encode_response_packet(
    op: KittyClipboardOperation,
    status: KittyClipboardStatus,
    primary: bool,
    id: &str,
    mime: Option<&str>,
    pw: Option<&str>,
    payload: &[u8],
    terminator: KittyClipboardTerminator,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload.len() * 4 / 3);
    encode_metadata(&mut out, op, status, primary, id, mime, pw);
    if !payload.is_empty() {
        out.push(b';');
        out.extend_from_slice(B64.encode(payload).as_bytes());
    }
    out.extend_from_slice(terminator.as_bytes());
    out
}

/// Encode a status-only `OSC 5522` packet (`DONE`, `EPERM`, `EINVAL`, etc.).
pub fn encode_status_packet(
    op: KittyClipboardOperation,
    status: KittyClipboardStatus,
    primary: bool,
    id: &str,
    terminator: KittyClipboardTerminator,
) -> Vec<u8> {
    encode_response_packet(op, status, primary, id, None, None, &[], terminator)
}

/// Encode an unsolicited Kitty paste event (`DECSET 5522`).
///
/// Emits `OK`, the targets (`.`) `DATA` packet listing `available_mimes`, and `DONE`,
/// carrying `pw` on every packet so the client can read any advertised MIME type.
pub fn encode_paste_event(
    pw: &str,
    available_mimes: &[&str],
    primary: bool,
    terminator: KittyClipboardTerminator,
) -> Vec<u8> {
    encode_read_packets(
        primary,
        "",
        Some(pw),
        true,
        available_mimes,
        &[],
        terminator,
    )
}

/// Encode a full successful `OSC 5522` read response (`OK`, optional `.` listing,
/// chunked `DATA` packets per representation, and `DONE`).
pub fn encode_read_success(
    req: &KittyClipboardReadRequest,
    available_mimes: &[&str],
    contents: &[KittyClipboardContent],
) -> Vec<u8> {
    encode_read_packets(
        req.primary,
        &req.id,
        None,
        req.list_targets,
        available_mimes,
        contents,
        req.terminator,
    )
}

fn encode_read_packets(
    primary: bool,
    id: &str,
    pw: Option<&str>,
    list_targets: bool,
    available_mimes: &[&str],
    contents: &[KittyClipboardContent],
    terminator: KittyClipboardTerminator,
) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. Initial OK packet (only OK carries loc=primary on paste events / reads).
    out.extend_from_slice(&encode_response_packet(
        KittyClipboardOperation::Read,
        KittyClipboardStatus::Ok,
        primary,
        id,
        None,
        pw,
        &[],
        terminator,
    ));

    // 2. Targets ('.') listing packet if requested.
    if list_targets {
        encode_metadata(
            &mut out,
            KittyClipboardOperation::Read,
            KittyClipboardStatus::Data,
            false,
            id,
            Some(TARGETS_MIME),
            pw,
        );
        let capped = &available_mimes[..available_mimes.len().min(MAX_LISTING_MIMES)];
        if !capped.is_empty() {
            let mut listing = Vec::new();
            for (idx, &mime) in capped.iter().enumerate() {
                let sep = usize::from(idx > 0);
                if listing.len() + sep + mime.len() + 1 > READ_CHUNK_SIZE {
                    break;
                }
                if idx > 0 {
                    listing.push(b' ');
                }
                listing.extend_from_slice(mime.as_bytes());
            }
            if !listing.is_empty() {
                listing.push(b'\n');
                out.push(b';');
                out.extend_from_slice(B64.encode(&listing).as_bytes());
            }
        }
        out.extend_from_slice(terminator.as_bytes());
    }

    // 3. Chunked DATA packets for each served representation.
    for content in contents {
        for chunk in content.data.chunks(READ_CHUNK_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            out.extend_from_slice(&encode_response_packet(
                KittyClipboardOperation::Read,
                KittyClipboardStatus::Data,
                false,
                id,
                Some(&content.mime),
                pw,
                chunk,
                terminator,
            ));
        }
    }

    // 4. Trailing DONE packet.
    out.extend_from_slice(&encode_response_packet(
        KittyClipboardOperation::Read,
        KittyClipboardStatus::Done,
        false,
        id,
        None,
        pw,
        &[],
        terminator,
    ));

    out
}

fn encode_metadata(
    out: &mut Vec<u8>,
    op: KittyClipboardOperation,
    status: KittyClipboardStatus,
    primary: bool,
    id: &str,
    mime: Option<&str>,
    pw: Option<&str>,
) {
    out.extend_from_slice(b"\x1b]5522;type=");
    out.extend_from_slice(op.as_str().as_bytes());
    out.extend_from_slice(b":status=");
    out.extend_from_slice(status.as_str().as_bytes());
    if primary {
        out.extend_from_slice(b":loc=primary");
    }
    if !id.is_empty() {
        out.extend_from_slice(b":id=");
        out.extend_from_slice(id.as_bytes());
    }
    if let Some(mime) = mime {
        out.extend_from_slice(b":mime=");
        out.extend_from_slice(B64.encode(mime.as_bytes()).as_bytes());
    }
    if let Some(pw) = pw {
        out.extend_from_slice(b":pw=");
        out.extend_from_slice(B64.encode(pw.as_bytes()).as_bytes());
    }
}

/// Sanitize `id` by stripping characters outside `[a-zA-Z0-9-_+.]` and truncating to 512 bytes.
pub fn sanitize_id(raw: &str) -> String {
    raw.bytes()
        .filter(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'.'))
        .take(MAX_ID_LEN)
        .map(char::from)
        .collect()
}

#[derive(Debug, Default)]
struct WriteTransaction {
    id: String,
    primary: bool,
    terminator: KittyClipboardTerminator,
    total_bytes: usize,
    entries: Vec<(String, Vec<u8>)>,
    pending_b64: HashMap<String, Vec<u8>>,
    aliases: Vec<(String, String)>,
}

/// Per-screen Kitty clipboard (`OSC 5522`) state machine.
#[derive(Debug, Default)]
pub struct KittyClipboardState {
    in_flight_write: Option<WriteTransaction>,
}

impl KittyClipboardState {
    pub fn clear(&mut self) {
        self.in_flight_write = None;
    }

    /// Process the body of an `ESC ] 5522 ; <body_after_semicolon> <ST|BEL>` sequence.
    pub fn handle_osc(
        &mut self,
        body: &[u8],
        bell_terminated: bool,
        effects: &mut TerminalEffects,
    ) {
        let terminator = if bell_terminated {
            KittyClipboardTerminator::Bel
        } else {
            KittyClipboardTerminator::St
        };
        let (meta_bytes, payload_bytes) = match body.iter().position(|&b| b == b';') {
            Some(idx) => (&body[..idx], &body[idx + 1..]),
            None => (body, &[][..]),
        };
        if meta_bytes.is_empty() {
            return;
        }
        let Ok(meta_str) = std::str::from_utf8(meta_bytes) else {
            return;
        };

        let mut req_type: Option<&str> = None;
        let mut id = String::new();
        let mut primary = false;
        let mut raw_mime: Option<&str> = None;
        let mut raw_pw: Option<&str> = None;
        let mut raw_name: Option<&str> = None;

        for pair in meta_str.split(':') {
            let Some((key, value)) = pair.split_once('=') else {
                // Any record without '=' drops the request silently.
                return;
            };
            match key {
                "type" => req_type = Some(value),
                "id" => id = sanitize_id(value),
                "loc" => primary = value == "primary",
                "mime" => raw_mime = Some(value),
                "pw" => raw_pw = Some(value),
                "name" => raw_name = Some(value),
                _ => {}
            }
        }

        let Some(req_type) = req_type else {
            return;
        };

        match req_type {
            "read" => {
                self.handle_read(
                    id,
                    primary,
                    raw_mime,
                    raw_pw,
                    raw_name,
                    payload_bytes,
                    terminator,
                    effects,
                );
            }
            "write" => {
                self.handle_write_start(id, primary, raw_mime, raw_pw, raw_name, terminator, effects);
            }
            "wdata" => {
                self.handle_wdata(raw_mime, raw_pw, raw_name, payload_bytes, terminator, effects);
            }
            "walias" => {
                self.handle_walias(raw_mime, raw_pw, raw_name, payload_bytes, terminator, effects);
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_read(
        &mut self,
        id: String,
        primary: bool,
        raw_mime: Option<&str>,
        raw_pw: Option<&str>,
        raw_name: Option<&str>,
        payload_bytes: &[u8],
        terminator: KittyClipboardTerminator,
        effects: &mut TerminalEffects,
    ) {
        // Invalid base64/UTF-8 on read is dropped with no response per spec.
        if let Some(m) = raw_mime
            && decode_b64_utf8(m, MAX_MIME_LEN).is_none()
        {
            return;
        }
        if let Some(n) = raw_name
            && decode_b64_utf8(n, MAX_MIME_LEN).is_none()
        {
            return;
        }
        let pw = match raw_pw {
            Some(raw) => {
                let Some(decoded) = decode_b64_utf8(raw, MAX_PW_LEN) else {
                    return;
                };
                Some(decoded)
            }
            None => None,
        };
        if payload_bytes.is_empty() {
            return;
        }
        let Ok(decoded_payload) = B64.decode(payload_bytes) else {
            return;
        };
        let Ok(mimes_str) = std::str::from_utf8(&decoded_payload) else {
            return;
        };

        let mut list_targets = false;
        let mut requested_mimes = Vec::new();
        for token in mimes_str.split(' ') {
            if token.is_empty() {
                continue;
            }
            if token == TARGETS_MIME {
                list_targets = true;
                continue;
            }
            if token.len() <= MAX_MIME_LEN
                && requested_mimes.len() < MAX_READ_MIMES
                && !requested_mimes.iter().any(|existing| existing == token)
            {
                requested_mimes.push(token.to_string());
            }
        }
        if !list_targets && requested_mimes.is_empty() {
            return;
        }

        effects.kitty_clipboard_reads.push(KittyClipboardReadRequest {
            id,
            primary,
            pw,
            list_targets,
            requested_mimes,
            terminator,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_write_start(
        &mut self,
        id: String,
        primary: bool,
        raw_mime: Option<&str>,
        raw_pw: Option<&str>,
        raw_name: Option<&str>,
        terminator: KittyClipboardTerminator,
        effects: &mut TerminalEffects,
    ) {
        if raw_mime.is_some_and(|m| decode_b64_utf8(m, MAX_MIME_LEN).is_none())
            || raw_pw.is_some_and(|p| decode_b64_utf8(p, MAX_PW_LEN).is_none())
            || raw_name.is_some_and(|n| decode_b64_utf8(n, MAX_MIME_LEN).is_none())
        {
            effects.pty_write.push(encode_status_packet(
                KittyClipboardOperation::Write,
                KittyClipboardStatus::Einval,
                false,
                &id,
                terminator,
            ));
            self.in_flight_write = None;
            return;
        }

        self.in_flight_write = Some(WriteTransaction {
            id: id.clone(),
            primary,
            terminator,
            total_bytes: 0,
            entries: Vec::new(),
            pending_b64: HashMap::new(),
            aliases: Vec::new(),
        });
        effects.pty_write.push(encode_status_packet(
            KittyClipboardOperation::Write,
            KittyClipboardStatus::Ok,
            false,
            &id,
            terminator,
        ));
    }

    fn handle_wdata(
        &mut self,
        raw_mime: Option<&str>,
        raw_pw: Option<&str>,
        raw_name: Option<&str>,
        payload_bytes: &[u8],
        terminator: KittyClipboardTerminator,
        effects: &mut TerminalEffects,
    ) {
        let Some(mut tx) = self.in_flight_write.take() else {
            return;
        };
        tx.terminator = terminator;
        if raw_pw.is_some_and(|p| decode_b64_utf8(p, MAX_PW_LEN).is_none())
            || raw_name.is_some_and(|n| decode_b64_utf8(n, MAX_MIME_LEN).is_none())
        {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }

        // A wdata packet without mime (or with empty mime) commits the transaction.
        let mime = match raw_mime {
            None | Some("") => None,
            Some(raw) => match decode_b64_utf8(raw, MAX_MIME_LEN) {
                Some(m) if !m.is_empty() => Some(m),
                _ => {
                    Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                    return;
                }
            },
        };

        let Some(mime) = mime else {
            if !payload_bytes.is_empty() {
                Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                return;
            }
            // Finalize any remaining buffered base64 streams.
            for (pending_mime, buf) in tx.pending_b64.drain() {
                if buf.is_empty() {
                    continue;
                }
                let Ok(decoded) = B64.decode(&buf) else {
                    Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                    return;
                };
                if !Self::append_write_bytes(&mut tx, &pending_mime, &decoded) {
                    Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                    return;
                }
            }
            // Expand aliases that point to an existing source MIME.
            for (src_mime, dst_mime) in &tx.aliases {
                if tx.entries.iter().any(|(m, _)| m == dst_mime) {
                    continue;
                }
                if let Some((_, data)) = tx.entries.iter().find(|(m, _)| m == src_mime).cloned() {
                    tx.entries.push((dst_mime.clone(), data));
                }
            }
            let text = tx
                .entries
                .iter()
                .find(|(m, _)| m == "text/plain" || m == "text/plain;charset=utf-8")
                .and_then(|(_, data)| String::from_utf8(data.clone()).ok());
            let contents = tx
                .entries
                .into_iter()
                .map(|(mime, data)| KittyClipboardContent { mime, data })
                .collect();
            effects.kitty_clipboard_writes.push(KittyClipboardWriteCommit {
                primary: tx.primary,
                contents,
                text,
            });
            effects.pty_write.push(encode_status_packet(
                KittyClipboardOperation::Write,
                KittyClipboardStatus::Done,
                false,
                &tx.id,
                tx.terminator,
            ));
            return;
        };

        // Validate base64 alphabet strictly before buffering.
        if !payload_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }

        let buf = tx.pending_b64.entry(mime.clone()).or_default();
        buf.extend_from_slice(payload_bytes);

        // Decode completed 4-byte base64 groups or padded endings immediately.
        let ends_with_padding = buf.ends_with(b"=");
        let decode_len = if ends_with_padding {
            buf.len()
        } else {
            buf.len() / 4 * 4
        };
        if decode_len > 0 {
            let chunk: Vec<u8> = buf.drain(..decode_len).collect();
            let Ok(decoded) = B64.decode(&chunk) else {
                Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                return;
            };
            if !Self::append_write_bytes(&mut tx, &mime, &decoded) {
                Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
                return;
            }
        } else if !Self::ensure_write_mime_slot(&mut tx, &mime) {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }

        self.in_flight_write = Some(tx);
    }

    fn handle_walias(
        &mut self,
        raw_mime: Option<&str>,
        raw_pw: Option<&str>,
        raw_name: Option<&str>,
        payload_bytes: &[u8],
        terminator: KittyClipboardTerminator,
        effects: &mut TerminalEffects,
    ) {
        let Some(mut tx) = self.in_flight_write.take() else {
            return;
        };
        tx.terminator = terminator;
        if raw_pw.is_some_and(|p| decode_b64_utf8(p, MAX_PW_LEN).is_none())
            || raw_name.is_some_and(|n| decode_b64_utf8(n, MAX_MIME_LEN).is_none())
        {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }
        let Some(src_mime) = raw_mime.and_then(|m| decode_b64_utf8(m, MAX_MIME_LEN)) else {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        };
        if src_mime.is_empty() || payload_bytes.is_empty() {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }
        let Ok(decoded_target) = B64.decode(payload_bytes) else {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        };
        let Ok(dst_mime) = String::from_utf8(decoded_target) else {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        };
        if dst_mime.is_empty() || dst_mime.len() > MAX_MIME_LEN || tx.aliases.len() >= MAX_WRITE_ALIASES {
            Self::abort_write(&tx, KittyClipboardStatus::Einval, effects);
            return;
        }
        tx.aliases.push((src_mime, dst_mime));
        self.in_flight_write = Some(tx);
    }

    fn ensure_write_mime_slot(tx: &mut WriteTransaction, mime: &str) -> bool {
        if tx.entries.iter().any(|(m, _)| m == mime) {
            return true;
        }
        if tx.entries.len() >= MAX_WRITE_MIMES {
            return false;
        }
        tx.entries.push((mime.to_string(), Vec::new()));
        true
    }

    fn append_write_bytes(tx: &mut WriteTransaction, mime: &str, bytes: &[u8]) -> bool {
        if tx.total_bytes.saturating_add(bytes.len()) > MAX_WRITE_SIZE {
            return false;
        }
        if !Self::ensure_write_mime_slot(tx, mime) {
            return false;
        }
        tx.total_bytes += bytes.len();
        let (_, slot) = tx
            .entries
            .iter_mut()
            .find(|(m, _)| m == mime)
            .expect("slot ensured above");
        slot.extend_from_slice(bytes);
        true
    }

    fn abort_write(
        tx: &WriteTransaction,
        status: KittyClipboardStatus,
        effects: &mut TerminalEffects,
    ) {
        effects.pty_write.push(encode_status_packet(
            KittyClipboardOperation::Write,
            status,
            false,
            &tx.id,
            tx.terminator,
        ));
    }
}

fn decode_b64_utf8(encoded: &str, max_len: usize) -> Option<String> {
    let bytes = B64.decode(encoded.as_bytes()).ok()?;
    if bytes.len() > max_len {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paste_event_matches_ghostty_wire_format() {
        let packet = encode_paste_event(
            "otp",
            &["text/plain", "image/png"],
            false,
            KittyClipboardTerminator::St,
        );
        assert_eq!(
            std::str::from_utf8(&packet).unwrap(),
            "\x1b]5522;type=read:status=OK:pw=b3Rw\x1b\\\
             \x1b]5522;type=read:status=DATA:mime=Lg==:pw=b3Rw;dGV4dC9wbGFpbiBpbWFnZS9wbmcK\x1b\\\
             \x1b]5522;type=read:status=DONE:pw=b3Rw\x1b\\"
        );
    }

    #[test]
    fn read_success_chunks_large_payloads_at_4096_bytes() {
        let req = KittyClipboardReadRequest {
            id: "42".into(),
            primary: false,
            pw: Some("otp".into()),
            list_targets: false,
            requested_mimes: vec!["image/png".into()],
            terminator: KittyClipboardTerminator::St,
        };
        let data = vec![b'z'; READ_CHUNK_SIZE + 1];
        let encoded = encode_read_success(
            &req,
            &["image/png"],
            &[KittyClipboardContent {
                mime: "image/png".into(),
                data,
            }],
        );
        let text = std::str::from_utf8(&encoded).unwrap();
        assert_eq!(text.matches("\x1b]5522;").count(), 4);
        assert!(text.starts_with("\x1b]5522;type=read:status=OK:id=42\x1b\\"));
        assert!(text.ends_with("\x1b]5522;type=read:status=DONE:id=42\x1b\\"));
    }

    #[test]
    fn read_request_parses_targets_and_mimes_with_otp() {
        let mut state = KittyClipboardState::default();
        let mut effects = TerminalEffects::default();
        // base64("otp") = "b3Rw", base64(". image/png text/plain") = "LiBpbWFnZS9wbmcgdGV4dC9wbGFpbg=="
        state.handle_osc(
            b"type=read:id=req-1:pw=b3Rw;LiBpbWFnZS9wbmcgdGV4dC9wbGFpbg==",
            false,
            &mut effects,
        );
        assert_eq!(effects.kitty_clipboard_reads.len(), 1);
        let req = &effects.kitty_clipboard_reads[0];
        assert_eq!(req.id, "req-1");
        assert_eq!(req.pw.as_deref(), Some("otp"));
        assert!(req.list_targets);
        assert_eq!(req.requested_mimes, vec!["image/png", "text/plain"]);
    }

    #[test]
    fn write_transaction_commits_text_and_binary_representations() {
        let mut state = KittyClipboardState::default();
        let mut effects = TerminalEffects::default();
        state.handle_osc(b"type=write:id=w1", false, &mut effects);
        assert_eq!(
            effects.pty_write.pop().as_deref(),
            Some(b"\x1b]5522;type=write:status=OK:id=w1\x1b\\".as_slice())
        );
        // mime="text/plain" -> dGV4dC9wbGFpbg==, payload="hello" -> aGVsbG8=
        state.handle_osc(
            b"type=wdata:mime=dGV4dC9wbGFpbg==;aGVsbG8=",
            false,
            &mut effects,
        );
        // commit with empty wdata
        state.handle_osc(b"type=wdata", false, &mut effects);
        assert_eq!(
            effects.pty_write.pop().as_deref(),
            Some(b"\x1b]5522;type=write:status=DONE:id=w1\x1b\\".as_slice())
        );
        assert_eq!(effects.kitty_clipboard_writes.len(), 1);
        assert_eq!(
            effects.kitty_clipboard_writes[0].text.as_deref(),
            Some("hello")
        );
    }
}
