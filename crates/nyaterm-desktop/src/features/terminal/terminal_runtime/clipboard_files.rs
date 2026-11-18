use crate::features::{NyaTermApp, runtime_jobs::await_blocking_job};
use crate::models::{
    TransferJobEvent, TransferJobKind, TransferJobOutput, TransferJobResult, TransferJobState,
    TransferJobStatus,
};
use gpui::{ClipboardEntry, ClipboardItem, Context, Image};
use nyaterm_files::file_browser::FileBrowserService;
use nyaterm_files::sftp::SftpTransferControl;
use nyaterm_terminal::kitty_clipboard::{KittyClipboardContent, KittyClipboardReadRequest};
use std::path::Path;

const MAX_CLIPBOARD_IMAGE_BYTES: usize = 32 * 1024 * 1024;

impl NyaTermApp {
    pub(super) fn paste_clipboard_image(&mut self, image: Image, cx: &mut Context<Self>) {
        self.paste_clipboard_image_bytes(image.format.extension(), image.bytes, cx);
    }

    pub(super) fn paste_clipboard_image_bytes(
        &mut self,
        extension: &str,
        bytes: Vec<u8>,
        cx: &mut Context<Self>,
    ) {
        let Some(session_id) = self.session.active_id_owned() else {
            return;
        };
        let service = match self.file_browser_service_for_session(&session_id) {
            Ok(service) => service,
            Err(_) => {
                self.clipboard_image_failure(cx);
                return;
            }
        };
        let local = matches!(service, FileBrowserService::Local(_));
        let cwd = self.session.cwd(&session_id).map(str::to_owned);
        let options = self.sftp_transfer_options();
        let name = format!("nyaterm-clipboard-{}.{}", nyaterm_core::uuid(), extension);
        let local_path = std::env::temp_dir().join(&name);
        let control = SftpTransferControl::new();
        let id = self.transfer.next_transfer_job_id("clipboard-image");
        if !local {
            self.transfer.enqueue_transfer_job(TransferJobState {
                source_type: None,
                id: id.clone(),
                session_id: Some(session_id.clone()),
                kind: TransferJobKind::Upload {
                    local_path: local_path.clone(),
                    remote_path: name.clone(),
                },
                status: TransferJobStatus::Running,
                detail: rust_i18n::t!("terminal.uploadingClipboardImage").to_string(),
                created_at_ms: TransferJobState::now_ms(),
                display_name: name.clone(),
                entries: Vec::new(),
                summary: None,
                progress: None,
                control: Some(control.clone()),
                speed: Default::default(),
            });
        }
        let progress_tx = self.transfer.transfer_event_sender();
        let finish_tx = progress_tx.clone();
        let progress_id = id.clone();
        let worker_control = control.clone();
        let jobs = self.blocking_jobs.clone();
        cx.spawn(async move |this, cx| {
            let result = await_blocking_job(jobs.submit_task("clipboard-image", move |_| {
                if bytes.len() > MAX_CLIPBOARD_IMAGE_BYTES {
                    return Err("clipboard image is too large".to_string());
                }
                std::fs::write(&local_path, &bytes)
                    .map_err(|_| "cannot write clipboard image")?;
                if let FileBrowserService::Remote(service) = service {
                    let result = (|| {
                        worker_control
                            .check_cancelled()
                            .map_err(|error| error.to_string())?;
                        let directory = match cwd {
                            Some(cwd) => cwd,
                            None => service.home_dir().map_err(|error| error.to_string())?,
                        };
                        let remote_path = format!("{}/{}", directory.trim_end_matches('/'), name);
                        let summary = service
                            .upload_file_with_progress_and_control_options(
                                local_path.clone(),
                                &remote_path,
                                worker_control,
                                options,
                                move |progress| {
                                    let _ = progress_tx.unbounded_send(TransferJobResult {
                                        id: progress_id.clone(),
                                        event: TransferJobEvent::Progress(progress),
                                    });
                                },
                            )
                            .map_err(|error| error.to_string())?;
                        Ok::<_, String>((remote_path, Some(summary)))
                    })();
                    let _ = std::fs::remove_file(local_path);
                    result
                } else {
                    Ok((local_path.to_string_lossy().into_owned(), None))
                }
            }))
            .await
            .and_then(|result| result);
            let _ = this.update(cx, |app, cx| {
                match result {
                    Ok((path, summary)) => {
                        if let Some(summary) = summary {
                            let _ = finish_tx.unbounded_send(TransferJobResult {
                                id,
                                event: TransferJobEvent::Finished(Ok(TransferJobOutput::Summary(
                                    summary,
                                ))),
                            });
                        }
                        if !control.is_cancelled()
                            && app.session.has_session(&session_id)
                            && !app.session.is_disconnected(&session_id)
                        {
                            let quoted = if local {
                                nyaterm_core::terminal::file_drop::quote_local_path(&path)
                            } else {
                                format!("'{}'", path.replace('\'', "'\\''"))
                            };
                            app.send_terminal_paste_input_to_session(session_id, &quoted, cx);
                        }
                    }
                    Err(error) => {
                        if !local {
                            let _ = finish_tx.unbounded_send(TransferJobResult {
                                id,
                                event: TransferJobEvent::Finished(Err(error)),
                            });
                        }
                        if !control.is_cancelled() {
                            app.clipboard_image_failure(cx);
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn clipboard_image_failure(&self, cx: &mut Context<Self>) {
        self.notify_background_operation(
            "clipboard-image",
            nyaterm_ui::notification::NyaNotificationKind::Error,
            rust_i18n::t!("terminal.clipboardImageFailed").to_string(),
            cx,
        );
    }
}

/// Map a file extension to an image `(extension, mime_type)` pair when recognized.
pub(in crate::features) fn image_extension_and_mime(path: &Path) -> Option<(&'static str, &'static str)> {
    let ext = path.extension()?.to_str()?;
    if ext.eq_ignore_ascii_case("png") {
        Some(("png", "image/png"))
    } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
        Some(("jpg", "image/jpeg"))
    } else if ext.eq_ignore_ascii_case("webp") {
        Some(("webp", "image/webp"))
    } else if ext.eq_ignore_ascii_case("gif") {
        Some(("gif", "image/gif"))
    } else if ext.eq_ignore_ascii_case("svg") {
        Some(("svg", "image/svg+xml"))
    } else if ext.eq_ignore_ascii_case("bmp") {
        Some(("bmp", "image/bmp"))
    } else if ext.eq_ignore_ascii_case("tif") || ext.eq_ignore_ascii_case("tiff") {
        Some(("tiff", "image/tiff"))
    } else if ext.eq_ignore_ascii_case("ico") {
        Some(("ico", "image/ico"))
    } else {
        None
    }
}

/// Read a single local image file from `paths` when bounded by [`MAX_CLIPBOARD_IMAGE_BYTES`].
pub(in crate::features) fn read_single_clipboard_image_file(
    paths: &[std::path::PathBuf],
) -> Option<(&'static str, &'static str, Vec<u8>)> {
    if paths.len() != 1 {
        return None;
    }
    let path = &paths[0];
    let (ext, mime) = image_extension_and_mime(path)?;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CLIPBOARD_IMAGE_BYTES as u64 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some((ext, mime, bytes))
}

/// Inspect available MIME types on a GPUI [`ClipboardItem`] for Kitty `OSC 5522`.
///
/// Mirrors Ghostty's `NSPasteboard.ghosttyAvailableMimes()`:
/// - Plain text and copied files expose `text/plain`.
/// - Copied files additionally expose `text/uri-list`.
/// - Image entries (or a copied image file) expose their image MIME type (`image/png`, etc.).
pub(in crate::features) fn clipboard_available_kitty_mimes(
    clipboard: Option<&ClipboardItem>,
) -> Vec<String> {
    let Some(clipboard) = clipboard else {
        return Vec::new();
    };
    let mut mimes = Vec::new();
    let mut push_unique = |mime: &str| {
        if !mimes.iter().any(|existing| existing == mime) {
            mimes.push(mime.to_string());
        }
    };

    let has_paths = clipboard
        .entries()
        .iter()
        .any(|entry| matches!(entry, ClipboardEntry::ExternalPaths(p) if !p.paths().is_empty()));
    let has_string = clipboard
        .entries()
        .iter()
        .any(|entry| matches!(entry, ClipboardEntry::String(_)));

    if has_paths || has_string {
        push_unique("text/plain");
    }
    if has_paths {
        push_unique("text/uri-list");
    }
    for entry in clipboard.entries() {
        match entry {
            ClipboardEntry::Image(image) => {
                push_unique(image.format.mime_type());
            }
            ClipboardEntry::ExternalPaths(paths) => {
                if paths.paths().len() == 1
                    && let Some((_, mime)) = image_extension_and_mime(&paths.paths()[0])
                {
                    push_unique(mime);
                }
            }
            ClipboardEntry::String(_) => {}
        }
    }
    mimes
}

/// Serve requested MIME representations from a GPUI [`ClipboardItem`] for Kitty `OSC 5522`.
///
/// Mirrors Ghostty's `NSPasteboard.ghosttyData(forMime:)`:
/// - `text/plain` returns shell-escaped paths when files are copied, or the string content.
/// - `text/uri-list` returns `file://` URIs separated by `\r\n`.
/// - `image/*` returns raw image bytes from [`ClipboardEntry::Image`] or a copied image file.
pub(in crate::features) fn clipboard_kitty_contents_for_request(
    clipboard: Option<&ClipboardItem>,
    req: &KittyClipboardReadRequest,
) -> Vec<KittyClipboardContent> {
    let Some(clipboard) = clipboard else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for mime in &req.requested_mimes {
        if let Some(data) = clipboard_data_for_mime(clipboard, mime)
            && !data.is_empty()
        {
            out.push(KittyClipboardContent {
                mime: mime.clone(),
                data,
            });
        }
    }
    out
}

fn clipboard_data_for_mime(clipboard: &ClipboardItem, mime: &str) -> Option<Vec<u8>> {
    match mime {
        "text/plain" | "text/plain;charset=utf-8" => {
            if let Some(paths) = clipboard.entries().iter().find_map(|entry| match entry {
                ClipboardEntry::ExternalPaths(paths) if !paths.paths().is_empty() => Some(paths),
                _ => None,
            }) {
                let strings: Vec<String> = paths
                    .paths()
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                let formatted = nyaterm_core::format_local_terminal_drop_input(&strings);
                return Some(formatted.into_bytes());
            }
            clipboard.text().map(String::into_bytes)
        }
        "text/uri-list" => {
            let paths = clipboard.entries().iter().find_map(|entry| match entry {
                ClipboardEntry::ExternalPaths(paths) if !paths.paths().is_empty() => Some(paths),
                _ => None,
            })?;
            let mut uri_list = String::new();
            for path in paths.paths() {
                if let Ok(url) = url::Url::from_file_path(path) {
                    uri_list.push_str(url.as_str());
                    uri_list.push_str("\r\n");
                }
            }
            (!uri_list.is_empty()).then(|| uri_list.into_bytes())
        }
        _ => {
            for entry in clipboard.entries() {
                if let ClipboardEntry::Image(image) = entry
                    && image.format.mime_type().eq_ignore_ascii_case(mime)
                {
                    return Some(image.bytes.clone());
                }
            }
            for entry in clipboard.entries() {
                if let ClipboardEntry::ExternalPaths(paths) = entry
                    && let Some((_, file_mime, bytes)) =
                        read_single_clipboard_image_file(paths.paths())
                    && file_mime.eq_ignore_ascii_case(mime)
                {
                    return Some(bytes);
                }
            }
            None
        }
    }
}
