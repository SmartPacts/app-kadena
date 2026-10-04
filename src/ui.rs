//! Screens. NBGL on every device (Nano included, through `nano_nbgl`).
//!
//! Screen text follows the C app (zxlib `view_nbgl.c`); the review content
//! (titles, values, order) comes from `kadena_core` and is the C app's.

use alloc::string::String;
use alloc::vec::Vec;

use kadena_core::app::{path_to_str, App, Platform};
use kadena_core::items::{TITLE_BUF, VALUE_BUF};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{
    Field, NbglAddressReview, NbglChoice, NbglGlyph, NbglHomeAndSettings, NbglReviewStatus,
    NbglStreamingReview, StatusType,
};

use crate::settings;

#[cfg(target_os = "apex_p")]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/icon_apex_p_48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/kadena_64px.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/nanox_icon.gif", NBGL));

/// Heap budget of one streaming step, so that a large transaction never needs
/// all its items in RAM at once. Counted on the screen fields as shown: the text
/// after `\xNN` escaping (up to 4 characters per value byte) and, on Nano, after
/// paging, plus `FIELD_OVERHEAD` per field. An item that would exceed the budget
/// waits for the next step, so a step holds this much, or one item alone. The
/// heap is 8 KiB on every device; the heap-probe build measures the largest
/// review the app accepts, with printable and with non-printable values (see
/// submission/SECURITY-AUDIT.md).
const BATCH_BYTES: usize = 1200;
/// Per screen field: the `String` and `CString` headers and allocator blocks of
/// the field and of the SDK's copy of it.
const FIELD_OVERHEAD: usize = 32;
/// Items per streaming step.
const BATCH_ITEMS: usize = 16;

pub fn home() -> NbglHomeAndSettings {
    let switches = [
        ["Blind signing", "Enable transaction blind signing."],
        ["Expert mode", "Enable to review extra fields."],
    ];
    let home = NbglHomeAndSettings::new()
        .glyph(&GLYPH)
        .settings(settings::storage(), &switches)
        .infos(
            "Kadena",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        );
    // The C app's home text on touch screens. Nano keeps the SDK default
    // ("Kadena" / "app is ready"): the long text does not fit a Nano page.
    #[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
    let home =
        home.tagline("This application enables\nsigning transactions on the\nKadena network");
    home
}

/// Screen text for a value (V13): printable ASCII as is, every other byte as
/// `\xNN`, on every device (see `kadena_core::display`).
fn display_text(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    kadena_core::display::escape(bytes, |piece| {
        // Printable ASCII only, by construction.
        s.push_str(core::str::from_utf8(piece).unwrap_or(""));
    });
    s
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Address review (C: REVIEW_ADDRESS): the 64-hex public key; expert mode adds
/// "Your Path".
pub fn review_address<const T: usize, P: Platform>(comm: &mut Comm, app: &App<T>, p: &P) -> bool {
    let Some(pk) = app.address_review() else {
        return false;
    };
    let address = hex(&pk);
    let mut path_buf = [0u8; 64];
    let n = path_to_str(&app.hd_path(), &mut path_buf);
    let path = core::str::from_utf8(&path_buf[..n]).unwrap_or("");
    let extra = [Field {
        name: "Your Path",
        value: path,
    }];
    let mut review = NbglAddressReview::new()
        .glyph(&GLYPH)
        .review_title("Verify Kadena\naddress");
    if p.expert() {
        review = review.set_tag_value_list(&extra);
    }
    review.show(comm, &address)
}

/// Renders review items `from..` into owned strings, up to the batch budget.
/// Renders review items `from..` into screen fields, up to the batch budget.
/// Returns the fields and the number of review items they cover.
fn batch<const T: usize, P: Platform>(
    app: &App<T>,
    p: &P,
    from: usize,
) -> Option<(Vec<(String, String)>, usize)> {
    let mut out = Vec::new();
    let mut bytes = 0;
    let mut title = [0u8; TITLE_BUF];
    let mut value = [0u8; VALUE_BUF];
    let mut i = from;
    while i < app.review_len() && out.len() < BATCH_ITEMS {
        let (tl, vl) = app.review_item(p, i, &mut title, &mut value).ok()?;
        let mut fields = Vec::new();
        screen_fields(
            display_text(&title[..tl]),
            display_text(&value[..vl]),
            &mut fields,
        );
        // The rendered size (R2-3): escaping can make it 4 times the raw one.
        let cost: usize = fields
            .iter()
            .map(|(t, v)| t.len() + v.len() + FIELD_OVERHEAD)
            .sum();
        #[cfg(feature = "heap-probe")]
        probe::sample();
        if !out.is_empty() && bytes + cost > BATCH_BYTES {
            break;
        }
        bytes += cost;
        out.append(&mut fields);
        i += 1;
    }
    Some((out, i - from))
}

/// Touch screens show a title and its whole value (the SDK flows scroll).
#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
fn screen_fields(title: String, value: String, out: &mut Vec<(String, String)>) {
    out.push((title, value));
}

/// Nano screens: NBGL draws the title on one line and, when the value needs more
/// than one page, appends "(i/n)" and shortens the title with "..." to fit
/// (nbgl_step.c). A warning title must never be shortened, so the app pages the
/// value itself, with NBGL's own text measurement, so that NBGL never does:
/// each page is a field whose value fits one page, titled "Title (i/n)" when
/// that fits one line, else "Title" with "(i/n)" as the value's first line. A
/// title too wide for one line on its own continues on the first value line.
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
fn screen_fields(title: String, value: String, out: &mut Vec<(String, String)>) {
    use alloc::format;
    // A value without spaces (key, account, hash, namespace) is cut into lines
    // at the display width: NBGL would otherwise break such a run at some
    // punctuation ("n_" alone on a line), and a 42-character namespace would
    // spill onto a second page.
    let value = if value.contains(' ') || value.contains('\n') {
        value
    } else {
        nano::hard_wrap(&value)
    };
    let vl = nano::VALUE_LINES;
    let (head, tail) = nano::split_title(&title);
    // One page.
    let single = match &tail {
        Some(t) => format!("{t}\n{value}"),
        None => String::new(),
    };
    let single_text = if tail.is_some() { &single } else { &value };
    if nano::fits_one_page(single_text, vl) {
        let v = if tail.is_some() { single } else { value };
        out.push((head, v));
        return;
    }
    // Several pages, "Title (i/n)" when that fits one line.
    if tail.is_none() {
        let pages = nano::pages(&value, vl);
        let n = pages.len();
        if (1..=n).all(|i| nano::title_fits(&format!("{head} ({i}/{n})"))) {
            for (i, pg) in pages.into_iter().enumerate() {
                out.push((format!("{head} ({}/{n})", i + 1), pg));
            }
            return;
        }
    }
    // Otherwise the first value line of each page carries the rest of the
    // title (if any) and "(i/n)"; pages get fewer value lines until every page
    // fits one screen.
    for lines in (1..vl).rev() {
        let pages = nano::pages(&value, lines);
        let n = pages.len();
        let texts: Vec<String> = pages
            .iter()
            .enumerate()
            .map(|(i, pg)| match &tail {
                Some(t) => format!("{t} ({}/{n})\n{pg}", i + 1),
                None => format!("({}/{n})\n{pg}", i + 1),
            })
            .collect();
        if texts.iter().all(|t| nano::fits_one_page(t, vl)) {
            for t in texts {
                out.push((head.clone(), t));
            }
            return;
        }
    }
    // No layout with a page marker fits (not reached with the app's titles):
    // one field per page, each value on a single page, so NBGL never adds
    // "(i/n)" and never shortens the title (F9).
    let v = if tail.is_some() { single } else { value };
    for pg in nano::pages(&v, vl) {
        out.push((head.clone(), pg));
    }
}

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
mod nano {
    use alloc::ffi::CString;
    use alloc::string::String;
    use alloc::vec::Vec;
    use ledger_device_sdk::sys;

    /// Value lines on a review page (the title takes the first of NB_MAX_LINES).
    pub const VALUE_LINES: u16 = sys::NB_MAX_LINES as u16 - 1;
    const WIDTH: u16 = sys::AVAILABLE_WIDTH as u16;

    fn cstr(s: &str) -> CString {
        CString::new(s.replace('\0', " ")).unwrap_or_default()
    }

    /// Bytes of text measured at a time: a page of at most NB_MAX_LINES lines
    /// of AVAILABLE_WIDTH pixels holds far fewer. Measuring a window, not the
    /// whole rest of a value, keeps paging from copying long values (R2-3).
    const WINDOW: usize = 256;

    /// How many bytes of `text` NBGL puts on a page of `lines` lines.
    fn page_len(text: &str, lines: u16) -> usize {
        measure(text, lines, true)
    }

    /// `text` with a line break wherever a line of the display is full.
    pub fn hard_wrap(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + text.len() / 8 + 1);
        let mut rest = text;
        while !rest.is_empty() {
            let mut len = measure(rest, 1, false);
            while len > 0 && !rest.is_char_boundary(len) {
                len -= 1;
            }
            if len == 0 {
                len = rest
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(rest.len());
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&rest[..len]);
            rest = &rest[len..];
        }
        out
    }

    /// How many bytes of `text` fit `lines` lines, NBGL breaking lines at its
    /// word boundaries (`wrapping`) or wherever a line is full.
    fn measure(text: &str, lines: u16, wrapping: bool) -> usize {
        let n = text.len().min(WINDOW);
        let mut buf = [0u8; WINDOW + 1];
        for (d, b) in buf.iter_mut().zip(&text.as_bytes()[..n]) {
            *d = if *b == 0 { b' ' } else { *b };
        }
        let mut len: u16 = 0;
        // SAFETY: `buf` is NUL-terminated (buf[n] == 0); `len` is an out parameter.
        unsafe {
            sys::nbgl_getTextMaxLenInNbLines(
                sys::BAGL_FONT_OPEN_SANS_REGULAR_11px_1bpp,
                buf.as_ptr() as *const core::ffi::c_char,
                WIDTH,
                lines,
                &mut len,
                wrapping,
            );
        }
        (len as usize).min(n)
    }

    /// Whether the whole of `text` fits one page of `lines` lines.
    pub fn fits_one_page(text: &str, lines: u16) -> bool {
        text.len() <= WINDOW && page_len(text, lines) >= text.len()
    }

    /// Whether NBGL draws `t` as a title without shortening it.
    pub fn title_fits(t: &str) -> bool {
        let c = cstr(t);
        // SAFETY: NUL-terminated string, read only.
        let lines = unsafe {
            sys::nbgl_getTextNbLinesInWidth(
                sys::BAGL_FONT_OPEN_SANS_EXTRABOLD_11px_1bpp,
                c.as_ptr(),
                WIDTH,
                false,
            )
        };
        lines <= 1
    }

    /// Splits a title that does not fit one line at the last space that fits
    /// (or at the last character that fits); returns (title line, rest).
    pub fn split_title(t: &str) -> (String, Option<String>) {
        if title_fits(t) {
            return (String::from(t), None);
        }
        let mut cut = 0;
        for (i, ch) in t.char_indices() {
            let end = i + ch.len_utf8();
            if !title_fits(&t[..end]) {
                break;
            }
            cut = end;
        }
        if let Some(sp) = t[..cut].rfind(' ') {
            if sp > 0 {
                cut = sp;
            }
        }
        if cut == 0 {
            return (String::from(t), None);
        }
        (
            String::from(&t[..cut]),
            Some(String::from(t[cut..].trim_start())),
        )
    }

    /// Cuts `text` into pieces of at most `lines` lines each, exactly where
    /// NBGL would start a new page (nbgl_step.c getTextPageAt).
    pub fn pages(text: &str, lines: u16) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            let mut len = page_len(rest, lines);
            while len > 0 && !rest.is_char_boundary(len) {
                len -= 1;
            }
            if len == 0 {
                // Never loop: take one character.
                len = rest
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(rest.len());
            }
            // NBGL measures a break space as part of the line, but draws a
            // page's trailing spaces on a line of their own, which pages the
            // field again ("Title (1/2)" and an empty "(2/2)"). A page break
            // is a line break: like NBGL at every line wrap, it takes the one
            // space it breaks at; any further spaces start the next page.
            let mut take = len;
            while take < rest.len() && take > 1 && rest.as_bytes()[take - 1] == b' ' {
                take -= 1;
            }
            #[cfg(feature = "heap-probe")]
            super::probe::sample();
            out.push(String::from(&rest[..take]));
            rest = &rest[take..];
            if take < len {
                rest = &rest[1..];
            }
            if let Some(r) = rest.strip_prefix('\n') {
                rest = r;
            }
        }
        out
    }
}

/// Transaction review. Returns true if the user signs. A blind-signing review
/// (hash signing, and V11 JSON) starts with Ledger's blind-signing warning; both
/// kinds show every item, batch after batch (F7).
pub fn review_tx<const T: usize, P: Platform>(
    _comm: &mut Comm,
    app: &App<T>,
    p: &P,
    blind: bool,
) -> bool {
    let mut review = NbglStreamingReview::new().glyph(&GLYPH);
    if blind {
        review = review.blind();
    }
    if !review.start("Review transaction", None) {
        return false;
    }
    let mut next = 0;
    while next < app.review_len() {
        let Some((items, used)) = batch(app, p, next) else {
            return false;
        };
        next += used;
        let fields: Vec<Field> = items
            .iter()
            .map(|(t, v)| Field {
                name: t.as_str(),
                value: v.as_str(),
            })
            .collect();
        #[cfg(feature = "heap-probe")]
        probe::sample_sdk_copy(&fields);
        // `continue_review`, not `next`: `next` lets the user skip the rest of
        // the review (on Nano a "press both to skip" page follows the items),
        // which the C app never offered. The SDK marks it deprecated only in
        // favour of that skippable variant.
        #[allow(deprecated)]
        if !review.continue_review(&fields) {
            return false;
        }
    }
    review.finish(if blind {
        "Accept risk and sign transaction?"
    } else {
        "Sign transaction?"
    })
}

/// Heap measurement build only (`--features heap-probe`, never shipped): records
/// the largest heap use seen during reviews, measured as the heap size minus the
/// largest block that can still be allocated, and answers it on INS 0xFE.
#[cfg(feature = "heap-probe")]
pub mod probe {
    use alloc::alloc::{alloc, dealloc, Layout};
    use alloc::ffi::CString;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use ledger_device_sdk::nbgl::Field;
    use ledger_device_sdk::sys;

    struct Max(Cell<usize>);
    // SAFETY: the device runs one thread.
    unsafe impl Sync for Max {}
    // Zero-initialised: the app may not have a `.data` section.
    static MAX_USED: Max = Max(Cell::new(0));

    /// Largest block the allocator can hand out now (binary search).
    pub fn sample() {
        let (mut lo, mut hi) = (0usize, sys::HEAP_SIZE);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            let l = Layout::from_size_align(mid, 4).unwrap();
            // SAFETY: non-zero size; freed at once with the same layout. The
            // black box keeps the compiler from eliding the pair.
            let ptr = core::hint::black_box(unsafe { alloc(l) });
            if ptr.is_null() {
                hi = mid - 1;
            } else {
                unsafe { dealloc(ptr, l) };
                lo = mid;
            }
        }
        MAX_USED.0.set(MAX_USED.0.get().max(sys::HEAP_SIZE - lo));
    }

    /// The copies `continue_review` makes of a batch before it blocks on the
    /// screen (SDK nbgl_streaming_review.rs:209-246), then a sample.
    pub fn sample_sdk_copy(fields: &[Field]) {
        let copies: Vec<(CString, CString)> = fields
            .iter()
            .map(|f| {
                (
                    CString::new(f.name).unwrap_or_default(),
                    CString::new(f.value).unwrap_or_default(),
                )
            })
            .collect();
        let mut pairs: Vec<sys::nbgl_contentTagValue_t> = Vec::new();
        for _ in copies.iter() {
            pairs.push(sys::nbgl_contentTagValue_t::default());
        }
        sample();
        drop(pairs);
        drop(copies);
    }

    /// (heap size, largest use since the last call).
    pub fn take() -> (usize, usize) {
        (sys::HEAP_SIZE, MAX_USED.0.replace(0))
    }
}

/// C: `view_blindsign_error_show`. Returns true if the user chose "Go to settings".
/// The title fits one Nano line, so NBGL never shortens it.
pub fn blind_signing_required(comm: &mut Comm) -> bool {
    NbglChoice::new().glyph(&GLYPH).show(
        comm,
        "Cannot clear-sign",
        "Enable Blind signing in Settings to sign this transaction",
        "Go to settings",
        "Reject Transaction",
    )
}

pub fn status(comm: &mut Comm, address: bool, success: bool) {
    let kind = if address {
        StatusType::Address
    } else {
        StatusType::Transaction
    };
    NbglReviewStatus::new()
        .status_type(kind)
        .show(comm, success);
}
