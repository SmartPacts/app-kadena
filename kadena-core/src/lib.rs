//! Device-independent logic of the Kadena Ledger app.
//!
//! This crate is the whole protocol: APDU dispatch and chunk reassembly for both
//! command families, the JSON tokenizer and lookups, the review items, and the
//! structured-transfer template. It has no unsafe code and no heap allocation,
//! and it runs unchanged on the device and in host tests. The device crate
//! supplies key derivation, signing, hashing, flash storage and the screens
//! through [`app::Platform`].
//!
//! The behaviour follows the C implementation of the app (v1.3.0) line by line;
//! each module names the C source it was ported from.

#![no_std]
#![forbid(unsafe_code)]

pub mod app;
pub mod buffering;
pub mod display;
pub mod error;
pub mod fee;
pub mod items;
pub mod jsmn;
pub mod json;
pub mod parser;
pub mod principal;
pub mod sw;
pub mod transfer;
