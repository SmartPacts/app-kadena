/*****************************************************************************
 *   Kadena app for Ledger devices.
 *   (c) 2026 Smart Pacts.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#![no_std]
#![no_main]

extern crate alloc;

mod platform;
mod settings;
mod storage;
mod ui;

use core::cell::UnsafeCell;

use kadena_core::app::{Action, App, Reply};
use kadena_core::parser::MAX_TOKENS;
use ledger_device_sdk::io::{init_comm, ApduHeader, Comm, Reply as IoReply, StatusWords};
use ledger_device_sdk::nbgl::PageIndex;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut v: u16 = 0;
    let mut i = 0;
    while i < b.len() {
        v = v * 10 + (b[i] - b'0') as u16;
        i += 1;
    }
    v
}

/// (major, minor, patch) from Cargo.toml.
pub const VERSION: [u16; 3] = [
    parse_u16(env!("CARGO_PKG_VERSION_MAJOR")),
    parse_u16(env!("CARGO_PKG_VERSION_MINOR")),
    parse_u16(env!("CARGO_PKG_VERSION_PATCH")),
];

/// The APDU header, taken as-is: CLA filtering and INS dispatch are done by
/// `kadena_core` exactly as the C app does them.
struct Header(ApduHeader);

impl TryFrom<ApduHeader> for Header {
    type Error = StatusWords;
    fn try_from(h: ApduHeader) -> Result<Self, StatusWords> {
        Ok(Header(h))
    }
}

/// App state in `.bss` (it is all zero initially; the device link script
/// forbids a `.data` section).
struct AppCell(UnsafeCell<App<MAX_TOKENS>>);

// SAFETY: the device runs one thread; the cell is borrowed exactly once, in
// `sample_main`, which never returns.
unsafe impl Sync for AppCell {}

static APP: AppCell = AppCell(UnsafeCell::new(App::new()));

fn send(comm: &mut Comm, r: &Reply) {
    let _ = comm.send(r.payload(), IoReply(r.sw));
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    // SAFETY: sample_main runs once and this is the only reference ever taken.
    let app: &mut App<MAX_TOKENS> = unsafe { &mut *APP.0.get() };
    let mut device = platform::Device::new();

    let mut home = ui::home();
    home.show_and_return();

    loop {
        let command = comm.next_command();
        let Ok(Header(h)) = command.decode::<Header>() else {
            continue;
        };
        #[cfg(feature = "heap-probe")]
        if h.cla == 0 && h.ins == 0xFE {
            let (size, used) = ui::probe::take();
            let mut body = [0u8; 8];
            body[..4].copy_from_slice(&(size as u32).to_be_bytes());
            body[4..].copy_from_slice(&(used as u32).to_be_bytes());
            send(command.into_comm(), &Reply::with(&[&body], 0x9000));
            continue;
        }
        let action = app.handle(&mut device, h.cla, h.ins, h.p1, h.p2, command.get_data());
        let comm = command.into_comm();
        match action {
            Action::Reply(r) => send(comm, &r),
            // As in the C app, the status screen comes first and the reply is sent
            // when it closes: the host cannot send its next command while the
            // status screen is still up (it would be refused as a double APDU).
            Action::ReviewAddress => {
                let approved = ui::review_address(comm, app, &device);
                let r = app.address_done(approved);
                ui::status(comm, true, approved);
                send(comm, &r);
                home.show_and_return();
            }
            Action::ReviewTx { blind } => {
                let approved = ui::review_tx(comm, app, &device, blind);
                let r = app.sign_done(&device, approved);
                ui::status(comm, false, approved && r.sw == 0x9000);
                send(comm, &r);
                home.show_and_return();
            }
            Action::BlindSignRequired(r) => {
                let go_to_settings = ui::blind_signing_required(comm);
                send(comm, &r);
                if go_to_settings {
                    home.set_start_page(PageIndex::Settings(0));
                    home.show_and_return();
                    home.set_start_page(PageIndex::Home);
                } else {
                    home.show_and_return();
                }
            }
        }
    }
}
