//! Status words (zxlib `apdu_codes.h`, as used by the C app).

pub const OK: u16 = 0x9000;
pub const EXECUTION_ERROR: u16 = 0x6400;
pub const WRONG_LENGTH: u16 = 0x6700;
pub const OUTPUT_BUFFER_TOO_SMALL: u16 = 0x6983;
pub const DATA_INVALID: u16 = 0x6984;
pub const COMMAND_NOT_ALLOWED: u16 = 0x6986;
pub const TX_NOT_INITIALIZED: u16 = 0x6987;
pub const INVALID_P1P2: u16 = 0x6B00;
pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
pub const SIGN_VERIFY_ERROR: u16 = 0x6F01;
