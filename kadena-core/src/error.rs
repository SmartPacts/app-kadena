//! Parser error codes and their on-the-wire descriptions.
//!
//! The descriptions are the exact strings of `parser_getErrorDescription`
//! (C app `app/src/parser_impl.c`). Codes that have no case there fall back to
//! `"Unrecognized error code"`, exactly as in C.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParserError {
    NoData,
    InitContextEmpty,
    UnexpectedError,
    UnexpectedUnparsedBytes,
    UnexpectedBufferEnd,
    UnexpectedValue,
    UnexpectedCharacters,
    DuplicatedField,
    ValueOutOfRange,
    TxObjEmpty,
    BlindsignModeRequired,
    JsonZeroTokens,
    JsonTooManyTokens,
    JsonIncompleteJson,
    InvalidMetaField,
    NameTxTransfer,
    NameTxTransferXchain,
    NameRotate,
    NameGas,
    /// V9: no signer entry carries the device key.
    SignerNotFound,
    /// V9: more than one signer entry carries the device key.
    SignerRepeated,
}

impl ParserError {
    /// The ASCII text the device returns before `0x6984`.
    pub fn description(self) -> &'static [u8] {
        match self {
            ParserError::NoData => b"No more data",
            ParserError::InitContextEmpty => b"Initialized empty context",
            ParserError::UnexpectedUnparsedBytes => b"Unexpected unparsed bytes",
            ParserError::UnexpectedBufferEnd => b"Unexpected buffer end",
            ParserError::UnexpectedValue => b"Unexpected value",
            ParserError::UnexpectedCharacters => b"Unexpected characters",
            ParserError::DuplicatedField => b"Unexpected duplicated field",
            ParserError::ValueOutOfRange => b"Value out of range",
            ParserError::TxObjEmpty => b"Tx obj empty",
            ParserError::BlindsignModeRequired => b"Blind signing mode required",
            ParserError::JsonTooManyTokens => b"NOMEM: JSON string contains too many tokens",
            ParserError::InvalidMetaField => b"Invalid meta field",
            ParserError::NameTxTransfer => b"Transaction type: Transfer",
            ParserError::NameTxTransferXchain => b"Transaction type: Cross-chain Transfer",
            ParserError::NameRotate => b"Transaction type: Rotate",
            ParserError::NameGas => b"Transaction type: Gas",
            ParserError::SignerNotFound => b"Device key is not a signer",
            ParserError::SignerRepeated => b"Device key signs more than once",
            // parser_unexpected_error, parser_json_zero_tokens and
            // parser_json_incomplete_json have no case in C.
            ParserError::UnexpectedError
            | ParserError::JsonZeroTokens
            | ParserError::JsonIncompleteJson => b"Unrecognized error code",
        }
    }
}

pub type PResult = Result<(), ParserError>;
