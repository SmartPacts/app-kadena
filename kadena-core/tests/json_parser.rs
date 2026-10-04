//! The C app's tokenizer/helper unit tests (tests/json_parser.cpp, 29 tests),
//! ported one to one: same inputs, same expected token counts, types and indices.

use kadena_core::error::ParserError;
use kadena_core::jsmn::{self, TokType, Token};
use kadena_core::json::Json;

struct Parsed {
    buf: Vec<u8>,
    tokens: Vec<Token>,
    n: usize,
    valid: bool,
}

/// `JSON_PARSE(&parsed, s)` = `json_parse(parsed, s, strlen(s))`.
fn json_parse(s: &str) -> Parsed {
    let mut tokens = vec![Token::EMPTY; 768];
    let (n, valid) = match jsmn::parse(s.as_bytes(), &mut tokens) {
        Ok(0) | Err(_) => (0, false),
        Ok(n) => (n, true),
    };
    Parsed {
        buf: s.as_bytes().to_vec(),
        tokens,
        n,
        valid,
    }
}

impl Parsed {
    fn json(&self) -> Json<'_> {
        Json {
            buf: &self.buf,
            tokens: &self.tokens[..self.n],
        }
    }
    fn kind(&self, i: usize) -> TokType {
        self.tokens[i].kind
    }
}

#[test]
fn empty() {
    let p = json_parse("");
    assert!(!p.valid);
    assert_eq!(p.n, 0);
}

#[test]
fn single_primitive() {
    let p = json_parse("EMPTY");
    assert!(p.valid);
    assert_eq!(p.n, 1);
    assert_eq!(p.kind(0), TokType::Primitive);
}

#[test]
fn key_value_primitives() {
    let p = json_parse("KEY : VALUE");
    assert!(p.valid);
    assert_eq!(p.n, 2);
    assert_eq!(p.kind(0), TokType::Primitive);
    assert_eq!(p.kind(1), TokType::Primitive);
}

#[test]
fn single_string() {
    let p = json_parse("\"EMPTY\"");
    assert!(p.valid);
    assert_eq!(p.n, 1);
    assert_eq!(p.kind(0), TokType::String);
}

#[test]
fn key_value_strings() {
    let p = json_parse(r#""KEY" : "VALUE""#);
    assert!(p.valid);
    assert_eq!(p.n, 2);
    assert_eq!(p.kind(0), TokType::String);
    assert_eq!(p.kind(1), TokType::String);
}

#[test]
fn simple_array() {
    let p = json_parse("LIST : [1, 2, 3, 4]");
    assert!(p.valid);
    assert_eq!(p.n, 6);
    let k = [
        TokType::Primitive,
        TokType::Array,
        TokType::Primitive,
        TokType::Primitive,
        TokType::Primitive,
        TokType::Primitive,
    ];
    for (i, t) in k.iter().enumerate() {
        assert_eq!(p.kind(i), *t);
    }
}

#[test]
fn mixed_array() {
    let p = json_parse(r#"LIST : [1, "Text", 3, "Another text"]"#);
    assert!(p.valid);
    assert_eq!(p.n, 6);
    let k = [
        TokType::Primitive,
        TokType::Array,
        TokType::Primitive,
        TokType::String,
        TokType::Primitive,
        TokType::String,
    ];
    for (i, t) in k.iter().enumerate() {
        assert_eq!(p.kind(i), *t);
    }
}

#[test]
fn simple_object() {
    let p = json_parse(
        "vote : { \"key\" : \"value\", \"another key\" : { \"inner key\" : \"inner value\", \"total\":123 }}",
    );
    assert!(p.valid);
    assert_eq!(p.n, 10);
    let k = [
        TokType::Primitive,
        TokType::Object,
        TokType::String,
        TokType::String,
        TokType::String,
        TokType::Object,
        TokType::String,
        TokType::String,
        TokType::String,
        TokType::Primitive,
    ];
    for (i, t) in k.iter().enumerate() {
        assert_eq!(p.kind(i), *t);
    }
}

const OBJ3: &str = r#"{"array":[{"amount":5,"denom":"photon"}, {"amount":5,"denom":"photon"}, {"amount":5,"denom":"photon"}]}"#;

#[test]
fn array_element_count_objects() {
    let p = json_parse(OBJ3);
    let mut c = 0;
    assert_eq!(p.json().array_get_element_count(2, &mut c), Ok(()));
    assert_eq!(c, 3);
}

#[test]
fn array_element_count_primitives() {
    let p = json_parse(r#"{"array":[1, 2, 3, 4, 5, 6, 7]}"#);
    let mut c = 0;
    assert_eq!(p.json().array_get_element_count(2, &mut c), Ok(()));
    assert_eq!(c, 7);
}

#[test]
fn array_element_count_strings() {
    let p = json_parse(r#"{"array":["hello", "there"]}"#);
    let mut c = 0;
    assert_eq!(p.json().array_get_element_count(2, &mut c), Ok(()));
    assert_eq!(c, 2);
}

#[test]
fn array_element_count_empty() {
    let p = json_parse(r#"{"array":[]"#);
    let mut c = 0;
    assert_eq!(
        p.json().array_get_element_count(2, &mut c),
        Err(ParserError::NoData)
    );
}

#[test]
fn array_element_get_objects() {
    let p = json_parse(OBJ3);
    let mut t = 0;
    assert_eq!(p.json().array_get_nth_element(2, 1, &mut t), Ok(()));
    assert_eq!(t, 8);
    assert_eq!(p.kind(t as usize), TokType::Object);
}

#[test]
fn array_element_get_primitives() {
    let p = json_parse(r#"{"array":[1, 2, 3, 4, 5, 6, 7]}"#);
    let mut t = 0;
    assert_eq!(p.json().array_get_nth_element(2, 5, &mut t), Ok(()));
    assert_eq!(t, 8);
    assert_eq!(p.kind(t as usize), TokType::Primitive);
}

#[test]
fn array_element_get_strings() {
    let p = json_parse(r#"{"array":["hello", "there"]}"#);
    let mut t = 0;
    assert_eq!(p.json().array_get_nth_element(2, 0, &mut t), Ok(()));
    assert_eq!(t, 3);
    assert_eq!(p.kind(t as usize), TokType::String);
}

#[test]
fn array_element_get_empty() {
    let p = json_parse(r#"{"array":[]"#);
    let mut t = 0;
    assert_eq!(
        p.json().array_get_nth_element(2, 0, &mut t),
        Err(ParserError::NoData)
    );
}

#[test]
fn array_element_get_out_of_bounds_negative() {
    let p = json_parse(r#"{"array":["hello", "there"]"#);
    let mut t = 0;
    assert_eq!(
        p.json().array_get_nth_element(2, (-1i16) as u16, &mut t),
        Err(ParserError::NoData)
    );
}

#[test]
fn array_element_get_out_of_bounds() {
    let p = json_parse(r#"{"array":["hello", "there"]"#);
    let mut t = 0;
    assert_eq!(
        p.json().array_get_nth_element(2, 3, &mut t),
        Err(ParserError::NoData)
    );
}

#[test]
fn object_element_count_primitives() {
    let p = json_parse(r#"{"age":36, "height":185, "year":1981}"#);
    let mut c = 0;
    assert_eq!(p.json().object_get_element_count(0, &mut c), Ok(()));
    assert_eq!(c, 3);
}

#[test]
fn object_element_count_string() {
    let p = json_parse(r#"{"age":"36", "height":"185", "year":"1981", "month":"july"}"#);
    let mut c = 0;
    assert_eq!(p.json().object_get_element_count(0, &mut c), Ok(()));
    assert_eq!(c, 4);
}

#[test]
fn object_element_count_array() {
    let p = json_parse(
        r#"{ "ages":[36, 31, 10, 2],
                            "heights":[185, 164, 154, 132],
                            "years":[1981, 1985, 2008, 2016],
                            "months":["july", "august", "february", "july"]}"#,
    );
    let mut c = 0;
    assert_eq!(p.json().object_get_element_count(0, &mut c), Ok(()));
    assert_eq!(c, 4);
}

#[test]
fn object_element_count_object() {
    let p = json_parse(
        r#"{"person1":{"age":36, "height":185, "year":1981},
                           "person2":{"age":36, "height":185, "year":1981},
                           "person3":{"age":36, "height":185, "year":1981}}"#,
    );
    let mut c = 0;
    assert_eq!(p.json().object_get_element_count(0, &mut c), Ok(()));
    assert_eq!(c, 3);
}

#[test]
fn object_element_count_deep() {
    let p = json_parse(
        r#"{"person1":{"age":{"age":36, "height":185, "year":1981}, "height":{"age":36, "height":185, "year":1981}, "year":1981},
                           "person2":{"age":{"age":36, "height":185, "year":1981}, "height":{"age":36, "height":185, "year":1981}, "year":1981},
                           "person3":{"age":{"age":36, "height":185, "year":1981}, "height":{"age":36, "height":185, "year":1981}, "year":1981}}"#,
    );
    let mut c = 0;
    assert_eq!(p.json().object_get_element_count(0, &mut c), Ok(()));
    assert_eq!(c, 3);
}

#[test]
fn object_element_get_primitives() {
    let s = r#"{"age":36, "height":185, "year":1981}"#;
    let p = json_parse(s);
    let mut t = 0;
    assert_eq!(p.json().object_get_nth_key(0, 0, &mut t), Ok(()));
    assert_eq!(t, 1);
    assert_eq!(p.kind(t as usize), TokType::String);
    assert_eq!(p.json().span(t), b"age");
}

#[test]
fn object_element_get_string() {
    let p = json_parse(r#"{"age":"36", "height":"185", "year":"1981", "month":"july"}"#);
    let mut t = 0;
    assert_eq!(p.json().object_get_nth_value(0, 3, &mut t), Ok(()));
    assert_eq!(t, 8);
    assert_eq!(p.kind(t as usize), TokType::String);
    assert_eq!(p.json().span(t), b"july");
}

#[test]
fn object_element_get_out_of_bounds_negative() {
    let p = json_parse(r#"{"age":36, "height":185, "year":1981}"#);
    let mut t = 0;
    assert_eq!(
        p.json().object_get_nth_key(0, (-1i16) as u16, &mut t),
        Err(ParserError::NoData)
    );
}

#[test]
fn object_element_get_out_of_bounds() {
    let p = json_parse(r#"{"age":36, "height":185, "year":1981}"#);
    let mut t = 0;
    assert_eq!(
        p.json().object_get_nth_key(0, 5, &mut t),
        Err(ParserError::NoData)
    );
}

#[test]
fn object_element_get_array() {
    let p = json_parse(
        r#"{ "ages":[36, 31, 10, 2],
                            "heights":[185, 164, 154, 132],
                            "years":[1981, 1985, 2008, 2016, 2022],
                            "months":["july", "august", "february", "july"]}"#,
    );
    let mut t = 0;
    assert_eq!(p.json().object_get_value(0, b"years", &mut t), Ok(()));
    assert_eq!(t, 14);
    assert_eq!(p.kind(t as usize), TokType::Array);
    let mut c = 0;
    assert_eq!(p.json().array_get_element_count(t, &mut c), Ok(()));
    assert_eq!(c, 5);
}

#[test]
fn object_get_value_correct_format() {
    let p = json_parse(
        r#"{"account_number":"0","chain_id":"test-chain-1","fee":{"amount":[{"amount":"5","denom":"photon"}],"gas":"10000"},"memo":"testmemo","msgs":[{"inputs":[{"address":"cosmosaccaddr1d9h8qat5e4ehc5","coins":[{"amount":"10","denom":"atom"}]}],"outputs":[{"address":"cosmosaccaddr1da6hgur4wse3jx32","coins":[{"amount":"10","denom":"atom"}]}]}],"sequence":"1"}"#,
    );
    let j = p.json();
    let mut t = 0;
    assert_eq!(
        j.object_get_value(0, b"alt_bytes", &mut t),
        Err(ParserError::NoData)
    );
    for (k, want) in [
        ("account_number", 2),
        ("chain_id", 4),
        ("fee", 6),
        ("msgs", 19),
        ("sequence", 46),
    ] {
        assert_eq!(j.object_get_value(0, k.as_bytes(), &mut t), Ok(()), "{k}");
        assert_eq!(t, want, "{k}");
    }
}
