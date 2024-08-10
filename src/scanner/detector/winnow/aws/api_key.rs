use crate::scanner::common::charset;
use crate::scanner::detector::winnow::error::DetectorError;
use crate::scanner::detector::winnow::error::DetectorErrorKind;
use winnow::combinator::alt;
use winnow::token::take_while;
use winnow::{PResult, Parser};

fn aws_prefix<'a>(input: &mut &'a str) -> PResult<&'a str> {
    alt(("AKIA", "ABIA", "ACCA", "ASIA")).parse_next(input)
}

fn aws_base64<'a>(input: &mut &'a str) -> PResult<&'a str> {
    take_while(16, charset::BASE64).parse_next(input)
}

pub fn parse(input: &str) -> Result<String, DetectorError> {
    if input.len() != 20 {
        return Err(DetectorError {
            kind: DetectorErrorKind::InvalidSize,
        });
    }

    match (aws_prefix, aws_base64).parse_next(&mut &*input) {
        Ok(data) => Ok(data.0.to_owned() + data.1),
        Err(_) => Err(DetectorError {
            kind: DetectorErrorKind::NoMatch,
        }),
    }
}
