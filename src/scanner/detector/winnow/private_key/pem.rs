use crate::scanner::common::charset;
use crate::scanner::detector::winnow::error::{DetectorError, DetectorErrorKind};
use crate::scanner::finding::private_key::pem::{
    Pem, PemData, BOUNDARY_BEGIN_FOOTER, BOUNDARY_BEGIN_HEADER, BOUNDARY_END,
};
use winnow::combinator::{opt, preceded, terminated};
use winnow::error::{ContextError, ErrMode};
use winnow::token::take_while;
use winnow::{PResult, Parser};

// Detector for PEM Format as specified in RFC-7468:
// https://www.rfc-editor.org/rfc/rfc7468
//
// Legacy PEM file formats, as specified in RFC-1421, may not work:
// https://www.rfc-editor.org/rfc/rfc1421
//
// Base64 Encoding standard:
// https://datatracker.ietf.org/doc/html/rfc4648#section-4

fn pem_boundary<'a>(begin: &str, end: &str, input: &mut &'a str) -> PResult<&'a str> {
    match (
        preceded(opt(take_while(1.., char::is_whitespace)), begin),
        pem_label,
        terminated(end, opt(take_while(1.., char::is_whitespace))),
    )
        .parse_next(input)
    {
        Ok((_start, label, _end)) => Ok(label),
        Err(e) => Err(e),
    }
}
pub fn pem_header<'a>(input: &mut &'a str) -> PResult<&'a str> {
    pem_boundary(BOUNDARY_BEGIN_HEADER, BOUNDARY_END, input)
}
pub fn pem_footer<'a>(input: &mut &'a str) -> PResult<&'a str> {
    pem_boundary(BOUNDARY_BEGIN_FOOTER, BOUNDARY_END, input)
}

pub fn pem_data(input: &mut &str) -> PResult<String> {
    match (
        take_while(1.., charset::BASE64_WS),
        Parser::void(opt(take_while(1.., charset::ASCII_WHITESPACE))),
        take_while(0.., charset::BASE64_SYMBOL_PADDING),
        Parser::void(opt(take_while(0.., char::is_whitespace))),
    )
        .parse_next(input)
    {
        Ok((data, (), padding, ())) => {
            // strip all whitespace from data component
            let mut data_str = String::from(data);
            data_str.retain(|c| !c.is_whitespace());

            if PemData::validate_padding(data_str.as_str(), padding) {
                data_str.push_str(padding);
                Ok(data_str)
            } else {
                // invalid number of padding characters
                Err(ErrMode::Backtrack(ContextError::new()))
            }
        }
        Err(e) => Err(e),
    }
}

pub fn pem_label<'a>(input: &mut &'a str) -> PResult<&'a str> {
    take_while(1.., (' '..=',', '.'..='`', '{'..='~'))
        .verify(|label: &str| {
            !(label.starts_with(" ") || label.ends_with(" ") || label.contains("  "))
        })
        .parse_next(input)
}

pub fn parse(input: &str) -> Result<Pem, DetectorError> {
    match (pem_header, pem_data, pem_footer).parse_next(&mut &*input) {
        Ok((header_label, data, footer_label)) => {
            // header and footer labels must match
            if header_label != footer_label {
                return Err(DetectorError {
                    kind: DetectorErrorKind::NoMatch,
                });
            }

            let raw = Pem::format_pem_str(header_label.to_string(), data.to_string());

            match Pem::from(
                raw,
                header_label.to_string(),
                data,
                footer_label.to_string(),
            ) {
                Ok(my_pem) => Ok(my_pem),
                Err(_) => Err(DetectorError {
                    kind: DetectorErrorKind::Unknown,
                }),
            }
        }
        Err(_) => Err(DetectorError {
            kind: DetectorErrorKind::NoMatch,
        }),
    }
}
