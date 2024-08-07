use winnow::{Parser, PResult};
use winnow::combinator::{opt, preceded, terminated};
use winnow::error::{ContextError, ErrMode};
use winnow::token::{take_while};
use crate::winnow::detector::error::{DetectorError, DetectorErrorKind};
use crate::winnow::parser::charset;

// Detector for PEM Format as specified in RFC-7468:
// https://www.rfc-editor.org/rfc/rfc7468
//
// Legacy PEM file formats, as specified in RFC-1421, may not work:
// https://www.rfc-editor.org/rfc/rfc1421
//
// Base64 Encoding standard:
// https://datatracker.ietf.org/doc/html/rfc4648#section-4

const BOUNDARY_BEGIN_HEADER: &str = "-----BEGIN ";
const BOUNDARY_BEGIN_FOOTER: &str = "-----END ";
const BOUNDARY_END: &str = "-----";

fn pem_boundary<'s>(begin: &str, end: &str, input: &mut &str) -> PResult<(String, String)> {
    match (
        preceded(opt(take_while(0.., char::is_whitespace)),  begin),
        pem_label,
        terminated(end, opt(take_while(0.., char::is_whitespace))),
    ).parse_next(input) {
        Ok((start, label,end)) => {
            Ok((String::from(label), format!("{}{}{}", start, label, end)))
        },
        Err(e) => Err(e)
    }
}
pub fn pem_header(input: &mut &str) -> PResult<(String, String)> {
    pem_boundary(BOUNDARY_BEGIN_HEADER, BOUNDARY_END, input)
}
pub fn pem_footer(input: &mut &str) -> PResult<(String, String)> {
    pem_boundary(BOUNDARY_BEGIN_FOOTER, BOUNDARY_END, input)
}

pub fn pem_data(input: &mut &str) -> PResult<String> {
    match (
        take_while(1.., charset::BASE64_WS),
        take_while(0.., charset::BASE64_SYMBOL_PADDING),
        Parser::void(opt(take_while(0.., char::is_whitespace)))
    ).parse_next(input) {
        Ok( (data, padding, ())) => {

            let mut data_str = String::from(data);
            data_str.retain(|c| !c.is_whitespace() );

            let data_len = data_str.len();
            if (data_len % 4 == 0 && padding == "") ||
                (data_len % 3 == 0 && padding == "=") ||
                (data_len % 2 == 0 && padding == "==") {
                Ok(format!("{}{}", data_str, padding))
            } else {
                // invalid number of padding characters
                Err(ErrMode::Backtrack(ContextError::new()))
            }
        },
        Err(e) => Err(e)
    }
}

pub fn pem_label<'s>(input: &mut &'s str) -> PResult<&'s str> {
    take_while(1.., (' '..=',', '.'..='`', '{'..='~'))
        .verify(|label: &str| {
            !(  label.starts_with(" ") ||
                label.ends_with(" ") ||
                label.contains("  ") )
        })
        .parse_next(input)
}

pub fn parse(input: &str) -> Result<(String, String, String), DetectorError> {
    match (
        pem_header,
        pem_data,
        pem_footer
    ).parse_next(&mut &*input) {
        Ok(((header_label,_),data, (footer_label,_))) => {

            // header and footer labels must match
            if header_label != footer_label {
                return Err(DetectorError{ kind: DetectorErrorKind::NoMatch });
            }

            Ok((header_label,
                data,
                footer_label ))
        },
        Err(_) => Err(DetectorError{ kind: DetectorErrorKind::NoMatch })
    }
}
