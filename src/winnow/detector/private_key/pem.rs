use winnow::{Parser, PResult};
use winnow::token::{take_while};
use crate::winnow::detector::error::{DetectorError, DetectorErrorKind};
use crate::winnow::parser::charset;

// Detector for PEM Format as specified in RFC-7468:
// https://www.rfc-editor.org/rfc/rfc7468
//
// Legacy PEM file formats, as specified in RFC-1421, may not work:
// https://www.rfc-editor.org/rfc/rfc1421

const BOUNDARY_BEGIN_HEADER: &str = "-----BEGIN ";
const BOUNDARY_BEGIN_FOOTER: &str = "-----END ";

// TODO: at present boundary dashes must contain one less than actually required
// one less dash is required due to parse_label function consuming one too many characters
const BOUNDARY_END: &str = "-----";

fn pem_boundary<'s>(begin: &'s str, end: &'s str, input: &mut &'s str) -> PResult<(String, String)> {
    match (
        begin,
        pem_label,
        end,
    ).parse_next(input) {
        Ok((start, label,end)) => {
            Ok((String::from(label), format!("{}{}{}", start, label, end)))
        },
        Err(e) => Err(e)
    }
}
pub fn pem_header<'s>(input: &mut &'s str) -> PResult<(String, String)> {
    pem_boundary(BOUNDARY_BEGIN_HEADER, BOUNDARY_END, input)
}
pub fn pem_footer<'s>(input: &mut &'s str) -> PResult<(String, String)> {
    pem_boundary(BOUNDARY_BEGIN_FOOTER, BOUNDARY_END, input)
}
// TODO: add constraints on padding characters (termination, max number)
pub fn pem_data<'s>(input: &mut &'s str) -> PResult<&'s str> {
    take_while(0.., charset::BASE64_WITH_PADDING_WS).parse_next(input)
}

/*
TODO: FIXME
 1. consumes one too many characters if space or dash
 2. does not fail parse if either consecutive rules fail
 */
// pub fn pem_label<'s>(input: &mut &'s str) -> PResult<&'s str> {
//     let prev_c = RefCell::new(' ');          // double space after BEGIN is invalid
//     match take_while(0.., move |c: char| {
//         if (c == '-' && prev_c.borrow().as_char() == '-') ||    // consecutive dashes
//             (c == ' ' && prev_c.borrow().as_char() == ' ') {    // consecutive spaces
//             return false;    // TODO: this should fail the parser not just stop it
//         }
//         *prev_c.borrow_mut() = c;
//         match c {
//             ' '..='`' | '{'..='~' => true,
//             _ => false
//         }
//     }).parse_next(input) {
//         Ok(input_str) => {
//             let str_len = input_str.len();  // performance
//             if str_len < 2  || !input_str.ends_with('-') {
//                 return Ok(&input_str);
//             }
//             Ok(&input_str[..str_len - 1])
//         },
//         Err(e) => Err(e)
//     }
// }
pub fn pem_label<'s>(input: &mut &'s str) -> PResult<&'s str> {
    take_while(0.., (' '..=',', '.'..='`', '{'..='~'))
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
            Ok((header_label,
                String::from(data),
                footer_label ))
        },
        Err(_) => Err(DetectorError{ kind: DetectorErrorKind::NoMatch })
    }
}
