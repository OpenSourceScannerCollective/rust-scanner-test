use crate::scanner::detector::winnow::aws;
use crate::scanner::detector::winnow::error::DetectorErrorKind;

pub fn assert_valid_key(test_case: &str) {
    let mut input = test_case;
    let result = aws::api_key::parse(&mut input);
    assert_eq!(result.is_err(), false);
    assert_eq!(test_case, result.unwrap().to_owned());
}

pub fn assert_invalid_key(test_case: &str, err: DetectorErrorKind) {
    let mut input = test_case;
    let result = aws::api_key::parse(&mut input);
    assert_eq!(result.is_err(), true);
    assert_eq!(result.unwrap_err().kind, err);
}

#[test]
fn tp_valid() {
    assert_valid_key(r#"AKIAXR2OBLUTM8DTZV7F"#)
}

#[test]
fn fp_invalid_prefix() {
    assert_invalid_key(r#"ABCDXR2OBLUTM8DTZV7F"#, DetectorErrorKind::NoMatch);
}

#[test]
fn fp_invalid_base64() {
    assert_invalid_key(r#"AKIAXR2O:><TM8DTZV7F"#, DetectorErrorKind::NoMatch);
}

#[test]
fn fp_invalid_length() {
    assert_invalid_key(
        r#"AKIAXR2OBLUTM8DTZV7FXR2OBLUTM8DTZV7F"#,
        DetectorErrorKind::InvalidSize,
    );
}
