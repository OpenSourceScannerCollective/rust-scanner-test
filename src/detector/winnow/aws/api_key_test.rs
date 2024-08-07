use crate::detector::winnow::aws;

mod tests {
    use crate::detector::winnow::error::DetectorErrorKind;
    use super::*;

    #[test]
    fn tp_valid() {
        let test_case = r#"AKIAXR2OBLUTM8DTZV7F"#;
        let mut input = test_case;

        let result = aws::api_key::parse(&mut input);
        assert_eq!(result.is_err(), false);
        assert_eq!(test_case, result.unwrap().to_owned());
    }

    #[test]
    fn fp_invalid_prefix() {
        let mut input = r#"ABCDXR2OBLUTM8DTZV7F"#;

        let result  = aws::api_key::parse(&mut input);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err().kind, DetectorErrorKind::NoMatch);
    }

    #[test]
    fn fp_invalid_base64() {
        let mut input = r#"AKIAXR2O:><TM8DTZV7F"#;

        let result  = aws::api_key::parse(&mut input);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err().kind, DetectorErrorKind::NoMatch);
    }

    #[test]
    fn fp_invalid_length() {
        let mut input = r#"AKIAXR2OBLUTM8DTZV7FXR2OBLUTM8DTZV7F"#;

        let result  = aws::api_key::parse(&mut input);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err().kind, DetectorErrorKind::InvalidSize);
    }

}