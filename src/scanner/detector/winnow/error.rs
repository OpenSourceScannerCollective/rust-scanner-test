use std::fmt;

#[derive(PartialEq, Debug)]
pub enum DetectorErrorKind {
    Unknown,
    NoMatch,
    InvalidSize,
}
pub struct DetectorError {
    pub kind: DetectorErrorKind,
}

impl DetectorError {
    pub fn message(&self) -> String {
        match self.kind {
            DetectorErrorKind::Unknown => String::from(r#"Unspecified match failure condition"#),
            DetectorErrorKind::NoMatch => String::from(r#"Input is not a match"#),
            DetectorErrorKind::InvalidSize => String::from(r#"Input is not a valid size"#),
        }
    }
}

impl fmt::Display for DetectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message()) // user-facing output
    }
}

impl fmt::Debug for DetectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!()) // programmer-facing output
    }
}
