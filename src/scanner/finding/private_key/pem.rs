use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

pub const BOUNDARY_BEGIN_HEADER: &str = "-----BEGIN ";
pub const BOUNDARY_BEGIN_FOOTER: &str = "-----END ";
pub const BOUNDARY_END: &str = "-----";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemKind {
    SymmetricKey,
    AsymmetricKey,
    EllipticCurve,
    Mac,
    KeyDerivationFunction,
    Hash,
    Certificate,
    CertSignRequest,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemStatus {
    Valid,
    Invalid,
    InvalidEnclosure, // header & footer dont match
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PemData {
    pub raw: String,
    padding_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemErr {
    Unknown,
    InvalidInput,
    ValidationError,
    UnknownKeyType,
}

impl PemData {
    pub fn from(input: String) -> Result<PemData, PemErr> {
        match input.len() {
            0..1 => Err(PemErr::InvalidInput),
            len => Ok(PemData {
                raw: input,
                padding_count: Self::calc_base64_padding(len),
            }),
        }
    }

    pub fn base64(&self) -> &str {
        &self.raw[..self.raw.len().saturating_sub(self.padding_count)]
    }

    pub fn padding(&self) -> String {
        "=".repeat(self.padding_count)
    }

    pub fn validate_padding(input: &str, padding: &str) -> bool {
        let padding_size = PemData::calc_base64_padding(input.len());
        (padding_size == 0 && padding == "")
            || (padding_size == 1 && padding == "=")
            || (padding_size == 2 && padding == "==")
    }

    pub fn calc_base64_padding(str_len: usize) -> usize {
        match str_len % 4 {
            0 => 0,
            1 => 3,
            2 => 2,
            3 => 1,
            _ => unreachable!(),
        }
    }

    pub fn format(input: String) -> String {
        input
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    }
}

#[derive(Clone, Debug)]
pub struct Pem {
    pub raw: String,
    pub header_label: String,
    pub data: PemData,
    pub footer_label: String,
    pub kind: Option<PemKind>,
    pub status: Option<PemStatus>,

    // only one of these at a time:
    pub private_key: Option<PKey<Private>>,
    pub cert: Option<X509>,
}

impl Pem {
    pub fn from(
        raw: String,
        header_label: String,
        data: String,
        footer_label: String,
    ) -> Result<Pem, PemErr> {
        Ok(Pem {
            raw,
            header_label,
            data: PemData::from(data.to_string())?,
            footer_label,
            kind: None,
            status: None,
            private_key: None,
            cert: None,
        })
    }

    pub fn to_string(&self) -> Result<String, PemErr> {
        if self.private_key.is_none() && self.cert.is_none() {
            self.get_kind()?;
        }

        match match self.private_key {
            None => match self.cert {
                None => return Err(PemErr::Unknown),
                Some(_) => self.cert.clone().unwrap().to_pem(),
            },
            Some(_) => self.private_key.clone().unwrap().private_key_to_pem_pkcs8(),
        } {
            Ok(secret) => {
                let pem_result = String::from_utf8(secret);
                if pem_result.is_err() {
                    return Err(PemErr::Unknown); // TODO: better error handling
                }
                Ok(pem_result.unwrap())
            }
            Err(_) => Err(PemErr::Unknown),
        }
    }

    fn data_formatted(&self) -> String {
        PemData::format(self.data.raw.to_owned())
    }

    pub fn header(&self) -> String {
        [BOUNDARY_BEGIN_HEADER, &self.header_label, BOUNDARY_END].concat()
    }

    pub fn footer(&self) -> String {
        [BOUNDARY_BEGIN_FOOTER, &self.header_label, BOUNDARY_END].concat()
    }

    pub fn validate(&mut self) -> Result<PemStatus, PemErr> {
        let pk = self.get_private_key();
        if pk.is_err() {
            return Err(self.get_private_key().err().unwrap());
        }
        self.private_key = Some(pk.unwrap());

        match Pem::validate_input(self) {
            Ok(status) => {
                self.status = Some(status);
                self.kind = Some(self.get_kind()?);
                Ok(status)
            }
            Err(e) => Err(e),
        }
    }

    pub fn validate_input(input: &Pem) -> Result<PemStatus, PemErr> {
        if input.status.is_some() {
            return Ok(input.status.unwrap());
        }

        if &input.header_label != &input.footer_label {
            return Ok(PemStatus::InvalidEnclosure);
        }

        // if we can extract the public key
        // then the input is deemed valid
        match Pem::public_key_from_pem(input) {
            Ok(_public_key) => Ok(PemStatus::Valid),
            Err(e) => Err(e),
        }
    }

    pub fn check_is_valid(&mut self) -> bool {
        match self.status {
            None => match self.validate() {
                Ok(_) => true,
                Err(_) => false,
            },
            Some(PemStatus::Valid) => true,
            _ => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.status {
            None => match Pem::validate_input(self) {
                Ok(_) => true,
                Err(_) => false,
            },
            Some(PemStatus::Valid) => true,
            _ => false,
        }
    }

    pub fn format_pem_str(label: String, data: String) -> String {
        let nl = String::from("\n");
        let the_label = label.as_str();
        [
            BOUNDARY_BEGIN_HEADER,
            the_label,
            BOUNDARY_END,
            nl.as_str(),
            PemData::format(data).as_str(),
            nl.as_str(),
            BOUNDARY_BEGIN_FOOTER,
            the_label,
            BOUNDARY_END,
        ]
        .concat()
    }

    pub fn get_cert(&self) -> Result<X509, PemErr> {
        if self.private_key.is_some() {
            return Err(PemErr::InvalidInput); // TODO: better error handling
        }

        if self.cert.is_some() {
            return Ok(self.cert.clone().unwrap());
        }

        match Pem::cert_from_pem(self) {
            Ok(cert) => Ok(cert),
            Err(_) => Err(PemErr::ValidationError),
        }
    }

    pub fn cert_from_pem(input: &Pem) -> Result<X509, PemErr> {
        match X509::from_pem(input.raw.as_bytes()) {
            Ok(cert) => Ok(cert),
            Err(_e) => Err(PemErr::InvalidInput), // TODO: better error handling
        }
    }

    pub fn get_kind(&self) -> Result<PemKind, PemErr> {
        match self.get_private_key() {
            Ok(pk) => Ok(match pk.id() {
                openssl::pkey::Id::RSA
                | openssl::pkey::Id::DSA
                | openssl::pkey::Id::DH
                | openssl::pkey::Id::EC => PemKind::AsymmetricKey,
                openssl::pkey::Id::HMAC => PemKind::Hash,
                openssl::pkey::Id::CMAC => PemKind::Mac,
                openssl::pkey::Id::HKDF => PemKind::KeyDerivationFunction,
                openssl::pkey::Id::ED25519
                | openssl::pkey::Id::ED448
                | openssl::pkey::Id::X25519
                | openssl::pkey::Id::X448 => PemKind::EllipticCurve,
                _ => PemKind::Unknown,
            }),
            Err(_) => {
                return match self.get_cert() {
                    Ok(_) => Ok(PemKind::Certificate),
                    Err(_) => Err(PemErr::ValidationError),
                }
            }
        }
    }

    pub fn get_private_key(&self) -> Result<PKey<Private>, PemErr> {
        Pem::private_key_from_pem(&self)
    }

    pub fn private_key_from_pem(input: &Pem) -> Result<PKey<Private>, PemErr> {
        if input.private_key.is_some() {
            return Ok(input.private_key.clone().unwrap());
        }

        if input.cert.is_some() {
            return Err(PemErr::InvalidInput); // TODO: better error handling
        }

        let key = match PKey::private_key_from_pem(&input.raw.as_bytes()) {
            Ok(pkey) => pkey,
            Err(_) => {
                return Err(PemErr::ValidationError);
            }
        };

        match match key.id() {
            openssl::pkey::Id::RSA => match key.rsa() {
                Ok(the_key) => PKey::from_rsa(the_key),
                Err(e) => Err(e),
            },
            openssl::pkey::Id::DSA => match key.dsa() {
                Ok(the_key) => PKey::from_dsa(the_key),
                Err(e) => Err(e),
            },
            openssl::pkey::Id::EC => match key.ec_key() {
                Ok(the_key) => PKey::from_ec_key(the_key),
                Err(e) => Err(e),
            },
            openssl::pkey::Id::DH => match key.dh() {
                Ok(the_key) => PKey::from_dh(the_key),
                Err(e) => Err(e),
            },
            _ => return Err(PemErr::UnknownKeyType),
        } {
            Ok(result) => Ok(result),
            Err(_) => Err(PemErr::ValidationError),
        }
    }

    pub fn get_public_key(&self) -> Result<String, PemErr> {
        Pem::public_key_from_pem(&self)
    }

    pub fn public_key_from_pem(input: &Pem) -> Result<String, PemErr> {
        match Pem::get_private_key(input) {
            Ok(pkey) => match pkey.public_key_to_pem() {
                Ok(the_key) => match String::from_utf8(the_key) {
                    Ok(pem_string) => Ok(pem_string),
                    Err(_) => Err(PemErr::ValidationError),
                },
                Err(_) => Err(PemErr::ValidationError),
            },
            Err(_) => Err(PemErr::ValidationError),
        }
    }
}
