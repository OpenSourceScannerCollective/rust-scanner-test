use openssl::dsa::Dsa;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub const BOUNDARY_BEGIN_HEADER: &str = "-----BEGIN ";
pub const BOUNDARY_BEGIN_FOOTER: &str = "-----END ";
pub const BOUNDARY_END: &str = "-----";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemKind {
    PrivateKey,
    PublicKey,
    KeyPair,
    SymmetricKey,
    Certificate,
    CertSignRequest,
    Unknown
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemStatus {
    Valid,
    Invalid,
    InvalidEnclosure,   // header & footer dont match
    Unknown
}

#[derive(Clone, Debug, PartialEq)]
pub struct PemData {
    data: String,
    padding_count: usize
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PemErr {
    Unknown,
    InvalidInput,
    ValidationError,
    UnknownKeyType
}

impl PemData {
    pub fn from(input: String) -> Result<PemData, PemErr> {

        let data_len = input.len();
        if data_len < 1 {
            return Err(PemErr::InvalidInput);
        }

        Ok(PemData {
            data: input,
            padding_count: Self::calc_base64_padding(data_len)
        })
    }
    pub fn base64(&self) -> &str {
        &self.data[..self.data.len().saturating_sub(self.padding_count)]
    }
    pub fn padding(&self) -> String {
        "=".repeat(self.padding_count)
    }
    pub fn raw(&self) -> &String {
        &self.data
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pem {
    pub header_label: String,
    pub data: PemData,
    pub footer_label: String,
    pub kind: Option<PemKind>,
    pub status: Option<PemStatus>
}

impl Pem {
    pub fn from(header: String, data: String, footer: String) -> Result<Pem, PemErr> {
        Ok(Pem {
            header_label: String::from(header),
            data: PemData::from(data.to_string())?,
            footer_label: String::from(footer),
            kind: None,
            status: None
        })
    }

    pub fn to_string(&self) -> String {
        let nl = String::from("\n");
        [   BOUNDARY_BEGIN_HEADER,
            &self.header_label,
            BOUNDARY_END,
            nl.as_str(),
            &self.data_formatted(),
            nl.as_str(),
            BOUNDARY_BEGIN_FOOTER,
            &self.footer_label,
            BOUNDARY_END].concat()
    }

    fn data_formatted(&self) -> String {
        self.data.raw()
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    }

    pub fn header(&self) -> String {
        [BOUNDARY_BEGIN_HEADER, &self.header_label, BOUNDARY_END].concat()
    }

    pub fn footer(&self) -> String {
        [BOUNDARY_BEGIN_FOOTER, &self.header_label, BOUNDARY_END].concat()
    }

    // TODO: flesh out functionality
    pub fn validate(&mut self) -> Result<PemStatus, PemErr> {

        if self.status.is_some() {
            return Ok(self.status.unwrap());
        }

        if &self.header_label != &self.footer_label {
            self.status = Some(PemStatus::InvalidEnclosure);
            return Ok(PemStatus::InvalidEnclosure);
        }

        // Parse the PEM-encoded key
        let key_result = PKey::private_key_from_pem(self.to_string().as_bytes());
        if key_result.is_err() { return Err(PemErr::ValidationError); }

        let key = key_result.unwrap();

        match key.id() {
            openssl::pkey::Id::RSA => {

                // Get the RSA key from the parsed key
                let rsa_result = key.rsa();
                if rsa_result.is_err() { return Err(PemErr::ValidationError); }
                let rsa = rsa_result.unwrap();

                // Extract the public key
                let rsa_n = rsa.n().to_owned();
                if rsa_n.is_err() { return Err(PemErr::ValidationError); }

                let rsa_e = rsa.e().to_owned();
                if rsa_e.is_err() { return Err(PemErr::ValidationError); }

                let public_key = Rsa::from_public_components(
                    rsa_n.unwrap(),
                    rsa_e.unwrap());
                if public_key.is_err() { return Err(PemErr::ValidationError); }

                // Convert the public key to PEM format
                let pem = public_key.unwrap().public_key_to_pem();
                if pem.is_err() { return Err(PemErr::ValidationError); }

                // Convert the PEM bytes to a string
                match String::from_utf8(pem.unwrap()) {
                    Ok(_pem_str) => Ok(PemStatus::Valid),
                    Err(_) => Err(PemErr::ValidationError)
                }
            },
            openssl::pkey::Id::DSA => {

                // Get the RSA key from the parsed key
                let dsa_result = key.dsa();
                if dsa_result.is_err() { return Err(PemErr::ValidationError); }

                let dsa = dsa_result.unwrap();

                let dsa_p = dsa.p().to_owned();
                if dsa_p.is_err() { return Err(PemErr::ValidationError); }

                let dsa_q = dsa.p().to_owned();
                if dsa_q.is_err() { return Err(PemErr::ValidationError); }

                let dsa_g = dsa.p().to_owned();
                if dsa_g.is_err() { return Err(PemErr::ValidationError); }

                let dsa_pub_key = dsa.pub_key();

                // Extract the public key
                let public_key = Dsa::from_public_components(
                    dsa_p.unwrap(),
                    dsa_q.unwrap(),
                    dsa_g.unwrap(),
                    dsa_pub_key.to_owned().unwrap());
                if public_key.is_err() { return Err(PemErr::ValidationError); }

                let pem = public_key.unwrap().public_key_to_pem();
                if pem.is_err() { return Err(PemErr::ValidationError); }

                // Convert the PEM bytes to a string
                let pem_str = String::from_utf8(pem.unwrap());
                if pem_str.is_err() { return Err(PemErr::ValidationError); }

                Ok(PemStatus::Valid)
            },
            // openssl::pkey::Id::DH => "DH".to_string(),
            // openssl::pkey::Id::EC => "EC".to_string(),
            // openssl::pkey::Id::HMAC => "HMAC".to_string(),
            // openssl::pkey::Id::CMAC => "CMAC".to_string(),
            // openssl::pkey::Id::X25519 => "X25519".to_string(),
            // openssl::pkey::Id::ED25519 => "ED25519".to_string(),
            // openssl::pkey::Id::X448 => "X448".to_string(),
            // openssl::pkey::Id::ED448 => "ED448".to_string(),
            _ => Err(PemErr::UnknownKeyType),
        }
    }


    pub fn check_is_valid(&mut self) -> bool {
        if self.status.is_none() {
            return match self.validate() {
                Ok(_) => true,
                Err(_) => false
            };
        }
        match self.status {
            Some(PemStatus::Valid) => true,
            _ => false
        }
    }

    pub fn private_key(&self) -> Option<String> {
        None
    }

    pub fn public_key(&self) -> Option<String> {
        None
    }

    pub fn certificate(&self) -> Option<String> {
        None
    }
}