use openssl::dsa::Dsa;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub fn make_pem(header: &str, data: &str, footer: &str) -> String {
    let nl = String::from("\n");
    [header, nl.as_str(), data, nl.as_str(), footer].concat()
}

pub enum KeyStatus {
    Valid,
    Invalid,
    Unknown
}

pub struct KeyValidation {
    status: KeyStatus,
    value: Option<String>
}

impl KeyValidation {
    fn valid(key: String) -> KeyValidation {
        KeyValidation {
            status: KeyStatus::Valid,
            value: Some(key)
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.status {
            KeyStatus::Valid => true,
            _ => false
        }
    }

    fn invalid() -> KeyValidation {
        KeyValidation {
            status: KeyStatus::Invalid,
            value: None
        }
    }

    fn unknown() -> KeyValidation {
        KeyValidation {
            status: KeyStatus::Unknown,
            value: None
        }
    }
}

pub fn validate_key(input: &str) -> KeyValidation {

    // Parse the PEM-encoded key
    let key_result = PKey::private_key_from_pem(input.as_bytes());
    if key_result.is_err() { return KeyValidation::invalid() }
    let key = key_result.unwrap();

    match key.id() {
        openssl::pkey::Id::RSA => {

            // Get the RSA key from the parsed key
            let rsa_result = key.rsa();
            if rsa_result.is_err() { return KeyValidation::invalid(); }
            let rsa = rsa_result.unwrap();

            // Extract the public key
            let rsa_n = rsa.n().to_owned();
            if rsa_n.is_err() { return KeyValidation::invalid(); }

            let rsa_e = rsa.e().to_owned();
            if rsa_e.is_err() { return KeyValidation::invalid(); }

            let public_key = Rsa::from_public_components(
                rsa_n.unwrap(),
                rsa_e.unwrap());
            if public_key.is_err() { return KeyValidation::invalid(); }

            // Convert the public key to PEM format
            let pem = public_key.unwrap().public_key_to_pem();
            if pem.is_err() { return KeyValidation::invalid(); }

            // Convert the PEM bytes to a string
            match String::from_utf8(pem.unwrap()) {
                Ok(pem_str) => KeyValidation::valid(pem_str),
                Err(_) => KeyValidation::invalid()
            }
        },
        openssl::pkey::Id::DSA => {

            // Get the RSA key from the parsed key
            let dsa_result = key.dsa();
            if dsa_result.is_err() { return KeyValidation::invalid(); }

            let dsa = dsa_result.unwrap();

            let dsa_p = dsa.p().to_owned();
            if dsa_p.is_err() { return KeyValidation::invalid(); }

            let dsa_q = dsa.p().to_owned();
            if dsa_q.is_err() { return KeyValidation::invalid(); }

            let dsa_g = dsa.p().to_owned();
            if dsa_g.is_err() { return KeyValidation::invalid(); }

            let dsa_pub_key = dsa.pub_key();
            // if dsa_pub_key.is_err() { return KeyValidation::invalid(); }

            // Extract the public key
            let public_key = Dsa::from_public_components(
                dsa_p.unwrap(),
                dsa_q.unwrap(),
                dsa_g.unwrap(),
                dsa_pub_key.to_owned().unwrap());
            if public_key.is_err() { return KeyValidation::invalid(); }

            let pem = public_key.unwrap().public_key_to_pem();
            if pem.is_err() { return KeyValidation::invalid(); }

            // Convert the PEM bytes to a string
            let pem_str = String::from_utf8(pem.unwrap());
            if pem_str.is_err() { return KeyValidation::invalid(); }

            KeyValidation::valid(pem_str.unwrap())
        },
        // openssl::pkey::Id::DH => "DH".to_string(),
        // openssl::pkey::Id::EC => "EC".to_string(),
        // openssl::pkey::Id::HMAC => "HMAC".to_string(),
        // openssl::pkey::Id::CMAC => "CMAC".to_string(),
        // openssl::pkey::Id::X25519 => "X25519".to_string(),
        // openssl::pkey::Id::ED25519 => "ED25519".to_string(),
        // openssl::pkey::Id::X448 => "X448".to_string(),
        // openssl::pkey::Id::ED448 => "ED448".to_string(),
        _ => KeyValidation::unknown(),
    }
}