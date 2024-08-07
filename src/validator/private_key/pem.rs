use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub fn make_pem(header: &str, data: &str, footer: &str) -> String {
    let nl = String::from("\n");
    [header, nl.as_str(), data, nl.as_str(), footer].concat()
}

pub fn validate_key(input: &str) -> Option<String> {

    // Parse the PEM-encoded key
    let key_result = PKey::private_key_from_pem(input.as_bytes());
    if key_result.is_err() { return None; }
    let key = key_result.unwrap();

    match key.id() {
        openssl::pkey::Id::RSA => {

            // Get the RSA key from the parsed key
            let rsa_result = key.rsa();
            if rsa_result.is_err() { return None; }
            let rsa = rsa_result.unwrap();

            // Extract the public key
            let rsa_n = rsa.n().to_owned();
            if rsa_n.is_err() { return None; }

            let rsa_e = rsa.e().to_owned();
            if rsa_e.is_err() { return None; }

            let public_key = Rsa::from_public_components(
                rsa_n.unwrap(),
                rsa_e.unwrap());
            if public_key.is_err() { return None; }

            // Convert the public key to PEM format
            let pem = public_key.unwrap().public_key_to_pem();
            if pem.is_err() { return None; }

            // Convert the PEM bytes to a string
            match String::from_utf8(pem.unwrap()) {
                Ok(pem_str) => Some(pem_str),
                Err(_) => None
            }
        },
        // openssl::pkey::Id::DSA => {
        //
        //     // Get the RSA key from the parsed key
        //     let dsa = key.dsa()?;
        //
        //     // Extract the public key
        //     let public_key = Dsa::from_public_components(
        //         dsa.p().to_owned()?,
        //         dsa.q().to_owned()?,
        //         dsa.g().to_owned()?,
        //         dsa.pub_key().to_owned()?);
        //
        //     let pem = public_key.unwrap().public_key_to_pem();
        //
        //     // Convert the PEM bytes to a string
        //     Ok(String::from_utf8(pem.unwrap())?)
        // },
        // openssl::pkey::Id::DH => "DH".to_string(),
        // openssl::pkey::Id::EC => "EC".to_string(),
        // openssl::pkey::Id::HMAC => "HMAC".to_string(),
        // openssl::pkey::Id::CMAC => "CMAC".to_string(),
        // openssl::pkey::Id::X25519 => "X25519".to_string(),
        // openssl::pkey::Id::ED25519 => "ED25519".to_string(),
        // openssl::pkey::Id::X448 => "X448".to_string(),
        // openssl::pkey::Id::ED448 => "ED448".to_string(),
        _ => None,
    }
}