use rst_lib::scanner::detector::winnow::{aws::api_key, private_key::pem};

fn main() {
    aws_key();
    pem_key();
}

fn aws_key() {
    let test_case = r#"AKIAXR2OBLUTM8DTZV7F"#;
    let result = api_key::parse(test_case);

    if result.is_err() {
        println!("[AWS] Error: {}", result.err().unwrap());
        return;
    }

    println!("[AWS] Result: {}", result.unwrap());
}

fn pem_key() {
    let test_case = r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANd4azcpShA5I9Vs
tJDUKoJP5E30EkFc/OM4waLMZ+PHNDghxOiDzrIknA0kUTfBwN+ykOpHYVmIo66/
5tJ5pV6EXXyFtqSyi3rORf+Hr08L3c2F3+S0AahRymSpru2/C25QTRd15Y28DNC3
QzXBG0YVmLiJ44hfuHX1HEVtfM7HAgMBAAECgYAiU9v48MoM5Z2Q3f2yaSrQkfvU
c4MJCNB9PsiSsDAI+O6X1sFxLbabaPu3mEacNHEO8nrl6DNZOUyihY43kAvJRTH4
GPbudkY0suimIfpLJZA/jjElzXFj6klOB18vBS8vSi3c+vqpaX4MyUuVac81fVyT
zIoIw3Lq9Dgkkzov6QJBAPWyQrA9NFQmj8afwY48OxENrH+8sRSxiJd2uqfrL55d
1CRrfOJ5vQdrBiuWPwjuwhyxcQnBkVdiPColabS6sbsCQQDggajU7yraZL9C2oPW
YJZ/FPM8mdLIjHryByhu8PhZwLDRWrjvFLcUalKwivBcBGuJosUhsM27LyhVBt/C
GxBlAkEAgrNMdJJqduV4kHHFtlNmHIFIpT8MeHSks+YuD0u2Lim9w44Ghje6jeqq
Ap/PcoIIctkVx9nX5kNUvBrg64pxJwJAdg0X1ufwM6h4PdIjMu3VFPvSLxJ/mL7t
wyhqZXPGU4OUNnGq/uR4pH6H/pcAbpJQba4uVFngxEW2wob7z9hlVQJBAJJxYYYD
gOB36ex0dUdXhOPqQf3EZPMeMS28kKcPMloPWbmz1IFiQK/HWpmr7yb3qKCdvhgP
vhj3eVN6voMtw7o=
-----END PRIVATE KEY-----"#;

    let result = pem::parse(test_case);

    if result.is_err() {
        println!("[PEM] Error: {}", result.err().unwrap());
        return;
    }

    let mut pkey = result.unwrap();
    let _ = pkey.validate();

    let pem_str = pkey.to_string();
    if pem_str.is_err() {
        println!("[PEM] Error: {:?}", pem_str.err().unwrap());
        return;
    }
    println!("[PEM] Private Key:\n {}", pem_str.unwrap().trim());

    let pub_key = pkey.get_public_key();
    if pub_key.is_err() {
        println!("[PEM] Error: {:?}", pub_key.err().unwrap());
        return;
    }
    println!("[PEM] Public Key:\n {}", pub_key.unwrap().trim());
}
