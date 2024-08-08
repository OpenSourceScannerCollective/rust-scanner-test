mod detector;
mod finding_type;
#[allow(dead_code)]
pub(crate) mod parser;

fn main() {
    aws_key();
    pem_key();
}


fn aws_key() {
    let test_case = r#"AKIAXR2OBLUTM8DTZV7F"#;
    let result = detector::winnow::aws::api_key::parse(test_case);

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
    let result = detector::winnow::private_key::pem::parse(test_case);

    if result.is_err() {
        println!("[PEM] Error: {}", result.err().unwrap());
        return;
    }

    let mut my_pem = result.unwrap();
    let _ = my_pem.validate();

    let pem_str = my_pem.to_string();
    if pem_str.is_err() {
        println!("[PEM] Error: {:?}", pem_str.err().unwrap());
        return;
    }

    println!("[PEM] Result: {}", pem_str.unwrap());
}