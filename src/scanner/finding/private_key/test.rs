use crate::scanner::detector;
use crate::scanner::finding::private_key::pem::PemStatus;

#[allow(unused_variables)]
pub fn assert_valid_key(private_key: &str, public_key: &str) {
    let result = detector::winnow::private_key::pem::parse(private_key);
    assert_eq!(result.is_err(), false);

    let mut my_pem = result.unwrap();
    let is_valid = my_pem.validate();
    assert_eq!(is_valid.is_err(), false);

    let validation = is_valid.unwrap();
    assert_eq!(validation, PemStatus::Valid);

    let pk_result = my_pem.get_public_key();
    assert_eq!(pk_result.is_err(), false);

    let public_key = pk_result.unwrap();
    assert_eq!(public_key, public_key);
}

#[warn(unused_variables)]
pub fn assert_invalid_key(private_key: &str) {
    let result = detector::winnow::private_key::pem::parse(private_key);
    assert_eq!(result.is_err(), true);
}

#[test]
fn tp_valid_key_rsa_1() {
    let private_key = r#"-----BEGIN PRIVATE KEY-----
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

    let public_key = r#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXeGs3KUoQOSPVbLSQ1CqCT+RN
9BJBXPzjOMGizGfjxzQ4IcTog86yJJwNJFE3wcDfspDqR2FZiKOuv+bSeaVehF18
hbaksot6zkX/h69PC93Nhd/ktAGoUcpkqa7tvwtuUE0XdeWNvAzQt0M1wRtGFZi4
ieOIX7h19RxFbXzOxwIDAQAB
-----END PUBLIC KEY-----
"#; // openssl adds a newline

    assert_valid_key(private_key, public_key);
}

#[test]
fn fp_invalid_key_rsa_1() {
    let private_key = r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANd4azcpShA5I9Vs
tJDUKoJP5E30EkFc/OM4waLMZ+PHNDghxOiDzrIknA0kUTfBwN+ykOpHYVmIo66/
5tJ5pV6EXXyFtqSyi3rORf+Hr08L3c2F3+S0AahRymSpru2/C25QTRd15Y28DNC3
QzXBG0YVmLiJ44hfuHX1HEVtfM7HAgMBAAECgYAiU9v48MoM5Z2Q3f2yaSrQkfvU
c4MJCNB9PsiSsDAI+O6X1sFxLbabaPu3mEacNHEO8nrl6DNZOUyihY43kAvJRTH4
GPbudkY0suimIfpLJZA/jjElzXFj6klOB18vBS8vSi3c+vqpaX4MyUuVac81fVyT
zIoIw3Lq9Dgkkzov6QJBAPWyQrA9NFQmj8afwY48OxENrH+8sRSxiJd2uqfrL55d
1CRrfOJ5vQdrBiuWP { This key is invalid } DwjuwhyxcQnBkVdiPColab
YJZ/FPM8mdLIjHryByhu8PhZwLDRWrjvFLcUalKwivBcBGuJosUhsM27LyhVBt/C
GxBlAkEAgrNMdJJqduV4kHHFtlNmHIFIpT8MeHSks+YuD0u2Lim9w44Ghje6jeqq
Ap/PcoIIctkVx9nX5kNUvBrg64pxJwJAdg0X1ufwM6h4PdIjMu3VFPvSLxJ/mL7t
wyhqZXPGU4OUNnGq/uR4pH6H/pcAbpJQba4uVFngxEW2wob7z9hlVQJBAJJxYYYD
gOB36ex0dUdXhOPqQf3EZPMeMS28kKcPMloPWbmz1IFiQK/HWpmr7yb3qKCdvhgP
vhj3eVN6voMtw7o=
-----END PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}

#[test]
fn tp_valid_key_dsa_1() {
    let private_key = r#"-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCoEbdAHInLUX+2kkZdaqG7cNIZk3x8g6UZCo1pqrrbNEkn1k/m
RFOW5bU36URjaiJK2E1/iXdQ2ZDITTqvkZVzEhwF25rllsIz11UoHbsxIkQCV342
RTCRtOIU+KHDgyV5s+/nhAWZe7a/p8PnzMFpWapEBeAvxpVGHJBjszCiEQIVAMXr
ZihRmKMqsIKy/e0XHwHSFZRTAoGBAJDBJCYHXk+4HExhx6wuVghzeFOArSaJdEU4
I9KDdRHTFyq9iS+TRYmaLps+m/CKRGpaPGTGCitm4UKbI8jLdIU4SShXWiNCxxYV
xyDBV0KZ3IHhTCxPKzfexQjAAAVQyk8q3bKZvYZRxREisnlepJJLwkrqebaESFON
mZQneQ5vAoGAQ4qHnMA06CR93UWjkGN2Ek/K47W5Q5EpLDc9VX7iLmpAiL9xFH8U
Gxh6e6FFmzxGKpF1fWqAJKEgQRbINvFtKWBhx828YMMElEG0u/3uJEcGsiPumKF+
zGKoyYj8mzf5egnFiFKjzV8LzxSjWAz6FkmqRNUGXqtxbjGb45uhcQ0CFFaKPjsi
1z9fVy7ZdQljvks44bET
-----END DSA PRIVATE KEY-----"#;

    let public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBtzCCASwGByqGSM44BAEwggEfAoGBAKgRt0AcictRf7aSRl1qobtw0hmTfHyD
pRkKjWmquts0SSfWT+ZEU5bltTfpRGNqIkrYTX+Jd1DZkMhNOq+RlXMSHAXbmuWW
wjPXVSgduzEiRAJXfjZFMJG04hT4ocODJXmz7+eEBZl7tr+nw+fMwWlZqkQF4C/G
lUYckGOzMKIRAhUAxetmKFGYoyqwgrL97RcfAdIVlFMCgYEAkMEkJgdeT7gcTGHH
rC5WCHN4U4CtJol0RTgj0oN1EdMXKr2JL5NFiZoumz6b8IpEalo8ZMYKK2bhQpsj
yMt0hThJKFdaI0LHFhXHIMFXQpncgeFMLE8rN97FCMAABVDKTyrdspm9hlHFESKy
eV6kkkvCSup5toRIU42ZlCd5Dm8DgYQAAoGAQ4qHnMA06CR93UWjkGN2Ek/K47W5
Q5EpLDc9VX7iLmpAiL9xFH8UGxh6e6FFmzxGKpF1fWqAJKEgQRbINvFtKWBhx828
YMMElEG0u/3uJEcGsiPumKF+zGKoyYj8mzf5egnFiFKjzV8LzxSjWAz6FkmqRNUG
XqtxbjGb45uhcQ0=
-----END PUBLIC KEY-----
"#; // openssl adds a newline

    assert_valid_key(private_key, public_key);
}

#[test]
fn fp_invalid_key_dsa_1() {
    let private_key = r#"-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCoEbdAHInLUX+2kkZdaqG7cNIZk3x8g6UZCo1pqrrbNEkn1k/m
RFOW5bU36URjaiJK2E1/iXdQ2ZDITTqvkZVzEhwF25rllsIz11UoHbsxIkQCV342
RTCRtOIU+KHDgyV5s+/nhAWZe7a/p8PnzMFpWapEBeAvxpVGHJBjszCiEQIVAMXr
ZihRmKMqsIKy/e0XHwHS { This key is invalid} FZRTAoGBAJDBJCYHXk+4
I9KDdRHTFyq9iS+TRYmaLps+m/CKRGpaPGTGCitm4UKbI8jLdIU4SShXWiNCxxYV
xyDBV0KZ3IHhTCxPKzfexQjAAAVQyk8q3bKZvYZRxREisnlepJJLwkrqebaESFON
mZQneQ5vAoGAQ4qHnMA06CR93UWjkGN2Ek/K47W5Q5EpLDc9VX7iLmpAiL9xFH8U
Gxh6e6FFmzxGKpF1fWqAJKEgQRbINvFtKWBhx828YMMElEG0u/3uJEcGsiPumKF+
zGKoyYj8mzf5egnFiFKjzV8LzxSjWAz6FkmqRNUGXqtxbjGb45uhcQ0CFFaKPjsi
1z9fVy7ZdQljvks44bET
-----END DSA PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}
