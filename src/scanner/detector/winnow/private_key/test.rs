use crate::scanner::detector::winnow::private_key;
use crate::scanner::finding::private_key::test::{assert_invalid_key, assert_valid_key};
use winnow::Parser;

pub fn assert_valid_label(label: &str) {
    let mut input = label;
    let result = private_key::pem::pem_label.parse_next(&mut input);
    assert_eq!(result.is_err(), false);
    assert_eq!(label, result.unwrap().to_owned());
}

pub fn assert_invalid_label(label: &str) {
    let mut input = label;
    let result = private_key::pem::pem_label.parse_next(&mut input);
    assert_eq!(result.is_err(), true);
}

#[test]
fn tp_valid_label_1() {
    assert_valid_label(r#"RSA PRIVATE KEY"#);
}

#[test]
fn tp_invalid_label_1() {
    let label = r#"RSA PRIVATE"#;
    let test_case = r#"RSA PRIVATE-KEY"#; // dash causes parser to quit early
    let mut input = test_case;

    let result = private_key::pem::pem_label.parse_next(&mut input);
    assert_eq!(result.is_err(), false);
    assert_eq!(result.unwrap(), label);
}

#[test]
fn tp_invalid_label_2() {
    // double space
    assert_invalid_label(r#"RSA PRIVATE  KEY"#);
}

#[test]
fn tp_invalid_label_3() {
    // start with space
    assert_invalid_label(r#" RSA PRIVATE KEY"#);
}

#[test]
fn tp_invalid_label_4() {
    // end with space
    assert_invalid_label(r#"RSA PRIVATE KEY "#);
}

pub fn assert_valid_header(label: &str) {
    let test_case = [r#"-----BEGIN "#, label, r"-----"].concat();
    let mut input = test_case.as_str();

    let result = private_key::pem::pem_header.parse_next(&mut input);
    assert_eq!(result.is_err(), false);
    assert_eq!(label, result.unwrap().to_owned());
}

pub fn assert_invalid_header(label: &str) {
    let mut input = label;
    let result = private_key::pem::pem_header.parse_next(&mut input);
    assert_eq!(result.is_err(), true);
}

#[test]
fn tp_valid_header_1() {
    assert_valid_header(r#"RSA PRIVATE KEY"#);
}

#[test]
fn fp_invalid_header_1() {
    assert_invalid_header(r#"-----BEGIN RSA--PRIVATE KEY-----"#);
}

#[test]
fn fp_invalid_header_2() {
    assert_invalid_header(r#"-----BEGIN RSA  PRIVATE KEY-----"#);
}

#[test]
fn fp_invalid_header_3() {
    assert_invalid_header(r#"-----BEGIN  RSA PRIVATE KEY-----"#);
}

// TODO: test trailing dash in header
// #[test]
// fn fp_invalid_header_4() {
//     let test_case = r#"-----BEGIN RSA PRIVATE KEY------"#;
//     let mut input = test_case;
//
//     let result = private_key::pem::pem_header.parse_next(&mut input);
//     assert_eq!(result.is_err(), true);
// }

#[test]
fn fp_invalid_footer_1() {
    assert_invalid_header(r#"-----END RSA--PRIVATE KEY-----"#);
}

#[test]
fn fp_invalid_footer_2() {
    assert_invalid_header(r#"-----END RSA  PRIVATE KEY-----"#);
}

#[test]
fn fp_invalid_footer_3() {
    assert_invalid_header(r#"-----END  RSA PRIVATE KEY-----"#);
}

// TODO: test trailing dash in footer
// #[test]
// fn fp_invalid_footer_4() {
//     let test_case = r#"-----BEGIN RSA PRIVATE KEY------"#;
//     let mut input = test_case;
//
//     let result = private_key::pem::pem_header.parse_next(&mut input);
//     assert_eq!(result.is_err(), true);
// }

#[test]
fn tp_valid_key_1() {
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
-----END PUBLIC KEY-----"#;

    assert_valid_key(private_key, public_key);
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
-----END PUBLIC KEY-----"#;

    assert_valid_key(private_key, public_key);
}

#[test]
fn tp_invalid_key_1() {
    // extra dash in header
    let private_key = r#"-----BEGIN RSA PRIVATE KEY------
ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F==
-----END RSA PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}

#[test]
fn tp_invalid_key_2() {
    // dash in header
    let private_key = r#"-----BEGIN RSA -- PRIVATE KEY-----
ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F==
-----END RSA PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}

#[test]
fn tp_invalid_key_3() {
    // invalid data
    let private_key = r#"-----BEGIN RSA PRIVATE KEY-----
ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2Q < invalid > zLzjQzkSKRBaCosApf4776FfF
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F==
-----END RSA PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}

#[test]
fn tp_invalid_key_4() {
    // header and footer do not match
    let private_key = r#"-----BEGIN RSA PRIVATE KEY-----
ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F==
-----END PGP PRIVATE KEY-----"#;

    assert_invalid_key(private_key);
}

#[test]
fn fp_invalid_data_1() {
    // contains invalid tokens at 419th char
    let private_key = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4{ invalid }WzLaCosApf4776FhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F=="#;

    assert_invalid_key(private_key);
}

#[test]
fn fp_invalid_data_2() {
    // incorrect number of padding characters
    let private_key = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F"#; // 0, should be 2

    assert_invalid_key(private_key);
}

#[test]
fn fp_invalid_data_3() {
    // incorrect number of padding characters
    let private_key = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F="#; // 1, should be 2

    assert_invalid_key(private_key);
}

#[test]
fn fp_invalid_data_4() {
    // incorrect number of padding characters
    let private_key = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4WzLzjQzkSKRBaCosApf4776FfFhXsKK9CCh
v9sg9fRBuZc9y86lGjMDs5A7gSkTsy13+FX7+riqXCRaU4HTAbVQFPeI5N6w/3Nr
NcmLBBcObeKTdqUCpZdCD6VzI4lae04rjhmaHSXoLIcn+D7CsIC0hGHffFRVEk/h
QdPUzYbRfFCBCUABRsgr+pn2epVtUvUPiQOFJc8TjoZgD8vwQ1LSyBDV6aA7MHrV
WeiEfYqbXzm0N8mgW10pW2Ll1BfQ3rstgJ2LbIOb5fFWZy9wZnEikoIrUYI2MTpH
6pNaC7cz5fVYmaDUxQFktp/wLJXM2u+HqMoZoo8cqSGWNX6brAPYDvjk9nGJ3KjI
zmrk4XhFJvj7p1Q+A9NUR4pvfrPsNcqSMLxH8D0FM68+l360EHyerCtqS2mChlvQ
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F==="#; // 3, should be 2

    assert_invalid_key(private_key);
}
