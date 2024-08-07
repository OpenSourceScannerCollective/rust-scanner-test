use crate::detector::winnow::private_key;

mod tests {
    use winnow::Parser;
    use super::*;

    #[test]
    fn tp_valid_label_1() {
        let test_case = r#"RSA PRIVATE KEY"#;
        let mut input = test_case;

        let result = private_key::pem::pem_label.parse_next(&mut input);
        assert_eq!(result.is_err(), false);
        assert_eq!(test_case, result.unwrap().to_owned());
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
        let test_case = r#"RSA PRIVATE  KEY"#; // double space
        let mut input = test_case;

        let result = private_key::pem::pem_label.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_invalid_label_3() {
        let test_case = r#" RSA PRIVATE KEY"#; // start with space
        let mut input = test_case;

        let result = private_key::pem::pem_label.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_invalid_label_4() {
        let test_case = r#"RSA PRIVATE KEY "#; // end with space
        let mut input = test_case;

        let result = private_key::pem::pem_label.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_valid_header_1() {
        let label = r#"RSA PRIVATE KEY"#;
        let test_case = r#"-----BEGIN RSA PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), false);
        assert_eq!(label, result.unwrap().0.to_owned());
    }

    #[test]
    fn tp_valid_data_1() {
        let test_case = r#"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMTRu62muZ7xoKoJ
CSO2Pi6TGWGYn5QfUc9iL6zcy6F2BUkx49e+9UFfDQvYAzyUCwCGKJgHEhm2Afkf
p4P22JO5YSGJQxPSozNlbQ3T+RZoh0nQpD5ijkqD4GZZylanNFcnQcK+tFKv9Jvp
d+lxCUoP9jhEHG8BYkbiCPnSDIpFAgMBAAECgYB/fzXKmdRoyDHBtDS9c5L4bMXm
WQ4Wz+sZIouruSQYJfHqpmzoF4WcoUw8PeRq26P85OtrADmTejnw/bZwX/mPJZfK
xKZFxnR5uo1xWReG7/MfC5Sm8iDNPozt7kx+M+xvT/qpPiTCASCB+lQlkZ8j8bLo
G2z05uvEQxwaUPTziQJBAOCgw1afMS0E1PDpgDs4MkZwMuDxvgGUgqamoyPDOTMS
d3Nfu1iz1vIBl5BZefuV3/gXQVglfPxuExqMI27IJEsCQQDgTrYW2O9qCkggK6Kv
xV2CYLXoklJpu51YF894AZB7ALN5yh5OzFi7cAywTPnZl/7QQLyuc57wHz/uOPdz
QFGvAkBHfoONv29Mb9xCrV8V+iXuS2m2NNsP76/B0QndqRY8jiUcwJyFd//y2NTf
qcrsa2B0uxoeLxhf070a1v20FdmPAkABNUtTyi1X8+A5lCKXMcf0KNMyAn/BJAqP
6+jpK5D8qJ9O26DYKc+citj2piN+YYw00PRzOBo2DuUIQnRKwaDvAkEA3IHe/85U
3hHh+/4B6CPDmb84WwHStDWaVkbuJ5oLwgeIdr+Z5Z7bdnHl74uN72s9Ertt2cwc
lLWxWrkO5VhnBQ=="#;
        let mut input = test_case;

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), false);

        let mut result_value = String::from(test_case);
        result_value.retain(|c| !c.is_whitespace());
        assert_eq!(result_value, result.unwrap().to_owned());
    }

    #[test]
    fn tp_valid_key_1() {
        let label = r#"PRIVATE KEY"#;
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
        let input = test_case;

        let mut pem_data = String::from(r#"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANd4azcpShA5I9Vs
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
vhj3eVN6voMtw7o="#);
        pem_data.retain(|c| !c.is_whitespace());

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), false);

        let r = result.unwrap();
        assert_eq!(label, r.0.to_owned());
        assert_eq!(pem_data, r.1.to_owned());
    }

    #[test]
    fn tp_invalid_key_1() { // extra dash in header
        let test_case = r#"-----BEGIN RSA PRIVATE KEY------
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
        let input = test_case;

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_invalid_key_2() { // dash in header
        let test_case = r#"-----BEGIN RSA -- PRIVATE KEY-----
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
        let input = test_case;

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_invalid_key_3() { // invalid data
        let test_case = r#"-----BEGIN RSA PRIVATE KEY-----
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
        let input = test_case;

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn tp_invalid_key_4() { // header and footer do not match
        let test_case = r#"-----BEGIN RSA PRIVATE KEY-----
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
        let input = test_case;

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_header_1() {
        let test_case = r#"-----BEGIN RSA--PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_header_2() {
        let test_case = r#"-----BEGIN RSA  PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_header_3() {
        let test_case = r#"-----BEGIN  RSA PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    // TODO: test additional dash in header
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
        let test_case = r#"-----END RSA--PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_footer_2() {
        let test_case = r#"-----END RSA  PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_footer_3() {
        let test_case = r#"-----END  RSA PRIVATE KEY-----"#;
        let mut input = test_case;

        let result = private_key::pem::pem_header.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    // TODO: test additional dash in header
    // #[test]
    // fn fp_invalid_footer_4() {
    //     let test_case = r#"-----BEGIN RSA PRIVATE KEY------"#;
    //     let mut input = test_case;
    //
    //     let result = private_key::pem::pem_header.parse_next(&mut input);
    //     assert_eq!(result.is_err(), true);
    // }

    #[test]
    fn fp_invalid_data_1() { // contains invalid tokens at 419th char
        let mut valid_str = String::from(r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
cmeGR3c3bestelR+y7uIMZY43qfDJf03wEj0VBrZ8vs6vqCLXViaLvVyq2haLLq/
nKpp+qsjalYqBNjrEN2knvKeEL4+eUkdO8uA8V3mx4VxDWu/Lvgwp3qAt25Y7+7u
OUDBA/aKSUYjXUjZfIEZwzrK4Df/PUSA6tC3zth29ycirvI5yxJSIOEL/RNvSIMT
+ezRj/Cmv5SQOlF7XJsLs4++v9wwpH6QpflTvk9nEJ9kfa/w54gG8gsQ6xg/TqNN
IfwZpPBbhnMciwGyN2UmoaI3GlJ8VStpAB08b5ZrFRqJDFTvdvK8109s2EVZkVXp
ndu93dlLim2aZJBEevYcbsKd2QzQ4"#);
        valid_str.retain(|c| !c.is_whitespace());

        let test_case = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
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
        let mut input = test_case;

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_data_2() { // incorrect number of padding characters
        let test_case = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
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
        let mut input = test_case;

        let mut valid_str = String::from(test_case);
        valid_str.retain(|c| !c.is_whitespace());

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_data_3() { // incorrect number of padding characters
        let test_case = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
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
        let mut input = test_case;

        let mut valid_str = String::from(test_case);
        valid_str.retain(|c| !c.is_whitespace());

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn fp_invalid_data_4() { // incorrect number of padding characters
        let test_case = r#"ASHpbFXorct33gBiqPfpdxodzouF2sVf2gCAqZHAmnDz9eKAcG3H7x3oPXQbwEtQ
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
        let mut input = test_case;

        let mut valid_str = String::from(test_case);
        valid_str.retain(|c| !c.is_whitespace());

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), true);
    }
}