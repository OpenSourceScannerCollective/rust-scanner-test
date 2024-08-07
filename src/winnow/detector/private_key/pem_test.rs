use crate::winnow::detector::private_key;

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
KrNsCithPEygwLsHI6tSRPavOqctkrv1SHrRwGziVocQnrdAOgDC6F=="#;
        let mut input = test_case;

        let result = private_key::pem::pem_data.parse_next(&mut input);
        assert_eq!(result.is_err(), false);

        let mut result_value = String::from(test_case);
        result_value.retain(|c| !c.is_whitespace());
        assert_eq!(result_value, result.unwrap().to_owned());
    }

    #[test]
    fn tp_valid_key_1() {
        let label = r#"RSA PRIVATE KEY"#;
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
-----END RSA PRIVATE KEY-----"#;
        let input = test_case;

        let result = private_key::pem::parse(input);
        assert_eq!(result.is_err(), false);
        assert_eq!(label, result.unwrap().0.to_owned());
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