use winnow::detector;

mod winnow;
mod vectorscan;
mod pest;
mod chumsky;

fn main() {
    aws_key();
    pem_key();
}


fn aws_key() {
    let test_case = r#"AKIAXR2OBLUTM8DTZV7F"#;
    let result = detector::aws::api_key::parse(test_case);

    if result.is_err() {
        println!("[AWS] Error: {}", result.err().unwrap());
        return;
    }

    println!("[AWS] Result: {}", result.unwrap());
}

fn pem_key() {
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
    let result = detector::private_key::pem::parse(test_case);

    if result.is_err() {
        println!("[PEM] Error: {}", result.err().unwrap());
        return;
    }

    println!("[PEM] Result: {}", result.unwrap().0);
}