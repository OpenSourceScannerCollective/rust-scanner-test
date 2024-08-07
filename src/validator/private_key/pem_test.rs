// TODO: Add tests


mod tests {
    use crate::validator;

    #[test]
    fn tp_valid_key_rsa_1() {
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

        let result = validator::private_key::pem::validate_key(test_case);
        assert_eq!(result.is_valid(), true);
    }

    #[test]
    fn fp_invalid_key_rsa_1() {
        let test_case = r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANd4azcpShA5I9Vs
tJDUKoJP5E30EkFc/OM4waLMZ+PHNDghxOiDzrIknA0kUTfBwN+ykOpHYVmIo66/
5tJ5pV6EXXyFtqSyi3rORf+Hr08L3c2F3+S0AahRymSpru2/C25QTRd15Y28DNC3
QzXBG0YVmLiJ44hfuHX1HEVtfM7HAgMBAAECgYAiU9v48MoM5Z2Q3f2yaSrQkfvU
c4MJCNB9PsiSsDAI+O6X1sFxLbabaPu3mEacNHEO8nrl6DNZOUyihY43kAvJRTH4
GPbudkY0suimIfpLJZA/jjElzXFj6klOB18vBS8vSi3c+vqpaX4MyUuVac81fVyT
zIoIw3Lq9Dgkkzov6QJBAPWyQrA9NFQmj8afwY48OxENrH+8sRSxiJd2uqfrL55d
1CRrfOJ5vQdrBiuWPTHIS+KEY+IS+INVALIDwjuwhyxcQnBkVdiPColabS6sbsCQ
YJZ/FPM8mdLIjHryByhu8PhZwLDRWrjvFLcUalKwivBcBGuJosUhsM27LyhVBt/C
GxBlAkEAgrNMdJJqduV4kHHFtlNmHIFIpT8MeHSks+YuD0u2Lim9w44Ghje6jeqq
Ap/PcoIIctkVx9nX5kNUvBrg64pxJwJAdg0X1ufwM6h4PdIjMu3VFPvSLxJ/mL7t
wyhqZXPGU4OUNnGq/uR4pH6H/pcAbpJQba4uVFngxEW2wob7z9hlVQJBAJJxYYYD
gOB36ex0dUdXhOPqQf3EZPMeMS28kKcPMloPWbmz1IFiQK/HWpmr7yb3qKCdvhgP
vhj3eVN6voMtw7o=
-----END PRIVATE KEY-----"#;

        let result = validator::private_key::pem::validate_key(test_case);
        assert_eq!(result.is_valid(), false);
    }

    #[test]
    fn tp_valid_key_dsa_1() {
        let test_case = r#"-----BEGIN DSA PRIVATE KEY-----
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

        let result = validator::private_key::pem::validate_key(test_case);
        assert_eq!(result.is_valid(), true);
    }

    #[test]
    fn fp_invalid_key_dsa_1() {
        let test_case = r#"-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCoEbdAHInLUX+2kkZdaqG7cNIZk3x8g6UZCo1pqrrbNEkn1k/m
RFOW5bU36URjaiJK2E1/iXdQ2ZDITTqvkZVzEhwF25rllsIz11UoHbsxIkQCV342
RTCRtOIU+KHDgyV5s+/nhAWZe7a/p8PnzMFpWapEBeAvxpVGHJBjszCiEQIVAMXr
ZihRmKMqsIKy/e0XHwHSTHIS+KEY+IS+INVALIDFZRTAoGBAJDBJCYHXk+4HExhx
I9KDdRHTFyq9iS+TRYmaLps+m/CKRGpaPGTGCitm4UKbI8jLdIU4SShXWiNCxxYV
xyDBV0KZ3IHhTCxPKzfexQjAAAVQyk8q3bKZvYZRxREisnlepJJLwkrqebaESFON
mZQneQ5vAoGAQ4qHnMA06CR93UWjkGN2Ek/K47W5Q5EpLDc9VX7iLmpAiL9xFH8U
Gxh6e6FFmzxGKpF1fWqAJKEgQRbINvFtKWBhx828YMMElEG0u/3uJEcGsiPumKF+
zGKoyYj8mzf5egnFiFKjzV8LzxSjWAz6FkmqRNUGXqtxbjGb45uhcQ0CFFaKPjsi
1z9fVy7ZdQljvks44bET
-----END DSA PRIVATE KEY-----"#;

        let result = validator::private_key::pem::validate_key(test_case);
        assert_eq!(result.is_valid(), false);
    }

}