//
// Created by User on 07.03.2026.
//

#ifndef TEST_MODULE_JWT_VALIDATOR_H
#define TEST_MODULE_JWT_VALIDATOR_H

int split_jwt(const unsigned char *jwt, int jwt_len, int *signature_start_pos);

int base64url_to_base64(const char *in, int in_len, unsigned char **out, int *out_len);

int cacl_hmac(
    const unsigned char *jwt_secret,
    const int jwt_secret_len,
    const unsigned char *jwt,
    const int len_jwt,
    unsigned char *sig,
    unsigned int *sig_len
);

int verify_jwt(const unsigned char *jwt, const int len_jwt, const unsigned char *jwt_secret, const int jwt_secret_len);
#endif //TEST_MODULE_JWT_VALIDATOR_H
