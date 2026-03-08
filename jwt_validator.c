// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java:
// https://pvs-studio.com

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


int split_jwt(const unsigned char *jwt, int jwt_len, int *signature_start_pos) {
  int segments = 0;
  for (int i = 0; i < jwt_len; i++) {
    if (jwt[i] == '.') {
      segments++;
      if (segments == 2 && i != jwt_len - 1) {
        *signature_start_pos = i + 1;
      }
    }
  }
  if (segments != 2) {
    return -1;
  }
  return 1;
}

int base64url_to_base64(const char *in, int in_len, unsigned char **out,
                        int *out_len) {
  int pad = 0;
  if (in_len % 4 != 0) {
    pad = 4 - (in_len % 4);
  }
  *out_len = in_len + pad;
  *out = (unsigned char *)malloc((*out_len) * sizeof(unsigned char));
  if (*out == NULL) {
    return -1;
  }
  strncpy((char *)*out, in, in_len);
  for (int i = in_len; i < in_len + pad; i++) {
    (*out)[i] = '=';
  }
  for (int i = 0; i < *out_len; i++) {
    if ((*out)[i] == '-') {
      (*out)[i] = '+';
    }

    if ((*out)[i] == '_') {
      (*out)[i] = '/';
    }
  }

  return 0;
}


int cacl_hmac(
    const unsigned char *jwt_secret,
    const int jwt_secret_len,
    const unsigned char *jwt,
    const int len_jwt,
    unsigned char *sig,
    unsigned int *sig_len
    ) {
  const unsigned char *result = HMAC(
      EVP_sha256(),
      jwt_secret,
      jwt_secret_len,
      jwt,
      len_jwt,
      sig,
      sig_len
      );
  if (result == NULL) {
    return -1;
  }
  return 0;
}


int base64url_decode_openssl(const char *in, int size, char *out_buffer,
                             int *out_len) {
  BIO *mem_bio;
  *out_len = 0;

  int len_b64 = 0;
  unsigned char *base64 = NULL;
  if (base64url_to_base64(in, size, &base64, &len_b64) < 0) {
    return -1;
  }

  // Не создает копию буфера, создает обертку, буфер должен жить до заверщения процесса
  mem_bio = BIO_new_mem_buf(base64, len_b64);

  if (mem_bio == NULL) {
    return -1;
  }

  BIO *b64_filter = BIO_new(BIO_f_base64());

  if (b64_filter == NULL) {
    BIO_free(mem_bio);
    return -1;
  }

  BIO_set_flags(b64_filter, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64_filter, mem_bio);
  const int final_len = BIO_read(b64_filter, out_buffer, size);

  if (final_len < 0) {
    BIO_free_all(b64_filter);
    free(base64);
    return -1;
  }
  *out_len = final_len;
  BIO_free_all(b64_filter);
  free(base64);
  return 0;
}


int verify_jwt(const unsigned char *jwt, const int len_jwt,
               const unsigned char *jwt_secret, const int jwt_secret_len) {
  int signature_start_pos = 0;
  if (split_jwt(jwt, len_jwt, &signature_start_pos) < 0) {
    return 0;
  }
  const int body_len = signature_start_pos - 1;
  const unsigned char *signature = &jwt[signature_start_pos];
  const int len_signature = len_jwt - signature_start_pos;
  unsigned char expected_sig[EVP_MAX_MD_SIZE];
  unsigned int expected_sig_len = 0;

  if (cacl_hmac(jwt_secret, jwt_secret_len, jwt, body_len, expected_sig,
                &expected_sig_len) < 0) {
    return 0;
  }
  // printf("Ecpected sign: ");
  // for (int i = 0; i < expected_sig_len; i++) {
  //     printf("%02x", expected_sig[i]);
  // }
  // printf("\n");
  unsigned char *got_signature = (unsigned char *)malloc(
      EVP_MAX_MD_SIZE * sizeof(unsigned char));
  unsigned int len_got_signature = 0;
  if (base64url_decode_openssl((const char *)signature, len_signature,
                               (char *)got_signature,
                               (int *)&len_got_signature) < 0) {
    free(got_signature);
    return 0;
  }
  // printf("Got sign: ");
  // for (int i = 0; i < len_got_signature; i++) {
  //     printf("%02x", (unsigned char) got_signature[i]);
  // }
  printf("\n");
  printf("Got sign: %d %d", expected_sig_len, len_got_signature);
  if (expected_sig_len != len_got_signature) {
    free(got_signature);
    return 0;
  }
  const int is_valid_jwt = memcmp(expected_sig, got_signature,
                                  len_got_signature);
  free(got_signature);
  return is_valid_jwt == 0;
}