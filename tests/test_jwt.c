#include "unity.h"
#include <jwt_validator.h>
#include <string.h>

void setUp(void) {
}

void tearDown(void) {
}


void test_case1(void) {
  const unsigned char case1[] = "1.2.3";
  int signature_pos;
  int result = split_jwt(case1, strlen(case1), &signature_pos);
  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL(4, signature_pos);
  TEST_ASSERT_EQUAL('3', case1[signature_pos]);
  TEST_ASSERT_EQUAL_STRING("3", &case1[signature_pos]);
}


void test_case2(void) {
  const unsigned char case2[] = "";
  int signature_pos;
  int result = split_jwt(case2, strlen(case2), &signature_pos);
  TEST_ASSERT_EQUAL(-1, result);
}


void test_case3(void) {
  const unsigned char case3[] = ".";
  int signature_pos;
  int result = split_jwt(case3, strlen(case3), &signature_pos);
  TEST_ASSERT_EQUAL(-1, result);
}


void test_case4(void) {
  const unsigned char case4[] = "..";
  int signature_pos;
  int result = split_jwt(case4, strlen(case4), &signature_pos);
  TEST_ASSERT_EQUAL(1, result);
}

void test_case5(void) {
  const unsigned char case5[] = "...";
  int signature_pos;
  int result = split_jwt(case5, strlen(case5), &signature_pos);
  TEST_ASSERT_EQUAL(-1, result);
}


void test_case6(void) {
  const char secret[] = "test 123";
  const char body[] = "abcd";
  unsigned char expected_sig[64];
  unsigned int expected_sig_len = 0;

  int result = cacl_hmac(secret, strlen(secret), body, strlen(body),
                         expected_sig, &expected_sig_len);
  TEST_ASSERT_EQUAL(0, result);

  unsigned char expected[] = {
      0x63, 0x62, 0x1b, 0xac, 0x4a, 0xba, 0x1a, 0x24, 0x77, 0x25, 0x0f, 0x0f,
      0xdb, 0xaa, 0x1c, 0x4f, 0xfc, 0xfc, 0xbc, 0xba, 0xdf, 0x68,
      0xb8, 0x1f, 0x23, 0xc9, 0x7c, 0xb9, 0x44, 0xd6, 0xf5, 0x9f
  };
  TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, expected_sig, 2);;
}

void test_case7(void) {
  const char secret[] = "test_123";
  const char jwt[] =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm8ifQ.qNYjRtlEVZFJGi5O1kxhsyUWqpuenbkUnqt23hqWRJs";
  unsigned char expected_sig[64];
  unsigned int expected_sig_len = 0;

  int result = verify_jwt(jwt, strlen(jwt), secret, strlen(secret));
  TEST_ASSERT_EQUAL(1, result);
}

void test_case8(void) {
  const char secret[] = "test_321";
  const char jwt[] =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm8ifQ.qNYjRtlEVZFJGi5O1kxhsyUWqpuenbkUnqt23hqWRJs";

  int result = verify_jwt(jwt, strlen(jwt), secret, strlen(secret));
  TEST_ASSERT_EQUAL(0, result);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_case1);
  RUN_TEST(test_case2);
  RUN_TEST(test_case3);
  RUN_TEST(test_case4);
  RUN_TEST(test_case5);
  RUN_TEST(test_case6);
  RUN_TEST(test_case7);
  RUN_TEST(test_case8);
  return UNITY_END();
}