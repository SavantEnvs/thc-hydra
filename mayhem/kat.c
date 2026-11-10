/* Known-answer tests over hydra's helper library, linked against the project's own objects built
 * with normal flags. Expected values come from RFC test vectors / independent computation. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../bfg.h"
#include "../sasl.h"

extern void hydra_tobase64(unsigned char *buf, uint32_t buflen, uint32_t bufsize);
extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern int32_t hydra_memsearch(char *haystack, int32_t hlen, char *needle, int32_t nlen);
extern char *hydra_string_replace(const char *string, const char *substr, const char *replacement);
extern int32_t hydra_string_match(char *str, const char *regex);
extern char *hydra_address2string(char *address);
extern void hmac_md5(unsigned char key[16], unsigned char *data, int32_t data_len, unsigned char *digest);

static int passed, failed;

#define CHECK(name, cond) do { \
    if (cond) { passed++; printf("ok   %s\n", name); } \
    else { failed++; printf("FAIL %s\n", name); } } while (0)

static int streq(const char *a, const char *b) { return a != NULL && b != NULL && strcmp(a, b) == 0; }

int main(void) {
  char buf[256], *s;
  unsigned char dig[16], key[16] = {'J', 'e', 'f', 'e'};
  char addr[32] = {4, 10, 1, 2, 3};
  char addr6[32] = {16};
  int k;

  memset(buf, 0, sizeof(buf));
  strcpy(buf, "user:password");
  hydra_tobase64((unsigned char *)buf, 13, sizeof(buf));
  CHECK("base64 encode", streq(buf, "dXNlcjpwYXNzd29yZA=="));

  memset(buf, 0, sizeof(buf));
  from64tobits(buf, "dXNlcjpwYXNzd29yZA==");
  CHECK("base64 decode", streq(buf, "user:password"));

  CHECK("strcasestr hit", streq(hydra_strcasestr("HTTP/1.1 200 OK", "200 ok"), "200 OK"));
  CHECK("strcasestr miss", hydra_strcasestr("HTTP/1.1 200 OK", "404") == NULL);
  CHECK("memsearch", hydra_memsearch("abcdef", 6, "cde", 3) == 2 && hydra_memsearch("abcdef", 6, "x", 1) == -1);

  s = hydra_string_replace("login=^USER^&pass=^PASS^", "^USER^", "admin");
  CHECK("string_replace", streq(s, "login=admin&pass=^PASS^"));
  free(s);

  CHECK("string_match caseless", hydra_string_match("Welcome Back", "^welcome") != 0);
  CHECK("string_match miss", hydra_string_match("Access denied", "^welcome") == 0);

  CHECK("address2string v4", streq(hydra_address2string(addr), "10.1.2.3"));
  addr6[16] = 1;
  CHECK("address2string v6", streq(hydra_address2string(addr6), "::1"));

  hmac_md5(key, (unsigned char *)"what do ya want for nothing?", 28, dig);
  snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x%02x%02x", dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7]);
  CHECK("hmac_md5 RFC 2202 (Jefe)", streq(buf, "750c783e6ab0b503"));

  memset(buf, 0, sizeof(buf));
  sasl_plain(buf, "tim", "tanstaaftuccr");
  CHECK("sasl PLAIN", streq(buf, "dGltAHRpbQB0YW5zdGFhZnR1Y2Ny"));

  memset(buf, 0, sizeof(buf));
  sasl_cram_md5(buf, "tanstaaftuccr", "<1896.697170952@postoffice.reston.mci.net>");
  CHECK("sasl CRAM-MD5", streq(buf, "3ccf13150f6ce6aee99ee3aed2948184"));
  memset(buf, 0, sizeof(buf));
  sasl_cram_sha1(buf, "tanstaaftuccr", "<1896.697170952@postoffice.reston.mci.net>");
  CHECK("sasl CRAM-SHA1", streq(buf, "d716bb9751bfbd8674722cde063afd294b9348e6"));
  memset(buf, 0, sizeof(buf));
  sasl_cram_sha256(buf, "tanstaaftuccr", "<1896.697170952@postoffice.reston.mci.net>");
  CHECK("sasl CRAM-SHA256", streq(buf, "f109c71e544ab523092010d22b2cf1c09b73fb5bb4776435ab6e6c61d551a400"));

  {
    char arg[] = "1:2:bc";
    static const char *want[] = {"b", "c", "bb", "bc", "cb", "cc"};
    int ok;

    memset(&bf_options, 0, sizeof(bf_options));
    ok = bf_init(arg) == 0;
    for (k = 0; ok && k < 6; k++) {
      char *w = bf_next();
      ok = w != NULL && streq(w, want[k]);
    }
    ok = ok && bf_next() == NULL;
    CHECK("bfg -x 1:2:bc sequence", ok);
  }

  printf("%d passed, %d failed\n", passed, failed);
  return failed != 0;
}
