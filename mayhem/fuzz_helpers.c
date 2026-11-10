/* libFuzzer harness over hydra's pure, in-process helpers: string utilities, base64, SASL/NTLM
 * computations, the -x brute-force generator and the address formatter. Input: one op byte, then
 * NUL-separated string arguments. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sasl.h"
#include "../bfg.h"

extern void hydra_tobase64(unsigned char *buf, uint32_t buflen, uint32_t bufsize);
extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern int32_t hydra_memsearch(char *haystack, int32_t hlen, char *needle, int32_t nlen);
extern char *hydra_strrep(char *string, char *oldpiece, char *newpiece);
extern int32_t hydra_string_match(char *str, const char *regex);
extern char *hydra_string_replace(const char *string, const char *substr, const char *replacement);
extern char *hydra_address2string(char *address);
extern char *hydra_address2string_beautiful(char *address);
extern int32_t make_to_lower(char *buf);
extern void hmac_md5(unsigned char key[16], unsigned char *data, int32_t data_len, unsigned char *digest);

#define MAXARGS 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *args[MAXARGS];
  size_t lens[MAXARGS];
  char *copy;
  size_t i, n = 0;
  uint8_t op;

  /* hydra's callers never hand these helpers more than a few KB (its own limits are 6000) */
  if (size < 1 || size > 4000)
    return -1;
  op = data[0];
  copy = malloc(size + 1);
  if (copy == NULL)
    return -1;
  memcpy(copy, data + 1, size - 1);
  copy[size - 1] = 0;
  for (i = 0; i < MAXARGS; i++) {
    args[i] = "";
    lens[i] = 0;
  }
  {
    char *p = copy, *end = copy + size - 1;

    while (n < MAXARGS && p <= end) {
      char *z = memchr(p, 0, (size_t)(end - p) + 1);

      args[n] = p;
      lens[n] = (size_t)(z - p);
      n++;
      p = z + 1;
    }
  }

  switch (op % 13) {
  case 0: { /* base64 encode in a buffer the size a module would pass */
    uint32_t bufsize = (uint32_t)(lens[0] * 3 / 2 + 8);
    unsigned char *buf = calloc(bufsize, 1);

    memcpy(buf, args[0], lens[0]);
    hydra_tobase64(buf, (uint32_t)lens[0], bufsize);
    free(buf);
    break;
  }
  case 1:
    hydra_strcasestr(args[0], args[1]);
    break;
  case 2: {
    char *h = malloc(lens[0] + 1), *nd = malloc(lens[1] + 1);

    memcpy(h, args[0], lens[0]);
    memcpy(nd, args[1], lens[1]);
    hydra_memsearch(h, (int32_t)lens[0], nd, (int32_t)lens[1]);
    free(h);
    free(nd);
    break;
  }
  case 3:
    hydra_strrep(args[0], args[1], args[2]);
    break;
  case 4: {
    char *r = hydra_string_replace(args[0], args[1], args[2]);

    free(r);
    break;
  }
  case 5:
    hydra_string_match(args[0], args[1]);
    break;
  case 6: { /* ip[0] is the address family tag, then 4 or 16 raw bytes */
    char addr[64];

    memset(addr, 0, sizeof(addr));
    addr[0] = (op & 0x80) ? 16 : 4;
    memcpy(addr + 1, args[0], lens[0] > 16 ? 16 : lens[0]);
    hydra_address2string(addr);
    hydra_address2string_beautiful(addr);
    break;
  }
  case 7: {
    unsigned char key[16], digest[16];

    memset(key, 0, sizeof(key));
    memcpy(key, args[0], lens[0] > 16 ? 16 : lens[0]);
    hmac_md5(key, (unsigned char *)args[1], (int32_t)lens[1], digest);
    break;
  }
  case 8: {
    char result[256];
    char *r;

    memset(result, 0, sizeof(result));
    sasl_plain(result, args[0], args[1]);
    memset(result, 0, sizeof(result));
    r = sasl_cram_md5(result, args[0], args[1]);
    (void)r;
    memset(result, 0, sizeof(result));
    sasl_cram_sha1(result, args[0], args[1]);
    memset(result, 0, sizeof(result));
    sasl_cram_sha256(result, args[0], args[1]);
    break;
  }
  case 9: { /* base64 decode with a bounded and an (as in the callers) pre-sized output */
    int32_t outlen = (int32_t)((op / 13) % 32);
    char *out = malloc((size_t)outlen + 1);
    char *big = malloc(lens[0] + 8);

    from64tobits_n(out, args[0], outlen);
    from64tobits(big, args[0]);
    free(out);
    free(big);
    break;
  }
  case 10: {
    unsigned char *out = malloc(lens[0] / 3 * 4 + 8);

    to64frombits(out, (unsigned char *)args[0], (int32_t)lens[0]);
    free(out);
    break;
  }
  case 11: { /* -x MIN:MAX:CHARSET brute-force generator */
    char *arg;
    int k;

    if (lens[0] > 100) { /* longer charsets hit bf_init's free-then-continue error path, after which hydra exits */
      free(copy);
      return -1;
    }
    arg = strdup(args[0]);
    memset(&bf_options, 0, sizeof(bf_options));
    if (bf_init(arg) == 0) {
      for (k = 0; k < 64; k++) {
        char *w = bf_next();

        if (w == NULL)
          break;
        free(w); /* hydra's caller owns each generated candidate */
      }
      free(bf_options.crs);
    }
    free(arg);
    break;
  }
  case 12: { /* NTLM type 3 response from a server-supplied type 2 challenge, in the callers' 4096-byte buffers */
    unsigned char *ch = calloc(4096, 1);
    unsigned char *resp = calloc(4096, 1);

    memcpy(ch, args[0], lens[0] > 4096 ? 4096 : lens[0]);
    buildAuthResponse((tSmbNtlmAuthChallenge *)ch, (tSmbNtlmAuthResponse *)resp, 0, args[1], args[2], NULL, args[3]);
    free(ch);
    free(resp);
    break;
  }
  }
  make_to_lower(copy);
  free(copy);
  return 0;
}
