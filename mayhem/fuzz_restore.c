/* AFL harness (file input) over hydra's session-restore parser, hydra_restore_read(): it
 * deserializes a ./hydra.restore file written by an earlier run (-R). The input is staged as that
 * file in a private temp dir and read back exactly as `hydra -R` would. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern void hydra_restore_read(void);

static char dir[4096];

static void cleanup(void) {
  if (unlink("hydra.restore") == 0 && chdir("/") == 0)
    rmdir(dir);
}

static void die(const char *what) {
  perror(what);
  abort();
}

int main(int argc, char **argv) {
  static char buf[1 << 20];
  size_t n;
  FILE *f;
  const char *tmp = getenv("TMPDIR");

  if (argc < 2 || (f = fopen(argv[1], "rb")) == NULL)
    return 1;
  n = fread(buf, 1, sizeof(buf), f);
  fclose(f);

  /* hydra_restore_read() opens the fixed name ./hydra.restore, so work inside a private dir under an
   * absolute $TMPDIR, else libc's P_TMPDIR (what tmpfile() uses); mkdtemp keeps a stale dir from a
   * reused pid harmless. A staging failure aborts: returning early would leave the parser unreached. */
  if (tmp == NULL || tmp[0] != '/')
    tmp = P_tmpdir;
  snprintf(dir, sizeof(dir), "%s/hydra-restore-XXXXXX", tmp);
  if (mkdtemp(dir) == NULL) {
    snprintf(dir, sizeof(dir), "%s/hydra-restore-XXXXXX", P_tmpdir);
    if (mkdtemp(dir) == NULL)
      die("mkdtemp");
  }
  if (chdir(dir) != 0)
    die("chdir");
  atexit(cleanup);
  if ((f = fopen("hydra.restore", "wb")) == NULL)
    die("fopen hydra.restore");
  if (fwrite(buf, 1, n, f) != n || fclose(f) != 0)
    die("write hydra.restore");

  hydra_restore_read();
  return 0;
}
