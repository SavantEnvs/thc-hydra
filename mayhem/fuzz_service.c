/* AFL harness (file input) over hydra's protocol modules. A module runs exactly as hydra's child
 * process runs it, but connect() is replaced (below) so that the "server" is the fuzz input: the
 * module's socket is spliced onto a socketpair whose far end replays the input's messages.
 *
 * Input: [service][options] then sections separated by the 2-byte delimiter DE AD:
 *   miscptr, login, password, then server message 1, 2, ...  */
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define SVC(name) extern void service_##name(char *, int32_t, unsigned char, char *, FILE *, int32_t, char *);
#define INIT(name) extern int32_t service_##name##_init(char *, int32_t, unsigned char, char *, FILE *, int32_t, char *);
SVC(adam6500) SVC(asterisk) SVC(cisco) SVC(cisco_enable) SVC(cobaltstrike) SVC(cvs) 
SVC(ftp) SVC(ftps) SVC(http_get) SVC(http_get_form) SVC(http_head) SVC(http_post) 
SVC(http_post_form) SVC(http_proxy) SVC(http_proxy_urlenum) SVC(icq) SVC(imap) SVC(irc) 
SVC(ldap2) SVC(ldap3) SVC(ldap3_cram_md5) SVC(ldap3_digest_md5) SVC(mssql) SVC(mysql) 
SVC(nntp) SVC(oracle_listener) SVC(oracle_sid) SVC(pcanywhere) SVC(pcnfs) SVC(pop3) 
SVC(redis) SVC(rexec) SVC(rlogin) SVC(rpcap) SVC(rsh) SVC(rtsp) 
SVC(s7_300) SVC(sip) SVC(smb) SVC(smtp) SVC(smtp_enum) SVC(snmp) 
SVC(socks5) SVC(teamspeak) SVC(telnet) SVC(vmauthd) SVC(vnc) 
INIT(adam6500) INIT(asterisk) INIT(cisco) INIT(cisco_enable) INIT(cobaltstrike) INIT(cvs) 
INIT(ftp) INIT(http) INIT(http_form) INIT(http_proxy) INIT(http_proxy_urlenum) INIT(icq) 
INIT(imap) INIT(irc) INIT(ldap) INIT(mssql) INIT(mysql) INIT(nntp) 
INIT(oracle_listener) INIT(oracle_sid) INIT(pcanywhere) INIT(pcnfs) INIT(pop3) INIT(redis) 
INIT(rexec) INIT(rlogin) INIT(rpcap) INIT(rsh) INIT(rtsp) INIT(s7_300) 
INIT(sip) INIT(smb) INIT(smtp) INIT(smtp_enum) INIT(snmp) INIT(socks5) 
INIT(teamspeak) INIT(telnet) INIT(vmauthd) INIT(vnc) 

typedef void (*service_fn)(char *, int32_t, unsigned char, char *, FILE *, int32_t, char *);
typedef int32_t (*service_init_fn)(char *, int32_t, unsigned char, char *, FILE *, int32_t, char *);

static const struct {
  const char *name;
  service_fn fn;
  service_init_fn init;
  int32_t port;
} services[] = {
    {"adam6500", service_adam6500, service_adam6500_init, 80},
    {"asterisk", service_asterisk, service_asterisk_init, 5038},
    {"cisco", service_cisco, service_cisco_init, 23},
    {"cisco_enable", service_cisco_enable, service_cisco_enable_init, 23},
    {"cobaltstrike", service_cobaltstrike, service_cobaltstrike_init, 50050},
    {"cvs", service_cvs, service_cvs_init, 2401},
    {"ftp", service_ftp, service_ftp_init, 21},
    {"ftps", service_ftps, service_ftp_init, 990},
    {"http_head", service_http_head, service_http_init, 80},
    {"http_get", service_http_get, service_http_init, 80},
    {"http_post", service_http_post, service_http_init, 80},
    {"http_get_form", service_http_get_form, service_http_form_init, 80},
    {"http_post_form", service_http_post_form, service_http_form_init, 80},
    {"http_proxy", service_http_proxy, service_http_proxy_init, 3128},
    {"http_proxy_urlenum", service_http_proxy_urlenum, service_http_proxy_urlenum_init, 3128},
    {"icq", service_icq, service_icq_init, 4000},
    {"imap", service_imap, service_imap_init, 143},
    {"irc", service_irc, service_irc_init, 6667},
    {"ldap2", service_ldap2, service_ldap_init, 389},
    {"ldap3", service_ldap3, service_ldap_init, 389},
    {"ldap3_cram_md5", service_ldap3_cram_md5, service_ldap_init, 389},
    {"ldap3_digest_md5", service_ldap3_digest_md5, service_ldap_init, 389},
    {"mssql", service_mssql, service_mssql_init, 1433},
    {"mysql", service_mysql, service_mysql_init, 3306},
    {"nntp", service_nntp, service_nntp_init, 119},
    {"oracle_listener", service_oracle_listener, service_oracle_listener_init, 1521},
    {"oracle_sid", service_oracle_sid, service_oracle_sid_init, 1521},
    {"pcanywhere", service_pcanywhere, service_pcanywhere_init, 5632},
    {"pcnfs", service_pcnfs, service_pcnfs_init, 111},
    {"pop3", service_pop3, service_pop3_init, 110},
    {"redis", service_redis, service_redis_init, 6379},
    {"rexec", service_rexec, service_rexec_init, 512},
    {"rlogin", service_rlogin, service_rlogin_init, 513},
    {"rpcap", service_rpcap, service_rpcap_init, 2002},
    {"rsh", service_rsh, service_rsh_init, 514},
    {"rtsp", service_rtsp, service_rtsp_init, 554},
    {"s7_300", service_s7_300, service_s7_300_init, 102},
    {"sip", service_sip, service_sip_init, 5060},
    {"smb", service_smb, service_smb_init, 445},
    {"smtp", service_smtp, service_smtp_init, 25},
    {"smtp_enum", service_smtp_enum, service_smtp_enum_init, 25},
    {"snmp", service_snmp, service_snmp_init, 161},
    {"socks5", service_socks5, service_socks5_init, 1080},
    {"teamspeak", service_teamspeak, service_teamspeak_init, 8767},
    {"telnet", service_telnet, service_telnet_init, 23},
    {"vmauthd", service_vmauthd, service_vmauthd_init, 902},
    {"vnc", service_vnc, service_vnc_init, 5900},
};
#define NSERVICES (sizeof(services) / sizeof(services[0]))

extern int32_t waittime, conwait;

#define MAXIN 32768
#define MAXMSG 64
static const unsigned char DELIM[2] = {0xde, 0xad};

static unsigned char *msg_ptr[MAXMSG];
static size_t msg_len[MAXMSG];
static int n_msgs, n_connects, n_timeouts, ctl_fd = -1;

/* The environment mock: connect() hands the module a socketpair end instead of reaching a host. The
 * other end is "the server": when the module waits for data (select with a timeout of a second or
 * more, or a blocking read) or polls after it has written something, and nothing is queued, the
 * server speaks the next scripted message. After the last one a wait times out at once and a poll or
 * read sees EOF. Nothing depends on timing, and the module never sleeps. */
#define MAXCONN 32
#define MAXCONNECTS 12
static struct {
  int fd, peer, next, sent;
} conn[MAXCONN];
static int n_conn;

static int conn_find(int fd) {
  int i;

  for (i = 0; i < n_conn; i++)
    if (conn[i].fd == fd)
      return i;
  return -1;
}

static int conn_pending(int i) {
  char c;

  return recv(conn[i].fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) > 0;
}

static void conn_wake(int i, int waiting) {
  if ((!waiting && !conn[i].sent) || conn_pending(i))
    return;
  conn[i].sent = 0;
  if (conn[i].next < n_msgs) {
    if (msg_len[conn[i].next] > 0) /* an empty message is a silent server */
      send(conn[i].peer, msg_ptr[conn[i].next], msg_len[conn[i].next], MSG_DONTWAIT | MSG_NOSIGNAL);
    conn[i].next++;
  }
  if (conn[i].next >= n_msgs)
    shutdown(conn[i].peer, SHUT_WR); /* peer stays open so the module's writes succeed */
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
  int sv[2], i = conn_find(fd);

  (void)addr;
  (void)len;
  if (n_connects >= MAXCONNECTS) /* a server that has taken this many connections is done with us */
    exit(0);
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0)
    return -1;
  dup2(sv[1], fd);
  close(sv[1]);
  if (i >= 0) {
    close(conn[i].peer);
  } else if (n_conn < MAXCONN) {
    i = n_conn++;
  } else {
    close(sv[0]);
    return -1;
  }
  conn[i].fd = fd;
  conn[i].peer = sv[0];
  conn[i].sent = 0;
  conn[i].next = ++n_connects <= 3 ? 0 : n_msgs; /* the first three connections replay the script */
  if (conn[i].next >= n_msgs)
    shutdown(conn[i].peer, SHUT_WR);
  return 0;
}

int select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv) {
  static int (*real)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
  int fd;

  if (real == NULL)
    real = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *))dlsym(RTLD_NEXT, "select");
  if (r != NULL) {
    int waiting = tv != NULL && tv->tv_sec > 0, cleared = 0, left = 0;

    for (fd = 0; fd < nfds; fd++)
      if (FD_ISSET(fd, r)) {
        int i = conn_find(fd);

        if (i >= 0) {
          conn_wake(i, waiting);
          if (waiting && !conn_pending(i)) { /* a silent server: the wait times out */
            if (++n_timeouts > 64) /* hydra_receive_line returns "" on a timeout and several modules re-read forever */
              exit(0);
            FD_CLR(fd, r);
            cleared = 1;
            continue;
          }
        }
        left = 1;
      }
    if (cleared && !left && w == NULL && e == NULL)
      return 0;
  }
  return real(nfds, r, w, e, tv);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
  static ssize_t (*real)(int, void *, size_t, int);
  int i = conn_find(fd);

  if (real == NULL)
    real = (ssize_t(*)(int, void *, size_t, int))dlsym(RTLD_NEXT, "recv");
  if (i >= 0 && !(flags & MSG_PEEK)) {
    conn_wake(i, 1);
    if (!conn_pending(i) && conn[i].next < n_msgs)
      return 0;
  }
  return real(fd, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t len) {
  static ssize_t (*real)(int, void *, size_t);
  int i = conn_find(fd);

  if (real == NULL)
    real = (ssize_t(*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
  /* fd 0 is hydra's intern_socket until a module registers its own; either way the parent's replies are
   * scripted, and once they run out it has nothing more to say */
  if (fd == ctl_fd || fd == 0) {
    ssize_t n = recv(ctl_fd, buf, len, MSG_DONTWAIT);

    if (n <= 0)
      exit(0);
    return n;
  }
  if (i >= 0) {
    conn_wake(i, 1);
    if (!conn_pending(i) && conn[i].next < n_msgs)
      return 0;
  }
  return real(fd, buf, len);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
  static ssize_t (*real)(int, const void *, size_t, int);
  int i = conn_find(fd);

  if (real == NULL)
    real = (ssize_t(*)(int, const void *, size_t, int))dlsym(RTLD_NEXT, "send");
  if (i >= 0)
    conn[i].sent = 1;
  return real(fd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t len) {
  static ssize_t (*real)(int, const void *, size_t);
  int i = conn_find(fd);

  if (real == NULL)
    real = (ssize_t(*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
  if (i >= 0)
    conn[i].sent = 1;
  return real(fd, buf, len);
}

static size_t find_delim(const unsigned char *p, size_t len) {
  size_t i;

  for (i = 0; i + 1 < len; i++)
    if (p[i] == DELIM[0] && p[i + 1] == DELIM[1])
      return i;
  return len;
}

int main(int argc, char **argv) {
  static unsigned char in[MAXIN];
  static unsigned char hydra_exit[5] = {0x00, 0xff, 0x00, 0xff, 0x00};
  char ip[64], *sec[3];
  size_t sec_len[3], len, pos, k;
  int ctl[2], i;
  FILE *in_f, *fp;
  unsigned char options;

  if (argc < 2 || (in_f = fopen(argv[1], "rb")) == NULL)
    return 1;
  len = fread(in, 1, sizeof(in), in_f);
  fclose(in_f);
  if (len < 2)
    return -1;

  signal(SIGPIPE, SIG_IGN);
  waittime = 3;
  conwait = 0; /* hydra sleeps conwait seconds before every reconnect */

  options = in[1] & (unsigned char)~1; /* OPTION_SSL would run a TLS handshake against the script */
  pos = 2;
  for (k = 0; k < 3; k++) {
    size_t d = find_delim(in + pos, len - pos);

    sec[k] = malloc(d + 1);
    memcpy(sec[k], in + pos, d);
    sec[k][d] = 0;
    sec_len[k] = strlen(sec[k]);
    pos += d + 2 <= len - pos ? d + 2 : len - pos;
  }
  for (n_msgs = 0; n_msgs < MAXMSG && pos < len; n_msgs++) {
    size_t d = find_delim(in + pos, len - pos);

    msg_ptr[n_msgs] = in + pos;
    msg_len[n_msgs] = d;
    pos += d + 2 <= len - pos ? d + 2 : len - pos;
  }

  /* the icq module spins on a login that is not a UIN (digits only) */
  if (strcmp(services[in[0] % NSERVICES].name, "icq") == 0) {
    if (sec[1][0] == 0)
      return -1;
    for (k = 0; sec[1][k]; k++)
      if (sec[1][k] < '0' || sec[1][k] > '9')
        return -1;
  }

  /* hydra hands a module "login\0password\0" in a buffer of 260 bytes */
  if (sec_len[1] + sec_len[2] + 2 > 255)
    return -1;

  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctl) < 0)
    return 1;
  ctl_fd = ctl[1];
  {
    unsigned char pair[260];

    memset(pair, 0, sizeof(pair));
    memcpy(pair, sec[1], sec_len[1]);
    memcpy(pair + sec_len[1] + 1, sec[2], sec_len[2]);
    send(ctl[0], pair, sec_len[1] + sec_len[2] + 2, 0);
    send(ctl[0], hydra_exit, sizeof(hydra_exit), 0);
    for (i = 0; i < 8; i++)
      send(ctl[0], "x", 1, 0);
  }

  memset(ip, 0, sizeof(ip));
  ip[0] = 4;
  ip[1] = 127;
  ip[4] = 1;
  fp = tmpfile(); /* findings the module reports land here */

  /* hydra runs a module's init once in the parent (sp = -1), then the module in each child */
  {
    int k2 = in[0] % NSERVICES;
    char *misc = sec[0];

    /* hydra.c hands the proxy modules either no option or a full URL */
    if (strncmp(services[k2].name, "http_proxy", 10) == 0) {
      if (misc[0] == 0)
        misc = NULL;
      else if (strstr(misc, "://") == NULL)
        return -1;
    }
    if (services[k2].init(ip, -1, options, misc, fp, services[k2].port, "localhost") != 0)
      return -1;
    services[k2].fn(ip, ctl[1], options, misc, fp, services[k2].port, "localhost");
  }
  return 0;
}
