/**
 * Exercises the `SSL_write` retry contract with a non-blocking transport.
 *
 * A client and server are connected through a BIO pair with small buffers,
 * so large writes regularly fail with `SSL_ERROR_WANT_WRITE`.  As required
 * by OpenSSL, such writes are retried with the same buffer once the peer
 * has read some data.  The received stream must match what was written,
 * exactly once.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static int require(int expect_rc, int got_rc, const char *str) {
  if (expect_rc != got_rc) {
    printf("REQUIRED(%s) failed: wanted=%d, got=%d\n", str, expect_rc, got_rc);
    fflush(stdout);
    abort();
  }
  return got_rc;
}

#define REQUIRE(expect, fn) require((expect), (fn), #fn)

static void dump_openssl_error_stack(void) {
  if (ERR_peek_error() != 0) {
    printf("openssl error: %08lx\n", ERR_peek_error());
    ERR_print_errors_fp(stderr);
  }
}

#define CHUNK 65536
#define ROUNDS 16
#define PAIR_BUFFER 4096

static uint8_t pattern(uint64_t i) { return (uint8_t)((i * 31) ^ (i >> 9)); }

static uint64_t received = 0;
static uint32_t hash = 2166136261u;

/* Read everything currently available on `client`. */
static void drain(SSL *client) {
  uint8_t buf[16384];
  for (;;) {
    int n = SSL_read(client, buf, sizeof(buf));
    if (n <= 0) {
      int err = SSL_get_error(client, n);
      if (err != SSL_ERROR_WANT_READ) {
        printf("unexpected SSL_read error %d\n", err);
        dump_openssl_error_stack();
        abort();
      }
      return;
    }
    for (int i = 0; i < n; i++) {
      hash = (hash ^ buf[i]) * 16777619u;
    }
    received += n;
  }
}

int main(void) {
  SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
  REQUIRE(1, SSL_CTX_use_certificate_chain_file(server_ctx,
                                                "test-ca/rsa/server.cert"));
  REQUIRE(1, SSL_CTX_use_PrivateKey_file(server_ctx, "test-ca/rsa/server.key",
                                         SSL_FILETYPE_PEM));
  SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());

  SSL *server = SSL_new(server_ctx);
  SSL *client = SSL_new(client_ctx);
  REQUIRE(1, SSL_set_tlsext_host_name(client, "localhost"));

  BIO *server_bio, *client_bio;
  REQUIRE(1,
          BIO_new_bio_pair(&server_bio, PAIR_BUFFER, &client_bio, PAIR_BUFFER));
  SSL_set_bio(server, server_bio, server_bio);
  SSL_set_bio(client, client_bio, client_bio);
  SSL_set_accept_state(server);
  SSL_set_connect_state(client);

  for (int i = 0; i < 100; i++) {
    int c = SSL_do_handshake(client);
    int s = SSL_do_handshake(server);
    if (c == 1 && s == 1) {
      break;
    }
  }
  REQUIRE(1, SSL_is_init_finished(client));
  REQUIRE(1, SSL_is_init_finished(server));
  printf("handshake complete\n");

  uint8_t *buf = malloc(CHUNK);
  uint64_t sent = 0;
  uint32_t expect_hash = 2166136261u;
  int would_block = 0;

  for (int round = 0; round < ROUNDS; round++) {
    for (int i = 0; i < CHUNK; i++) {
      buf[i] = pattern(sent + i);
      expect_hash = (expect_hash ^ buf[i]) * 16777619u;
    }

    int offset = 0;
    while (offset < CHUNK) {
      int n = SSL_write(server, buf + offset, CHUNK - offset);
      if (n > 0) {
        offset += n;
        continue;
      }
      int err = SSL_get_error(server, n);
      if (err != SSL_ERROR_WANT_WRITE) {
        printf("unexpected SSL_write error %d\n", err);
        dump_openssl_error_stack();
        abort();
      }
      would_block = 1;
      /* let the peer read, then retry with the same arguments */
      drain(client);
    }
    sent += CHUNK;
  }

  for (int i = 0; i < 1000 && received < sent; i++) {
    drain(client);
  }

  printf("writes blocked: %s\n", would_block ? "yes" : "no");
  printf("sent=%llu received=%llu\n", (unsigned long long)sent,
         (unsigned long long)received);
  printf("stream %s\n",
         received == sent && hash == expect_hash ? "intact" : "CORRUPT");

  free(buf);
  SSL_free(client);
  SSL_free(server);
  SSL_CTX_free(client_ctx);
  SSL_CTX_free(server_ctx);
  return 0;
}
