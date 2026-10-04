/**
 * Checks which alert a server sends when it rejects a ClientHello.
 *
 * Client and server are connected through a BIO pair; the client's info
 * callback records the alert it receives.  The server rejects the
 * `ClientHello` because of its configuration, or from one of its callbacks.
 */

#include <stdio.h>
#include <stdlib.h>

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

static int received_alert;

static void client_info_cb(const SSL *ssl, int where, int ret) {
  (void)ssl;
  if (where & SSL_CB_READ_ALERT) {
    received_alert = ret & 0xff;
  }
}

static int servername_reject(SSL *ssl, int *alert, void *arg) {
  (void)ssl;
  (void)arg;
  *alert = SSL_AD_ACCESS_DENIED;
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int servername_warn(SSL *ssl, int *alert, void *arg) {
  (void)ssl;
  (void)arg;
  *alert = SSL_AD_UNRECOGNIZED_NAME;
  return SSL_TLSEXT_ERR_ALERT_WARNING;
}

static int client_hello_reject(SSL *ssl, int *alert, void *arg) {
  (void)ssl;
  (void)arg;
  *alert = SSL_AD_HANDSHAKE_FAILURE;
  return SSL_CLIENT_HELLO_ERROR;
}

static int alpn_reject(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                       const uint8_t *in, unsigned int inlen, void *arg) {
  (void)ssl;
  (void)out;
  (void)outlen;
  (void)in;
  (void)inlen;
  (void)arg;
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int cert_reject(SSL *ssl, void *arg) {
  (void)ssl;
  (void)arg;
  return 0;
}

static SSL_CTX *new_server_ctx(void) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  REQUIRE(1,
          SSL_CTX_use_certificate_chain_file(ctx, "test-ca/rsa/server.cert"));
  REQUIRE(1, SSL_CTX_use_PrivateKey_file(ctx, "test-ca/rsa/server.key",
                                         SSL_FILETYPE_PEM));
  return ctx;
}

static void handshake(const char *label, SSL_CTX *server_ctx,
                      SSL_CTX *client_ctx) {
  received_alert = -1;

  SSL *server = SSL_new(server_ctx);
  SSL *client = SSL_new(client_ctx);
  REQUIRE(1, SSL_set_tlsext_host_name(client, "localhost"));
  SSL_set_info_callback(client, client_info_cb);

  BIO *server_bio, *client_bio;
  REQUIRE(1, BIO_new_bio_pair(&server_bio, 0, &client_bio, 0));
  SSL_set_bio(server, server_bio, server_bio);
  SSL_set_bio(client, client_bio, client_bio);
  SSL_set_accept_state(server);
  SSL_set_connect_state(client);

  int c = -1, s = -1;
  for (int i = 0; i < 10; i++) {
    if (c != 1) {
      c = SSL_do_handshake(client);
    }
    if (s != 1) {
      s = SSL_do_handshake(server);
    }
  }

  printf("%s: client %s, server %s, client received alert %d\n", label,
         c == 1 ? "connected" : "failed", s == 1 ? "connected" : "failed",
         received_alert);
  ERR_clear_error();

  SSL_free(client);
  SSL_free(server);
}

int main(void) {
  SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
  REQUIRE(0, SSL_CTX_set_alpn_protos(client_ctx, (const uint8_t *)"\x02h2", 3));

  SSL_CTX *ctx = new_server_ctx();
  SSL_CTX_set_tlsext_servername_callback(ctx, servername_reject);
  handshake("servername callback", ctx, client_ctx);
  SSL_CTX_free(ctx);

  /* not fatal: TLS1.3 has no warning alerts, so this carries on silently */
  ctx = new_server_ctx();
  SSL_CTX_set_tlsext_servername_callback(ctx, servername_warn);
  handshake("servername callback warning", ctx, client_ctx);
  SSL_CTX_free(ctx);

  ctx = new_server_ctx();
  SSL_CTX_set_client_hello_cb(ctx, client_hello_reject, NULL);
  handshake("client hello callback", ctx, client_ctx);
  SSL_CTX_free(ctx);

  ctx = new_server_ctx();
  SSL_CTX_set_alpn_select_cb(ctx, alpn_reject, NULL);
  handshake("ALPN callback", ctx, client_ctx);
  SSL_CTX_free(ctx);

  ctx = new_server_ctx();
  SSL_CTX_set_cert_cb(ctx, cert_reject, NULL);
  handshake("certificate callback", ctx, client_ctx);
  SSL_CTX_free(ctx);

  ctx = new_server_ctx();
  REQUIRE(1, SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION));
  REQUIRE(1, SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION));
  handshake("no common protocol version", ctx, client_ctx);
  SSL_CTX_free(ctx);

  SSL_CTX_free(client_ctx);
  return 0;
}
