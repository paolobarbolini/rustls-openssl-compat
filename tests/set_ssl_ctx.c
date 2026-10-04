/**
 * Checks what `SSL_set_SSL_CTX` changes when called from the servername
 * callback.
 *
 * `first_ctx` and `second_ctx` have different certificates, certificate
 * callbacks, ALPN callbacks and verification stores.  The verify mode is only
 * set on `first_ctx`: `SSL_new` copies it into the `SSL`, so a switch keeps it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int require(int expect_rc, int got_rc, const char *str) {
  if (expect_rc != got_rc) {
    printf("REQUIRED(%s) failed: wanted=%d, got=%d\n", str, expect_rc, got_rc);
    fflush(stdout);
    abort();
  }
  return got_rc;
}

#define REQUIRE(expect, fn) require((expect), (fn), #fn)

static SSL_CTX *second_ctx;
static const char *cert_cb_ran;

static int cert_cb(SSL *ssl, void *arg) {
  (void)ssl;
  cert_cb_ran = arg;
  return 1;
}

static int alpn_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                   const uint8_t *in, unsigned int inlen, void *arg) {
  (void)ssl;
  const char *choice = arg;
  for (unsigned int i = 0; i < inlen; i += 1 + in[i]) {
    if (in[i] == strlen(choice) && memcmp(&in[i + 1], choice, in[i]) == 0) {
      *out = &in[i + 1];
      *outlen = in[i];
      return SSL_TLSEXT_ERR_OK;
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static int servername_cb(SSL *ssl, int *alert, void *arg) {
  (void)alert;
  (void)arg;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  SSL_CTX *ctx = NULL;
  if (name && strcmp(name, "second.testserver.com") == 0) {
    ctx = second_ctx;
  } else if (name && strcmp(name, "same.testserver.com") == 0) {
    ctx = SSL_get_SSL_CTX(ssl);
  }
  if (ctx && SSL_set_SSL_CTX(ssl, ctx) != ctx) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *server_ctx(const char *cert, const char *key, const char *ca,
                           const char *name) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  REQUIRE(1, SSL_CTX_use_certificate_chain_file(ctx, cert));
  REQUIRE(1, SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM));
  REQUIRE(1, SSL_CTX_load_verify_file(ctx, ca));
  SSL_CTX_set_cert_cb(ctx, cert_cb, (void *)name);
  SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, (void *)name);
  SSL_CTX_set_tlsext_servername_callback(ctx, servername_cb);
  return ctx;
}

static void print_name(const char *label, const X509_NAME *name) {
  char buf[256] = "(none)";
  if (name) {
    X509_NAME_oneline(name, buf, sizeof(buf));
  }
  printf("%s: %s\n", label, buf);
}

/* Connect with `servername` to a server starting with `ctx`; if `own_cert`,
 * the server `SSL` gets its own certificate before the handshake, and if
 * `client_cert`, the client presents a certificate. */
static void handshake(SSL_CTX *ctx, const char *servername, int own_cert,
                      int client_cert) {
  printf("-- connecting to %s%s%s\n", servername,
         own_cert ? ", server SSL has its own certificate" : "",
         client_cert ? ", with client certificate" : "");
  cert_cb_ran = "none";

  static const uint8_t protos[] = "\005first\006second";
  SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
  REQUIRE(0, SSL_CTX_set_alpn_protos(client_ctx, protos, sizeof(protos) - 1));
  if (client_cert) {
    REQUIRE(1, SSL_CTX_use_certificate_chain_file(client_ctx,
                                                  "test-ca/rsa/client.cert"));
    REQUIRE(1, SSL_CTX_use_PrivateKey_file(client_ctx, "test-ca/rsa/client.key",
                                           SSL_FILETYPE_PEM));
  }
  SSL *server = SSL_new(ctx);
  SSL *client = SSL_new(client_ctx);
  REQUIRE(1, SSL_set_tlsext_host_name(client, servername));

  if (own_cert) {
    BIO *f = BIO_new_file("test-ca/rsa/server.cert", "r");
    X509 *cert = PEM_read_bio_X509(f, NULL, NULL, NULL);
    BIO_free(f);
    REQUIRE(1, SSL_use_certificate(server, cert));
    X509_free(cert);
    REQUIRE(1, SSL_use_PrivateKey_file(server, "test-ca/rsa/server.key",
                                       SSL_FILETYPE_PEM));
  }

  BIO *server_bio, *client_bio;
  REQUIRE(1, BIO_new_bio_pair(&server_bio, 0, &client_bio, 0));
  SSL_set_bio(server, server_bio, server_bio);
  SSL_set_bio(client, client_bio, client_bio);
  SSL_set_accept_state(server);
  SSL_set_connect_state(client);

  int done = 0;
  for (int i = 0; i < 100 && !done; i++) {
    int c = SSL_do_handshake(client);
    int s = SSL_do_handshake(server);
    done = c == 1 && s == 1;
  }
  REQUIRE(1, done);
  /* complete any post-handshake messages */
  char buf[1];
  REQUIRE(1, SSL_write(client, "x", 1));
  REQUIRE(1, SSL_read(server, buf, sizeof(buf)));

  printf("switched to second context: %s\n",
         SSL_get_SSL_CTX(server) == second_ctx ? "yes" : "no");
  printf("certificate callback: %s\n", cert_cb_ran);

  const uint8_t *alpn = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(client, &alpn, &alpn_len);
  printf("alpn: %.*s\n", (int)alpn_len, alpn ? (const char *)alpn : "");

  X509 *server_cert = SSL_get1_peer_certificate(client);
  print_name("server certificate issuer", X509_get_issuer_name(server_cert));
  X509_free(server_cert);

  X509 *client_peer = SSL_get1_peer_certificate(server);
  if (client_peer) {
    print_name("client certificate", X509_get_subject_name(client_peer));
    printf("verify result: %ld\n", SSL_get_verify_result(server));
    X509_free(client_peer);
  }

  SSL_free(client);
  SSL_free(server);
  SSL_CTX_free(client_ctx);
}

int main(void) {
  SSL_CTX *first_ctx = server_ctx("test-ca/ecdsa-p256/server.cert",
                                  "test-ca/ecdsa-p256/server.key",
                                  "test-ca/ecdsa-p256/ca.cert", "first");
  second_ctx = server_ctx("test-ca/rsa/server.cert", "test-ca/rsa/server.key",
                          "test-ca/rsa/ca.cert", "second");
  SSL_CTX_set_verify(first_ctx, SSL_VERIFY_PEER, NULL);

  handshake(first_ctx, "testserver.com", 0, 0);
  /* the client certificate is only trusted by `second_ctx` */
  handshake(first_ctx, "second.testserver.com", 0, 1);

  /* switching to the current context keeps the SSL's own certificate */
  SSL_CTX *bare_ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_tlsext_servername_callback(bare_ctx, servername_cb);
  handshake(bare_ctx, "same.testserver.com", 1, 0);

  SSL_CTX_free(bare_ctx);
  SSL_CTX_free(second_ctx);
  SSL_CTX_free(first_ctx);
  return 0;
}
