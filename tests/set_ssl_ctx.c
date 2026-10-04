/**
 * Checks what `SSL_set_SSL_CTX` changes when called from the servername
 * callback.
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

static int servername_cb(SSL *ssl, int *alert, void *arg) {
  (void)alert;
  (void)arg;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  SSL_CTX *ctx = NULL;
  if (name && strcmp(name, "same.testserver.com") == 0) {
    ctx = SSL_get_SSL_CTX(ssl);
  }
  if (ctx && SSL_set_SSL_CTX(ssl, ctx) != ctx) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  return SSL_TLSEXT_ERR_OK;
}

static void print_name(const char *label, const X509_NAME *name) {
  char buf[256] = "(none)";
  if (name) {
    X509_NAME_oneline(name, buf, sizeof(buf));
  }
  printf("%s: %s\n", label, buf);
}

/* Connect with `servername` to a server starting with `ctx`; if `own_cert`,
 * the server `SSL` gets its own certificate before the handshake. */
static void handshake(SSL_CTX *ctx, const char *servername, int own_cert) {
  printf("-- connecting to %s%s\n", servername,
         own_cert ? ", server SSL has its own certificate" : "");

  SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
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

  X509 *server_cert = SSL_get1_peer_certificate(client);
  print_name("server certificate issuer", X509_get_issuer_name(server_cert));
  X509_free(server_cert);

  SSL_free(client);
  SSL_free(server);
  SSL_CTX_free(client_ctx);
}

int main(void) {
  /* switching to the current context keeps the SSL's own certificate */
  SSL_CTX *bare_ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_tlsext_servername_callback(bare_ctx, servername_cb);
  handshake(bare_ctx, "same.testserver.com", 1);

  SSL_CTX_free(bare_ctx);
  return 0;
}
