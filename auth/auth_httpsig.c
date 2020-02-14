/* ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

/*** Signature authentication ***/

#include <serf.h>
#include <serf_private.h>
#include <auth/auth.h>

#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libssh/sshkey.h>
#include <libssh/sshbuf.h>
#include <libssh/digest.h>
#include <libssh/authfd.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_strings.h>

/* Stores the context information related to Signature authentication.
   This information is stored in the per server cache in the serf context. */
typedef struct sig_authn_info_t {
    apr_pool_t    *sai_pool;
    int            sai_authfd;
    struct sshkey *sai_key;
    const char    *sai_keyid;
    const char    *sai_hdrval;
    const char    *sai_envvar;
    const char    *sai_date;
    const char    *sai_user;
} sig_authn_info_t;

static apr_status_t
cleanup_ctx(void *data)
{
    sig_authn_info_t *sig_info = (sig_authn_info_t *)data;
    sshkey_free(sig_info->sai_key);
    close(sig_info->sai_authfd);
    return (APR_SUCCESS);
}

static const char *
httpsig_gen_date(apr_pool_t *pool)
{
    char datebuf[128];
    time_t now = time(0);
    struct tm *tm = gmtime(&now);
    strftime(datebuf, sizeof (datebuf), "%a, %d %b %Y %H:%M:%S %Z", tm);
    return (apr_pstrdup(pool, datebuf));
}

/* Implements serf__auth_handler_func_t callback. */
static apr_status_t
serf__handle_httpsig_auth(const serf__authn_scheme_t *scheme,
                        int code,
                        serf_request_t *request,
                        serf_bucket_t *response,
                        const char *auth_hdr,
                        const char *auth_attr,
                        apr_pool_t *pool)
{
    const char *tmp;
    const char *date, *tosign;
    const char *alg = NULL, *agalg;
    u_char *ssig, *sig, *sigstr;
    size_t ssiglen, siglen, dlen;
    apr_size_t tmp_len;
    serf_connection_t *conn = request->conn;
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info;
    sig_authn_info_t *sig_info;
    apr_status_t status;
    int rc;
    uint i;

    authn_info = serf__get_authn_info_for_server(conn);
    sig_info = authn_info->baton;

    if (sig_info->sai_key == NULL) {
        struct ssh_identitylist *idl = NULL;
        char *fp;
        rc = ssh_fetch_identitylist(sig_info->sai_authfd, &idl);

        for (i = 0; i < idl->nkeys; ++i) {
            fp = sshkey_fingerprint(idl->keys[i], SSH_DIGEST_MD5, SSH_FP_HEX);
            if (strcmp(fp, sig_info->sai_envvar) == 0) {
                free(fp);
                sshkey_demote(idl->keys[i], &sig_info->sai_key);
                break;
            }
            free(fp);
            fp = sshkey_fingerprint(idl->keys[i], SSH_DIGEST_SHA256,
              SSH_FP_BASE64);
            if (strcmp(fp, sig_info->sai_envvar) == 0) {
                free(fp);
                sshkey_demote(idl->keys[i], &sig_info->sai_key);
                break;
            }
            free(fp);
        }
        ssh_free_identitylist(idl);

        if (sig_info->sai_key == NULL) {
            return SERF_ERROR_AUTHN_MISSING_ATTRIBUTE;
        }
    }

    if (sig_info->sai_keyid == NULL) {
        char *fp;
        fp = sshkey_fingerprint(sig_info->sai_key, SSH_DIGEST_MD5, SSH_FP_HEX);
        sig_info->sai_keyid = apr_pstrcat(conn->pool, "/",
            sig_info->sai_user, "/keys/", &fp[4], NULL);
        free(fp);
    }

    sig_info->sai_date = date = httpsig_gen_date(conn->pool);

    tosign = apr_pstrcat(conn->pool, "date: ", date, NULL);
    dlen = strlen(tosign);

    agalg = NULL;
    switch (sig_info->sai_key->type) {
    case KEY_RSA:
        alg = "rsa-sha256";
        agalg = "rsa-sha2-256";
        break;
    case KEY_ECDSA:
        switch (sshkey_size(sig_info->sai_key)) {
        case 256:
            alg = "ecdsa-sha256";
            break;
        case 384:
            alg = "ecdsa-sha384";
            break;
        case 521:
            alg = "ecdsa-sha512";
            break;
        }
        break;
    case KEY_ED25519:
        alg = "ed25519-sha512";
        break;
    }

    rc = ssh_agent_sign(sig_info->sai_authfd, sig_info->sai_key,
        &ssig, &ssiglen, tosign, dlen, agalg, 0);
    if (rc != 0) {
        return SERF_ERROR_AUTHN_FAILED;
    }

    rc = sshkey_sig_to_asn1(sig_info->sai_key, ssig, ssiglen,
        &sig, &siglen);
    explicit_bzero(ssig, ssiglen);
    free(ssig);
    if (rc != 0) {
        return SERF_ERROR_AUTHN_FAILED;
    }

    sigstr = apr_palloc(conn->pool, apr_base64_encode_len(siglen) + 1);
    apr_base64_encode_binary(sigstr, sig, siglen);

    sig_info->sai_hdrval = apr_pstrcat(conn->pool, "Signature "
        "keyId=\"", sig_info->sai_keyid, "\",",
        "algorithm=\"", alg, "\",",
        "signature=\"", sigstr, "\"",
        NULL);

    return APR_SUCCESS;
}

/* For Basic authentication we expect all authn info to be the same for all
   connections in the context to the same server (same realm, username,
   password). Therefore we can keep the header value in the per-server store
   context instead of per connection. Implements serf__init_conn_func_t
   callback.
   TODO: we currently don't cache this info per realm, so each time a request
   'switches realms', we have to ask the application for new credentials. */
static apr_status_t
serf__init_httpsig_connection(const serf__authn_scheme_t *scheme,
                            int code,
                            serf_connection_t *conn,
                            apr_pool_t *pool)
{
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info;
    sig_authn_info_t *sig_info;
    int authfd;
    const char *envvar;

    authn_info = serf__get_authn_info_for_server(conn);

    if (!authn_info->baton) {
        envvar = getenv("SVN_KEY_ID");
        if (envvar == NULL) {
            return SERF_ERROR_AUTHN_MISSING_ATTRIBUTE;
        }
        if (ssh_get_authentication_socket(&authfd) == -1) {
            return SERF_ERROR_AUTHN_MISSING_ATTRIBUTE;
        }
        authn_info->baton = sig_info =
          apr_pcalloc(pool, sizeof(sig_authn_info_t));
        apr_pool_cleanup_register(pool, sig_info, cleanup_ctx,
            apr_pool_cleanup_null);
        sig_info->sai_pool = pool;
        sig_info->sai_authfd = authfd;
        sig_info->sai_envvar = envvar;

        if (sig_info->sai_user == NULL)
            sig_info->sai_user = getenv("SVN_USER");
        if (sig_info->sai_user == NULL)
            sig_info->sai_user = getenv("SUDO_USER");
        if (sig_info->sai_user == NULL)
            sig_info->sai_user = getenv("USER");
        if (sig_info->sai_user == NULL)
            sig_info->sai_user = getenv("LOGNAME");
    }

    return APR_SUCCESS;
}

/* Implements serf__setup_request_func_t callback. */
static apr_status_t
serf__setup_request_httpsig_auth(const serf__authn_scheme_t *scheme,
                               peer_t peer,
                               int code,
                               serf_connection_t *conn,
                               serf_request_t *request,
                               const char *method,
                               const char *uri,
                               serf_bucket_t *hdrs_bkt)
{
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info;
    sig_authn_info_t *sig_info;

    authn_info = serf__get_authn_info_for_server(conn);
    sig_info = authn_info->baton;

    if (sig_info && sig_info->sai_hdrval) {
        serf_bucket_headers_setn(hdrs_bkt, "Authorization",
                                 sig_info->sai_hdrval);
        serf_bucket_headers_setn(hdrs_bkt, "Date",
                                 sig_info->sai_date);
        return APR_SUCCESS;
    }

    return SERF_ERROR_AUTHN_FAILED;
}

/* Implements serf__validate_response_func_t callback. */
static apr_status_t
validate_response_func(const serf__authn_scheme_t *scheme,
                       peer_t peer,
                       int code,
                       serf_connection_t *conn,
                       serf_request_t *request,
                       serf_bucket_t *response,
                       apr_pool_t *pool)
{
    return APR_SUCCESS;
}

const serf__authn_scheme_t serf__http_sig_authn_scheme = {
    "Signature",
    "signature",
    SERF_AUTHN_SIGNATURE,
    serf__init_httpsig_connection,
    serf__handle_httpsig_auth,
    serf__setup_request_httpsig_auth,
    validate_response_func,
};
