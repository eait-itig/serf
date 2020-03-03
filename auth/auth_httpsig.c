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
#include <ctype.h>

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

typedef struct sig_auth_hdr_t {
    struct sig_auth_hdr_t      *sah_next;
    const char                 *sah_name;
} sig_authn_hdr_t;

/* Stores the context information related to Signature authentication.
   This information is stored in the per server cache in the serf context. */
typedef struct sig_authn_info_t {
    apr_pool_t      *sai_pool;

    int              sai_authfd;
    struct sshkey   *sai_key;
    const char      *sai_keyid;

    const char      *sai_envvar;
    const char      *sai_user;

    const char      *sai_date;
    time_t           sai_dateat;
    const char      *sai_alg;
    const char      *sai_agalg;
    sig_authn_hdr_t *sai_hdrs;

    const char      *sai_last_tosign;
    size_t           sai_last_dlen;
    const char      *sai_last_sigstr;
} sig_authn_info_t;

static apr_status_t
cleanup_ctx(void *data)
{
    sig_authn_info_t *sig_info = (sig_authn_info_t *)data;
    sshkey_free(sig_info->sai_key);
    if (sig_info->sai_authfd != 0)
        close(sig_info->sai_authfd);
    return (APR_SUCCESS);
}

static void
httpsig_gen_date(sig_authn_info_t *sig_info)
{
    char datebuf[128];
    time_t now = time(0);
    if (sig_info->sai_date == NULL || now - sig_info->sai_dateat > 5) {
        struct tm *tm = gmtime(&now);
        strftime(datebuf, sizeof (datebuf), "%a, %d %b %Y %H:%M:%S %Z", tm);
        sig_info->sai_date = apr_pstrdup(sig_info->sai_pool, datebuf);
        sig_info->sai_dateat = now;
    }
}

enum parse_state {
    ST_KEY = 1,
    ST_VAL = 2,
    ST_VAL_QUO = 3,
};

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
    serf_connection_t *conn = request->conn;
    serf__authn_info_t *authn_info;
    sig_authn_info_t *sig_info;
    sig_authn_hdr_t *hdr;
    int rc;
    uint i, st;
    char *stb;
    const char *k;
    char *v;
    char *attr;

    authn_info = serf__get_authn_info_for_server(conn);
    sig_info = authn_info->baton;

    /*
     * This is per-connection/per-auth level stuff which is cached -- we could
     * do this in init_httpsig_connection() but we might not ever actually use
     * Signature auth, so only do it if we're going to make an actual req.
     */
    if (sig_info->sai_key == NULL) {
        struct ssh_identitylist *idl = NULL;
        char *fp;
        rc = ssh_fetch_identitylist(sig_info->sai_authfd, &idl);
        if (rc != 0) {
            return SERF_ERROR_AUTHN_MISSING_ATTRIBUTE;
        }

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

    /*
     * Initialise the per-request state.
     *
     * Here we start using pool.
     */
    httpsig_gen_date(sig_info);
    sig_info->sai_hdrs = NULL;
    sig_info->sai_alg = NULL;

    /* Parse the auth attributes if we were given any by the server */
    attr = apr_pstrdup(pool, auth_attr);
    st = ST_KEY;
    stb = attr;
    for (i = 0; attr != NULL && attr[i] != '\0'; ++i) {
        switch (st) {
        case ST_KEY:
            if (attr[i] == '=') {
                attr[i] = '\0';
                k = apr_pstrdup(pool, stb);
                attr[i] = '=';
                stb = &attr[i + 1];
                st = ST_VAL;
            }
            break;
        case ST_VAL:
            if (attr[i] == ',') {
                attr[i] = '\0';
                v = apr_pstrdup(pool, stb);
                attr[i] = ',';
                while (attr[i + 1] != '\0' && isspace(attr[i + 1]))
                    ++i;
                stb = &attr[i + 1];
                st = ST_KEY;
                goto gotkv;
            } else if (attr[i] == '"') {
                stb = &attr[i + 1];
                st = ST_VAL_QUO;
            } else if (attr[i + 1] == '\0') {
                v = apr_pstrdup(pool, stb);
                goto gotkv;
            }
            break;
        case ST_VAL_QUO:
            if (attr[i] == '\\' && attr[i + 1] != '\0') {
                ++i;
            } else if (attr[i] == '"') {
                attr[i] = '\0';
                v = apr_pstrdup(pool, stb);
                attr[i] = '"';
                while (attr[i + 1] != '\0' && (
                  isspace(attr[i + 1]) || attr[i + 1] == ',')) {
                    ++i;
                }
                stb = &attr[i + 1];
                st = ST_KEY;
                goto gotkv;
            }
            break;
        }
        continue;
gotkv:
        /* Server has told us to sign a set of headers. */
        if (strcasecmp(k, "headers") == 0) {
            char *saveptr;
            char *term;
            sig_authn_hdr_t *lasthdr;

            lasthdr = sig_info->sai_hdrs = NULL;

            term = strtok_r(v, " ", &saveptr);
            while (term != NULL) {
                hdr = apr_pcalloc(pool, sizeof (sig_authn_hdr_t));
                hdr->sah_name = apr_pstrdup(pool, term);
                if (lasthdr == NULL) {
                    lasthdr = sig_info->sai_hdrs = hdr;
                } else {
                    lasthdr->sah_next = hdr;
                    lasthdr = hdr;
                }
                term = strtok_r(NULL, " ", &saveptr);
            }
        }
    }

    if (sig_info->sai_hdrs == NULL) {
        hdr = apr_pcalloc(pool, sizeof (sig_authn_hdr_t));
        hdr->sah_name = "date";
        sig_info->sai_hdrs = hdr;
    }

    sig_info->sai_agalg = NULL;
    switch (sig_info->sai_key->type) {
    case KEY_RSA:
        sig_info->sai_alg = "rsa-sha256";
        sig_info->sai_agalg = "rsa-sha2-256";
        break;
    case KEY_ECDSA:
        switch (sshkey_size(sig_info->sai_key)) {
        case 256:
            sig_info->sai_alg = "ecdsa-sha256";
            break;
        case 384:
            sig_info->sai_alg = "ecdsa-sha384";
            break;
        case 521:
            sig_info->sai_alg = "ecdsa-sha512";
            break;
        }
        break;
    case KEY_ED25519:
        sig_info->sai_alg = "ed25519-sha512";
        break;
    }

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

static const char *
hdrscat(apr_pool_t *pool, const char *hdrs, const char *val)
{
    if (hdrs == NULL)
        return (apr_pstrdup(pool, val));
    return (apr_pstrcat(pool, hdrs, " ", val, NULL));
}

static const char *
tosigncat(apr_pool_t *pool, const char *tosign, const char *hdr, const char *val)
{
    if (tosign == NULL)
        return (apr_pstrcat(pool, hdr, ": ", val, NULL));
    return (apr_pstrcat(pool, tosign, "\n", hdr, ": ", val, NULL));
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
    serf__authn_info_t *authn_info;
    sig_authn_info_t *sig_info;
    const char *tosign = NULL, *hdrs = NULL;
    u_char *ssig, *sig;
    char *sigstr;
    size_t ssiglen, siglen, dlen;
    sig_authn_hdr_t *hdr;
    int rc;
    char *methodl;
    const char *hv, *hdrval;
    uint i;
    apr_pool_t *pool, *buildpool = NULL;

    authn_info = serf__get_authn_info_for_server(conn);
    sig_info = authn_info->baton;

    if (sig_info == NULL || sig_info->sai_hdrs == NULL) {
        return SERF_ERROR_AUTHN_FAILED;
    }

    httpsig_gen_date(sig_info);

    pool = sig_info->sai_pool;
    if (apr_pool_create(&buildpool, pool) != APR_SUCCESS) {
        return SERF_ERROR_AUTHN_FAILED;
    }

    hdr = sig_info->sai_hdrs;
    while (hdr != NULL) {
        if (strcasecmp(hdr->sah_name, "date") == 0) {
            hdrs = hdrscat(buildpool, hdrs, "date");
            tosign = tosigncat(buildpool, tosign, "date",
                sig_info->sai_date);
            serf_bucket_headers_setn(hdrs_bkt, "Date", sig_info->sai_date);
        } else if (strcasecmp(hdr->sah_name, "(keyid)") == 0) {
            hdrs = hdrscat(buildpool, hdrs, "(keyid)");
            tosign = tosigncat(buildpool, tosign, "(keyid)",
                sig_info->sai_keyid);
        } else if (strcasecmp(hdr->sah_name, "(algorithm)") == 0) {
            hdrs = hdrscat(buildpool, hdrs, "(algorithm)");
            tosign = tosigncat(buildpool, tosign, "(algorithm)",
                sig_info->sai_alg);
        } else if (strcasecmp(hdr->sah_name, "(request-target)") == 0) {
            hdrs = hdrscat(buildpool, hdrs, "(request-target)");
            methodl = apr_pstrdup(buildpool, method);
            for (i = 0; i < strlen(methodl); ++i)
                methodl[i] = tolower(methodl[i]);
            hv = apr_pstrcat(buildpool, methodl, " ", uri, NULL);
            tosign = tosigncat(buildpool, tosign, "(request-target)", hv);
        } else {
            hv = serf_bucket_headers_get(hdrs_bkt, hdr->sah_name);
            if (hv == NULL) {
                apr_pool_destroy(buildpool);
                return SERF_ERROR_AUTHN_FAILED;
            }
            hdrs = hdrscat(buildpool, hdrs, hdr->sah_name);
            tosign = tosigncat(buildpool, tosign, hdr->sah_name, hv);
        }
        hdr = hdr->sah_next;
    }
    dlen = strlen(tosign);

    /*
     * Is the signing string the same as the last request? (can we just
     * re-use that signature and not talk to the agent again?)
     */
    if (sig_info->sai_last_dlen == dlen &&
        bcmp(sig_info->sai_last_tosign, tosign, dlen) == 0) {

        /* We can re-use it! */
        sigstr = (char *)sig_info->sai_last_sigstr;

    } else {
        /* Generate a new signature */
        rc = ssh_agent_sign(sig_info->sai_authfd, sig_info->sai_key,
            &ssig, &ssiglen, (u_char *)tosign, dlen, sig_info->sai_agalg, 0);
        if (rc != 0) {
            apr_pool_destroy(buildpool);
            return SERF_ERROR_AUTHN_FAILED;
        }

        rc = sshkey_sig_to_asn1(sig_info->sai_key, ssig, ssiglen,
            &sig, &siglen);
        explicit_bzero(ssig, ssiglen);
        free(ssig);
        if (rc != 0) {
            apr_pool_destroy(buildpool);
            return SERF_ERROR_AUTHN_FAILED;
        }

        /*
         * Since we're going to stash the sigstr potentially for the next req
         * we allocate it from pool (not buildpool)
         */
        sigstr = apr_palloc(pool, apr_base64_encode_len(siglen) + 1);
        apr_base64_encode_binary(sigstr, sig, siglen);

        explicit_bzero(sig, siglen);
        free(sig);

        sig_info->sai_last_dlen = dlen;
        sig_info->sai_last_tosign = apr_pstrdup(pool, tosign);
        sig_info->sai_last_sigstr = sigstr;
    }

    hdrval = apr_pstrcat(pool, "Signature "
        "headers=\"", hdrs, "\",",
        "keyId=\"", sig_info->sai_keyid, "\",",
        "algorithm=\"", sig_info->sai_alg, "\",",
        "signature=\"", sigstr, "\"",
        NULL);

    apr_pool_destroy(buildpool);

    serf_bucket_headers_setn(hdrs_bkt, "Authorization", hdrval);
    return APR_SUCCESS;
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
