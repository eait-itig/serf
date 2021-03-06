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

#ifndef SERF_BUCKET_TYPES_H
#define SERF_BUCKET_TYPES_H

#include <apr_mmap.h>
#include <apr_hash.h>

/* this header and serf.h refer to each other, so take a little extra care */
#ifndef SERF_H
#include "serf.h"
#endif


/**
 * @file serf_bucket_types.h
 * @brief serf-supported bucket types
 */
/* ### this whole file needs docco ... */

#ifdef __cplusplus
extern "C" {
#endif

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_request;
#define SERF_BUCKET_IS_REQUEST(b) SERF_BUCKET_CHECK((b), request)

serf_bucket_t *serf_bucket_request_create(
    const char *method,
    const char *URI,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator);

/* Send a Content-Length header with @a len. The @a body bucket should
   contain precisely that much data.  */
void serf_bucket_request_set_CL(
    serf_bucket_t *bucket,
    apr_int64_t len);

serf_bucket_t *serf_bucket_request_get_headers(
    serf_bucket_t *request);

/**
 * Transform @a bucket in-place into a request bucket.
 *
 * It is callers responsibility to free resources held by the original
 * bucket.
 */
void serf_bucket_request_become(
    serf_bucket_t *bucket,
    const char *method,
    const char *uri,
    serf_bucket_t *body);

/**
 * Sets the root url of the remote host. If this request contains a relative
 * url, it will be prefixed with the root url to form an absolute url.
 * @a bucket is the request bucket. @a root_url is the absolute url of the
 * root of the remote host, without the closing '/'.
 */
void serf_bucket_request_set_root(
    serf_bucket_t *bucket,
    const char *root_url);


/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_incoming_request;
#define SERF_BUCKET_IS_INCOMING_REQUEST(b)                              \
                                SERF_BUCKET_CHECK((b), incoming_request)

serf_bucket_t *serf_bucket_incoming_request_create(
                                      serf_bucket_t *body,
                                      serf_bucket_alloc_t *allocator);

/* All output arguments optional. Waits for the request line to have arrived
   with the normal read responses. */
/* ### Add RESULT_POOL argument? */
apr_status_t serf_bucket_incoming_request_read(
                                      serf_bucket_t **headers,
                                      const char **method,
                                      const char **path,
                                      int *http_version,
                                      serf_bucket_t *request);

apr_status_t serf_bucket_incoming_request_wait_for_headers(
                                      serf_bucket_t *response);

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_response;
#define SERF_BUCKET_IS_RESPONSE(b) SERF_BUCKET_CHECK((b), response)

serf_bucket_t *serf_bucket_response_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);

#define SERF_HTTP_VERSION(major, minor)  ((major) * 1000 + (minor))
#define SERF_HTTP_11 SERF_HTTP_VERSION(1, 1)
#define SERF_HTTP_10 SERF_HTTP_VERSION(1, 0)
/** @since New in 1.4. */
#define SERF_HTTP_20 SERF_HTTP_VERSION(2, 0)
#define SERF_HTTP_VERSION_MAJOR(shv) ((int)shv / 1000)
#define SERF_HTTP_VERSION_MINOR(shv) ((int)shv % 1000)

typedef struct serf_status_line {
    int version;
    int code;
    const char *reason;
} serf_status_line;

/**
 * Return the Status-Line information, if available. This function
 * works like other bucket read functions: it may return APR_EAGAIN or
 * APR_EOF to signal the state of the bucket for reading. A return
 * value of APR_SUCCESS will always indicate that status line
 * information was returned; for other return values the caller must
 * check the version field in @a sline. A value of 0 means that the
 * data is not (yet) present.
 */
apr_status_t serf_bucket_response_status(
    serf_bucket_t *bkt,
    serf_status_line *sline);

/**
 * Wait for the HTTP headers to be processed for a @a response.
 *
 * If the headers are available, APR_SUCCESS is returned.
 * If the headers aren't available, APR_EAGAIN is returned.
 */
apr_status_t serf_bucket_response_wait_for_headers(
    serf_bucket_t *response);

/**
 * Wait for the first HTTP headers to be processed for a @a response.
 * If 1XX informational responses are received before the actual headers
 * this function will return APR_SUCCESS as soon as such a set is processed,
 * while serf_bucket_response_wait_for_headers() will wait until the
 * actual headers to be available.
 *
 * If @a wait_for_next is TRUE, the function will wait for the next set
 * of informational header instead of returning success for the first set.
 *
 * @since New in 1.4.
 */
apr_status_t serf_bucket_response_wait_for_some_headers(
    serf_bucket_t *response,
    int wait_for_next);

/**
 * Get the headers bucket for @a response.
 */
serf_bucket_t *serf_bucket_response_get_headers(
    serf_bucket_t *response);

/**
 * Advise the response @a bucket that this was from a HEAD request and
 * that it should not expect to see a response body.
 */
void serf_bucket_response_set_head(
    serf_bucket_t *bucket);

/**
 * Ask the response @a bucket, to decode content based on the value of the
 * 'Content- Encoding' header, or not. The default setting of a response
 * bucket is to decode when the header is found.
 */
void serf_bucket_response_decode_content(
    serf_bucket_t *bucket,
    int decode);


/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_response_body;
#define SERF_BUCKET_IS_RESPONSE_BODY(b) SERF_BUCKET_CHECK((b), response_body)

serf_bucket_t *serf_bucket_response_body_create(
    serf_bucket_t *stream,
    apr_uint64_t limit,
    serf_bucket_alloc_t *allocator);

/* ==================================================================== */
/** @since New in 1.4 */
extern const serf_bucket_type_t serf_bucket_type_outgoing_response;
/** @since New in 1.4 */
#define SERF_BUCKET_IS_OUTGOING_RESPONSE(b)         \
                SERF_BUCKET_CHECK((b), outgoing_response)

/** @since New in 1.4 */
serf_bucket_t *serf_bucket_outgoing_response_create(
    serf_bucket_t *body,
    int status,
    const char *reason,
    int http_version,
    serf_bucket_alloc_t *allocator);

/** @since New in 1.4 */
serf_bucket_t *serf_bucket_outgoing_response_get_headers(
    serf_bucket_t *outgoing_response);

/** @since New in 1.4 */
void serf_bucket_outgoing_response_prepare(
    serf_bucket_t *outgoing_response,
    int http_version,
    int allow_chunking);

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_bwtp_frame;
#define SERF_BUCKET_IS_BWTP_FRAME(b) SERF_BUCKET_CHECK((b), bwtp_frame)

extern const serf_bucket_type_t serf_bucket_type_bwtp_incoming_frame;
#define SERF_BUCKET_IS_BWTP_INCOMING_FRAME(b) SERF_BUCKET_CHECK((b), bwtp_incoming_frame)

int serf_bucket_bwtp_frame_get_channel(
    serf_bucket_t *hdr);

int serf_bucket_bwtp_frame_get_type(
    serf_bucket_t *hdr);

const char *serf_bucket_bwtp_frame_get_phrase(
    serf_bucket_t *hdr);

serf_bucket_t *serf_bucket_bwtp_frame_get_headers(
    serf_bucket_t *hdr);

serf_bucket_t *serf_bucket_bwtp_channel_open(
    int channel,
    const char *URI,
    serf_bucket_alloc_t *allocator);

serf_bucket_t *serf_bucket_bwtp_channel_close(
    int channel,
    serf_bucket_alloc_t *allocator);

serf_bucket_t *serf_bucket_bwtp_header_create(
    int channel,
    const char *phrase,
    serf_bucket_alloc_t *allocator);

serf_bucket_t *serf_bucket_bwtp_message_create(
    int channel,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator);

serf_bucket_t *serf_bucket_bwtp_incoming_frame_create(
    serf_bucket_t *bkt,
    serf_bucket_alloc_t *allocator);

apr_status_t serf_bucket_bwtp_incoming_frame_wait_for_headers(
    serf_bucket_t *bkt);

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_aggregate;
#define SERF_BUCKET_IS_AGGREGATE(b) SERF_BUCKET_CHECK((b), aggregate)

typedef apr_status_t (*serf_bucket_aggregate_eof_t)(
    void *baton,
    serf_bucket_t *aggregate_bucket);

/** serf_bucket_aggregate_cleanup will instantly destroy all buckets in
    the aggregate bucket that have been read completely. Whereas normally,
    these buckets are destroyed on every read operation. */
void serf_bucket_aggregate_cleanup(
    serf_bucket_t *bucket,
    serf_bucket_alloc_t *allocator);

serf_bucket_t *serf_bucket_aggregate_create(
    serf_bucket_alloc_t *allocator);

/** Transform @a bucket in-place into an aggregate bucket.
 *
 * It is callers responsibility to free resources held by the original
 * bucket */
void serf_bucket_aggregate_become(
    serf_bucket_t *bucket);

void serf_bucket_aggregate_prepend(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *prepend_bucket);

void serf_bucket_aggregate_append(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *append_bucket);

void serf_bucket_aggregate_hold_open(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_aggregate_eof_t fn,
    void *baton);

void serf_bucket_aggregate_prepend_iovec(
    serf_bucket_t *aggregate_bucket,
    struct iovec *vecs,
    int vecs_count);

void serf_bucket_aggregate_append_iovec(
    serf_bucket_t *aggregate_bucket,
    struct iovec *vecs,
    int vecs_count);

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_file;
#define SERF_BUCKET_IS_FILE(b) SERF_BUCKET_CHECK((b), file)

serf_bucket_t *serf_bucket_file_create(
    apr_file_t *file,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_socket;
#define SERF_BUCKET_IS_SOCKET(b) SERF_BUCKET_CHECK((b), socket)

serf_bucket_t *serf_bucket_socket_create(
    apr_socket_t *skt,
    serf_bucket_alloc_t *allocator);

/**
 * Call @a progress_func every time bytes are read from the socket, pass
 * the number of bytes read.
 *
 * When using serf's bytes read & written progress indicator, pass
 * @a serf_context_progress_delta for progress_func and the serf_context for
 * progress_baton.
 */
void serf_bucket_socket_set_read_progress_cb(
    serf_bucket_t *bucket,
    const serf_progress_t progress_func,
    void *progress_baton);

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_simple;
#define SERF_BUCKET_IS_SIMPLE(b) SERF_BUCKET_CHECK((b), simple)

typedef void (*serf_simple_freefunc_t)(
    void *baton,
    const char *data);

serf_bucket_t *serf_bucket_simple_create(
    const char *data,
    apr_size_t len,
    serf_simple_freefunc_t freefunc,
    void *freefunc_baton,
    serf_bucket_alloc_t *allocator);

/**
 * Equivalent to serf_bucket_simple_create, except that the bucket takes
 * ownership of a private copy of the data.
 */
serf_bucket_t *serf_bucket_simple_copy_create(
    const char *data,
    apr_size_t len,
    serf_bucket_alloc_t *allocator);

/**
 * Equivalent to serf_bucket_simple_create, except that the bucket assumes
 * responsibility for freeing the data on this allocator without making
 * a copy.  It is assumed that data was created by a call from allocator.
 */
serf_bucket_t *serf_bucket_simple_own_create(
    const char *data,
    apr_size_t len,
    serf_bucket_alloc_t *allocator);

#define SERF_BUCKET_SIMPLE_STRING(s,a) \
    serf_bucket_simple_create(s, strlen(s), NULL, NULL, a)

#define SERF_BUCKET_SIMPLE_STRING_LEN(s,l,a) \
    serf_bucket_simple_create(s, l, NULL, NULL, a)

/* ==================================================================== */


/* Note: apr_mmap_t is always defined, but if APR doesn't have mmaps, then
   the caller can never create an apr_mmap_t to pass to this function. */

extern const serf_bucket_type_t serf_bucket_type_mmap;
#define SERF_BUCKET_IS_MMAP(b) SERF_BUCKET_CHECK((b), mmap)

serf_bucket_t *serf_bucket_mmap_create(
    apr_mmap_t *mmap,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_headers;
#define SERF_BUCKET_IS_HEADERS(b) SERF_BUCKET_CHECK((b), headers)

serf_bucket_t *serf_bucket_headers_create(
    serf_bucket_alloc_t *allocator);

/**
 * Set, default: value copied.
 *
 * Set the specified @a header within the bucket, copying the @a value
 * into space from this bucket's allocator. The header is NOT copied,
 * so it should remain in scope at least as long as the bucket.
 */
void serf_bucket_headers_set(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

/**
 * Set, copies: header and value copied.
 *
 * Copy the specified @a header and @a value into the bucket, using space
 * from this bucket's allocator.
 */
void serf_bucket_headers_setc(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

/**
 * Set, no copies.
 *
 * Set the specified @a header and @a value into the bucket, without
 * copying either attribute. Both attributes should remain in scope at
 * least as long as the bucket.
 *
 * @note In the case where a header already exists this will result
 *       in a reallocation and copy, @see serf_bucket_headers_setn.
 */
void serf_bucket_headers_setn(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

/**
 * Set, extended: fine grained copy control of header and value.
 *
 * Set the specified @a header, with length @a header_size with the
 * @a value, and length @a value_size, into the bucket. The header will
 * be copied if @a header_copy is set, and the value is copied if
 * @a value_copy is set. If the values are not copied, then they should
 * remain in scope at least as long as the bucket.
 *
 * If @a headers_bucket already contains a header with the same name
 * as @a header, then append @a value to the existing value,
 * separating with a comma (as per RFC 2616, section 4.2).  In this
 * case, the new value must be allocated and the header re-used, so
 * behave as if @a value_copy were true and @a header_copy false.
 */
void serf_bucket_headers_setx(
    serf_bucket_t *headers_bucket,
    const char *header,
    apr_size_t header_size,
    int header_copy,
    const char *value,
    apr_size_t value_size,
    int value_copy);

const char *serf_bucket_headers_get(
    serf_bucket_t *headers_bucket,
    const char *header);

/**
 * @param baton opaque baton as passed to @see serf_bucket_headers_do
 * @param key The header key from this iteration through the table
 * @param value The header value from this iteration through the table
 */
typedef int (serf_bucket_headers_do_callback_fn_t)(
    void *baton,
    const char *key,
    const char *value);

/**
 * Iterates over all headers of the message and invokes the callback
 * function with header key and value. Stop iterating when no more
 * headers are available or when the callback function returned a
 * non-0 value.
 *
 * @param headers_bucket headers to iterate over
 * @param func callback routine to invoke for every header in the bucket
 * @param baton baton to pass on each invocation to func
 */
void serf_bucket_headers_do(
    serf_bucket_t *headers_bucket,
    serf_bucket_headers_do_callback_fn_t func,
    void *baton);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_chunk;
#define SERF_BUCKET_IS_CHUNK(b) SERF_BUCKET_CHECK((b), chunk)

serf_bucket_t *serf_bucket_chunk_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_dechunk;
#define SERF_BUCKET_IS_DECHUNK(b) SERF_BUCKET_CHECK((b), dechunk)

serf_bucket_t *serf_bucket_dechunk_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_deflate;
#define SERF_BUCKET_IS_DEFLATE(b) SERF_BUCKET_CHECK((b), deflate)

#define SERF_DEFLATE_GZIP 0
#define SERF_DEFLATE_DEFLATE 1

serf_bucket_t *serf_bucket_deflate_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator,
    int format);

serf_bucket_t *serf_bucket_deflate_compress_create(
    serf_bucket_t *stream,
    int memlevel,
    int format,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_limit;
#define SERF_BUCKET_IS_LIMIT(b) SERF_BUCKET_CHECK((b), limit)

serf_bucket_t *serf_bucket_limit_create(
    serf_bucket_t *stream,
    apr_uint64_t limit,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */
#define SERF_SSL_CERT_NOTYETVALID       0x0001
#define SERF_SSL_CERT_EXPIRED           0x0002
#define SERF_SSL_CERT_UNKNOWNCA         0x0004
#define SERF_SSL_CERT_SELF_SIGNED       0x0008
#define SERF_SSL_CERT_UNKNOWN_FAILURE   0x0010
#define SERF_SSL_CERT_REVOKED           0x0020
#define SERF_SSL_CERT_UNABLE_TO_GET_CRL 0x0040
#define SERF_SSL_CERT_INVALID_HOST      0x0080

#define SERF_SSL_OCSP_RESPONDER_TRYLATER        0x0100
#define SERF_SSL_OCSP_RESPONDER_ERROR           0x0200
#define SERF_SSL_OCSP_RESPONDER_UNKNOWN_FAILURE 0x0400

extern const serf_bucket_type_t serf_bucket_type_ssl_encrypt;
#define SERF_BUCKET_IS_SSL_ENCRYPT(b) SERF_BUCKET_CHECK((b), ssl_encrypt)

typedef struct serf_ssl_context_t serf_ssl_context_t;
typedef struct serf_ssl_certificate_t serf_ssl_certificate_t;

typedef apr_status_t (*serf_ssl_need_client_cert_t)(
    void *data,
    const char **cert_path);

typedef apr_status_t (*serf_ssl_need_cert_password_t)(
    void *data,
    const char *cert_path,
    const char **password);

/**
 * Callback type for server certificate status info and OCSP responses.
 * Note that CERT can be NULL in case its called from the OCSP callback.
 */
typedef apr_status_t (*serf_ssl_need_server_cert_t)(
    void *data,
    int failures,
    const serf_ssl_certificate_t *cert);

typedef apr_status_t (*serf_ssl_server_cert_chain_cb_t)(
    void *data,
    int failures,
    int error_depth,
    const serf_ssl_certificate_t * const * certs,
    apr_size_t certs_len);

void serf_ssl_client_cert_provider_set(
    serf_ssl_context_t *context,
    serf_ssl_need_client_cert_t callback,
    void *data,
    void *cache_pool);

void serf_ssl_client_cert_password_set(
    serf_ssl_context_t *context,
    serf_ssl_need_cert_password_t callback,
    void *data,
    void *cache_pool);

/**
 * Set a callback to override the default SSL server certificate validation
 * algorithm.
 */
void serf_ssl_server_cert_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t callback,
    void *data);

/**
 * Set callbacks to override the default SSL server certificate validation
 * algorithm for the current certificate or the entire certificate chain.
 */
void serf_ssl_server_cert_chain_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t cert_callback,
    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
    void *data);

/**
 * Use the default root CA certificates as included with the OpenSSL library.
 */
apr_status_t serf_ssl_use_default_certificates(
    serf_ssl_context_t *context);

/**
 * Allow SNI indicators to be sent to the server.
 */
apr_status_t serf_ssl_set_hostname(
    serf_ssl_context_t *context, const char *hostname);


typedef apr_status_t (*serf_ssl_protocol_result_cb_t)(
    void *data,
    const char *protocol);

/**
 * Enables ALPN negotiation with the server. Setups that the supported protocols
 * will be sent to the server, and enables handling the response via a callback.
 *
 * SUPPORTED_PROTOCOLS is a comma separated list of protocols. No whitespace
 * should be added as the values are used literally. E.g. "h2,http/1.1,h2-16"
 *
 * Returns APR_ENOTIMPL when the ssl library doesn't implement ALPN.
 *
 * If successfull CALLBACK will be called as soon as the protocol is negotiated
 * or directly after the secured stream is connected.
 *
 * @since New in 1.4.
 */
apr_status_t serf_ssl_negotiate_protocol(
    serf_ssl_context_t *context,
    const char *protocols,
    serf_ssl_protocol_result_cb_t callback,
    void *callback_data);

/**
 * Return the depth of the certificate.
 */
int serf_ssl_cert_depth(
    const serf_ssl_certificate_t *cert);

/**
 * Extract the fields of the issuer in a table with keys (E, CN, OU, O, L,
 * ST and C). The returned table will be allocated in @a pool.
 */
apr_hash_t *serf_ssl_cert_issuer(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool);

/**
 * Extract the fields of the subject in a table with keys (E, CN, OU, O, L,
 * ST and C). The returned table will be allocated in @a pool.
 */
apr_hash_t *serf_ssl_cert_subject(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool);

/**
 * Extract the fields of the certificate in a table with keys
 *   (sha1, notBefore, notAfter, subjectAltName, OCSP).
 * The returned table will be allocated in @a pool.
 */
apr_hash_t *serf_ssl_cert_certificate(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool);

/**
 * Like serf_ssl_cert_export2() but uses a single pool for both the
 * result and temporary allocations.
 */
const char *serf_ssl_cert_export(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool);

/**
 * Export a certificate to base64-encoded, zero-terminated string.
 * The returned string is allocated in @a result_pool.
 * Uses @a scratch_pool for temporary allocations.
 * Returns NULL on failure.
 *
 * @since New in 1.4.
 */
const char *serf_ssl_cert_export2(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Import a certificate from a base64-encoded, zero-terminated string.
 * The returned certificate is allocated in @a result_pool.
 * Uses @a scratch_pool for temporary allocations.
 * Returns NULL on failure.
 *
 * @since New in 1.4.
 */
serf_ssl_certificate_t *serf_ssl_cert_import(
    const char *encoded_cert,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Load a CA certificate file from a path @a file_path. If the file was loaded
 * and parsed correctly, a certificate @a cert will be created and returned.
 * This certificate object will be alloced in @a pool.
 */
apr_status_t serf_ssl_load_cert_file(
    serf_ssl_certificate_t **cert,
    const char *file_path,
    apr_pool_t *pool);

/**
 * Adds the certificate @a cert to the list of trusted certificates in
 * @a ssl_ctx that will be used for verification.
 * See also @a serf_ssl_load_cert_file.
 */
apr_status_t serf_ssl_trust_cert(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_certificate_t *cert);

/**
 * Load a CRL .pem file from @a file_path and enable CRL checking.
 *
 * @since New in 1.4.
 */
apr_status_t serf_ssl_add_crl_from_file(serf_ssl_context_t *ssl_ctx,
                                        const char *file_path,
                                        apr_pool_t *pool);

/**
 * Enable or disable CRL checking of all server certificates.
 * @a enabled = 1 to enable CRL checking, 0 to disable CRL checking.
 * Default = disabled.
 *
 * @since New in 1.4.
 */
apr_status_t serf_ssl_check_crl(serf_ssl_context_t *ssl_ctx,
                                int enabled);

/**
 * Enable or disable certificate status request (OCSP stapling) checking of all
 * server certificates.
 * @a enabled = 1 to enable checking, 0 to disable checking.
 * Default = disabled.
 *
 * @since New in 1.4.
 */
apr_status_t
serf_ssl_check_cert_status_request(serf_ssl_context_t *ssl_ctx, int enabled);

/**
 * Enable or disable SSL compression on a SSL session.
 * @a enabled = 1 to enable compression, 0 to disable compression.
 * Default = disabled.
 */
apr_status_t serf_ssl_use_compression(
    serf_ssl_context_t *ssl_ctx,
    int enabled);

serf_bucket_t *serf_bucket_ssl_encrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_context,
    serf_bucket_alloc_t *allocator);

serf_ssl_context_t *serf_bucket_ssl_encrypt_context_get(
    serf_bucket_t *bucket);

/* ==================================================================== */

/**
 * Internal representation of an OCSP request.
 *
 * @since New in 1.4.
 */
typedef struct serf_ssl_ocsp_request_t serf_ssl_ocsp_request_t;

/**
 * Constructs an OCSP verification request for @a server_cert with
 * issuer certificate @a issuer_cert. If @a generate_nonce is
 * non-zero, the request will contain a random nonce.
 *
 * The request will be allocated from @a result_pool.
 *
 * Use @a scratch_pool for temporary allocations.
 *
 * Returns @c NULL on failure, e.g., if @a issuer_cert is not the
 * issuer certificate of @a server_cert.
 *
 * @since New in 1.4.
 */
serf_ssl_ocsp_request_t *serf_ssl_ocsp_request_create(
    const serf_ssl_certificate_t *server_cert,
    const serf_ssl_certificate_t *issuer_cert,
    int generate_nonce,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Returns an pointer to the DER-encoded OCSP request
 * body within the @a ocsp_request structure.
 *
 * The application must decide whether to use this data as the body of
 * an HTTP POST request or Base64-encoded as part of the URI for a GET
 * request; see RFC 2560, section A.1.1.
 *
 * @see serf_ssl_ocsp_request_body_size()
 *
 * @since New in 1.4.
 */
const void *serf_ssl_ocsp_request_body(
    const serf_ssl_ocsp_request_t *ocsp_request);

/**
 * Returns the size of the DER-encoded OCSP request body.
 * @see serf_ssl_ocsp_request_body().
 *
 * @since New in 1.4.
 */
apr_size_t serf_ssl_ocsp_request_body_size(
    const serf_ssl_ocsp_request_t *ocsp_request);

/**
 * Export @a ocsp_request to a zero-terminated string,
 * allocated from @a result_pool.
 *
 * Use @a scratch_pool for temporary allocations.
 *
 * Returns @c NULL on failure.
 *
 * @since New in 1.4.
 */
const char *serf_ssl_ocsp_request_export(
    const serf_ssl_ocsp_request_t *ocsp_request,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Create an OCSP request from a previously exported zero-terminated
 * string @a encoded_ocsp_request. The returned request will be
 * allocated from @a result_pool.
 *
 * Use @a scratch_pool for temporary allocations.
 *
 * Returns @c NULL on failure.
 *
 * @since New in 1.4.
 */
serf_ssl_ocsp_request_t *serf_ssl_ocsp_request_import(
    const char *encoded_ocsp_request,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Internal representation of an OCSP response.
 *
 * @since New in 1.4.
 */
typedef struct serf_ssl_ocsp_response_t serf_ssl_ocsp_response_t;

/**
 * Parse the body of an OCSP response in DER form, @a ocsp_response,
 * of size @a ocsp_response_size, and construct an internal
 * representation, allocated from @a result_pool.
 *
 * If @a failures is not @c NULL, it will be set as in
 * #serf_ssl_need_server_cert_t.
 *
 * Use @a scratch_pool for temporary allocations.
 *
 * Returns @c NULL on failure.
 *
 * @since New in 1.4.
 */
serf_ssl_ocsp_response_t *serf_ssl_ocsp_response_parse(
    const void *ocsp_response,
    apr_size_t ocsp_response_size,
    int *failures,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool);

/**
 * Check if the given @a ocsp_response is valid for the given
 * @a ocsp_request in the provided @a ssl_ctx, as defined by
 * the algorithm documented in RFC 2560, section 3.5.
 *
 * The OCSP responder and application wall clocks may be out of sync
 * by @a clock_skew, and @a max_age is the acceptable age of the
 * request. Their values are truncated to the nearest second.
 *
 * The returned value will be:
 *
 *   - APR_SUCCESS,
 *     if all steps of the verification succeeded;
 *   - SERF_ERROR_SSL_OCSP_RESPONSE_CERT_REVOKED,
 *     if the certificate was revoked;
 *   - SERF_ERROR_SSL_OCSP_RESPONSE_CERT_UNKNOWN,
 *     if the responder knows nothing about the certificate;
 *   - SERF_ERROR_SSL_OCSP_RESPONSE_INVALID,
 *     if the response itself is invalid or not well-formed.
 *
 * The @a this_update and @a next_update output arguments are
 * described in RFC 2560, section 2.4 and, when not @c NULL and if the
 * verificateion succeeded, will be parsed from the response. Any of
 * these times that are not present in the response will be set to the
 * epoch, i.e., @c APR_TIME_C(0).
 *
 * Uses @a scratch_pool for temporary allocations.
 *
 * @since New in 1.4.
 */
apr_status_t serf_ssl_ocsp_response_verify(
    serf_ssl_context_t *ssl_ctx,
    const serf_ssl_ocsp_response_t *ocsp_response,
    const serf_ssl_ocsp_request_t *ocsp_request,
    apr_time_t clock_skew,
    apr_time_t max_age,
    apr_time_t *this_update,
    apr_time_t *next_update,
    apr_pool_t *scratch_pool);

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_ssl_decrypt;
#define SERF_BUCKET_IS_SSL_DECRYPT(b) SERF_BUCKET_CHECK((b), ssl_decrypt)

serf_bucket_t *serf_bucket_ssl_decrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_context,
    serf_bucket_alloc_t *allocator);

serf_ssl_context_t *serf_bucket_ssl_decrypt_context_get(
    serf_bucket_t *bucket);


/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_barrier;
#define SERF_BUCKET_IS_BARRIER(b) SERF_BUCKET_CHECK((b), barrier)

serf_bucket_t *serf_bucket_barrier_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_iovec;
#define SERF_BUCKET_IS_IOVEC(b) SERF_BUCKET_CHECK((b), iovec)

serf_bucket_t *serf_bucket_iovec_create(
    struct iovec vecs[],
    int len,
    serf_bucket_alloc_t *allocator);

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_copy;
#define SERF_BUCKET_IS_COPY(b) SERF_BUCKET_CHECK((b), copy)

serf_bucket_t *serf_bucket_copy_create(
    serf_bucket_t *wrapped,
    apr_size_t min_size,
    serf_bucket_alloc_t *allocator);

/* ==================================================================== */

/* Reads a specific number of bytes from an inner bucket and forwards that
   to a callback, before reading the rest of the bucket normally.

   If the internal bucket is at EOF before the prefix length is read, the
   callback is called with whatever is read before returning EOF.
 */

extern const serf_bucket_type_t serf_bucket_type_prefix;
#define SERF_BUCKET_IS_PREFIX(b) SERF_BUCKET_CHECK((b), prefix)

/* Callback for the prefix handler */
typedef apr_status_t (*serf_bucket_prefix_handler_t)(
    void *baton,
    serf_bucket_t *stream,
    const char *data,
    apr_size_t len);

serf_bucket_t *serf_bucket_prefix_create(
    serf_bucket_t *stream,
    apr_size_t prefix_len,
    serf_bucket_prefix_handler_t handler,
    void *handler_baton,
    serf_bucket_alloc_t *allocator);

/* ==================================================================== */

/**
 * Creates two buckets, *HEAD and *TAIL, which together contain the output
 * of STREAM. If there is enough data in STREAM, HEAD will be a bucket of at
 * least MIN_CHUNK_SIZE and will never be larget than MAX_CHUNK_SIZE.
 *
 * If STREAM is at EOF before MIN_CHUNK_SIZE, HEAD will contain the data,
 * while TAIL is immediately at EOF.
 *
 * HEAD and TAIL will make sure that data read from TAIL will not break the
 * data availability promises on HEAD. Passing an existing tail of this
 * function as new stream may be handled specificaly, but the read promises
 * on all nodes ahead of stream will still hold.
 *
 * HEAD and TAIL are allocated in STREAM->allocator. STREAM will be
 * destroyed when no longer referenced or after EOF.
 *
 * @since New in 1.4.
 */
void serf_bucket_split_create(serf_bucket_t **head,
                              serf_bucket_t **tail,
                              serf_bucket_t *stream,
                              apr_size_t min_chunk_size,
                              apr_size_t max_chunk_size);


/**
 * Check if Serf bucket functions support Brotli (RFC 7932) format.
 * Return non-zero if Brotli is supported and zero otherwise.  If Brotli
 * is not supported, the behavior of all related bucket functions such
 * as @a serf_bucket_brotli_decompress_create is undefined.
 *
 * @since New in 1.4.
 */
int serf_bucket_is_brotli_supported(void);

/** @since New in 1.4. */
extern const serf_bucket_type_t serf_bucket_type_brotli_decompress;
/** @since New in 1.4. */
#define SERF_BUCKET_IS_BROTLI_DECOMPRESS(b) \
    SERF_BUCKET_CHECK((b), brotli_decompress)

/** @since New in 1.4. */
serf_bucket_t *
serf_bucket_brotli_decompress_create(serf_bucket_t *stream,
                                     serf_bucket_alloc_t *alloc);


/* ### do we need a PIPE bucket type? they are simple apr_file_t objects */


#ifdef __cplusplus
}
#endif

#endif /* !SERF_BUCKET_TYPES_H */
