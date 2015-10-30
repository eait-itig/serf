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

#ifndef SERF_PROTOCOL_HTTP2_PRIVATE_H
#define SERF_PROTOCOL_HTTP2_PRIVATE_H

#include "serf.h"
#include "serf_private.h"

#define SERF_LOGHTTP2 \
    SERF_LOGCOMP_PROTOCOL, (__FILE__ ":" APR_STRINGIFY(__LINE__))

#ifdef __cplusplus
extern "C" {
#endif

/* ********** HTTP2 Frame types ********** */

/* The standard maximum framesize. Always supported */
#define HTTP2_DEFAULT_MAX_FRAMESIZE 16384
/* The default stream and connection window size before updates */
#define HTTP2_DEFAULT_WINDOW_SIZE   65535

/* Frame type is an 8 bit unsigned integer */

/* http://tools.ietf.org/html/rfc7540#section-11.2 */
#define HTTP2_FRAME_TYPE_DATA           0x00
#define HTTP2_FRAME_TYPE_HEADERS        0x01
#define HTTP2_FRAME_TYPE_PRIORITY       0x02
#define HTTP2_FRAME_TYPE_RST_STREAM     0x03
#define HTTP2_FRAME_TYPE_SETTINGS       0x04
#define HTTP2_FRAME_TYPE_PUSH_PROMISE   0x05
#define HTTP2_FRAME_TYPE_PING           0x06
#define HTTP2_FRAME_TYPE_GOAWAY         0x07
#define HTTP2_FRAME_TYPE_WINDOW_UPDATE  0x08
#define HTTP2_FRAME_TYPE_CONTINUATION   0x09
/* https://httpwg.github.io/http-extensions/alt-svc.html
   documents that frame 0x0A will most likely be assigned
   to ALT-SVC */

/* ********** HTTP2 Flags ********** */


/* Defined on SETTINGS and PING */
#define HTTP2_FLAG_ACK            0x01
/* Defined on DATA and HEADERS */
#define HTTP2_FLAG_END_STREAM     0x01
/* Defined on HEADERS and CONTINUATION */
#define HTTP2_FLAG_END_HEADERS    0x04
/* Defined on DATA and HEADERS */
#define HTTP2_FLAG_PADDED         0x08
/* Defined on HEADERS */
#define HTTP2_FLAG_PRIORITY       0x20


/* ********** HTTP2 Settings ********** */

/* Settings are 16 bit unsigned integers*/
#define HTTP2_SETTING_HEADER_TABLE_SIZE       0x0001  /* default: 4096 */
#define HTTP2_SETTING_ENABLE_PUSH             0x0002  /* default: 1 */
#define HTTP2_SETTING_MAX_CONCURRENT_STREAMS  0x0003  /* default: (infinite) */
#define HTTP2_SETTING_INITIAL_WINDOW_SIZE     0x0004  /* default: 65535 */
#define HTTP2_SETTING_MAX_FRAME_SIZE          0x0005  /* default: 16384 */
#define HTTP2_SETTING_MAX_HEADER_LIST_SIZE    0x0006  /* default: (infinite) */

/* https://tools.ietf.org/html/rfc7540#section-3.5 */
#define HTTP2_CONNECTION_PREFIX "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"



/* ------------------------------------- */
typedef struct serf_http2_protocol_t serf_http2_protocol_t;
typedef struct serf_http2_stream_t
{
  struct serf_http2_protocol_t *h2;
  serf_bucket_alloc_t *alloc;

  /* Linked list of currently existing streams */
  struct serf_http2_stream_t *next;
  struct serf_http2_stream_t *prev;

  serf_request_t *request; /* May be NULL as streams may outlive requests */

  apr_int64_t lr_window; /* local->remote */
  apr_int64_t rl_window; /* remote->local */

  /* -1 until allocated. Odd is client side initiated, even server side */
  apr_int32_t streamid;

  enum
  {
    H2S_INIT = 0,
    H2S_IDLE,
    H2S_RESERVED_REMOTE,
    H2S_RESERVED_LOCAL,
    H2S_OPEN,
    H2S_HALFCLOSED_REMOTE,
    H2S_HALFCLOSED_LOCAL,
    H2S_CLOSED
  } status;

  /* TODO: Priority, etc. */
} serf_http2_stream_t;

/* Enques an http2 frame for output */
apr_status_t
serf_http2__enqueue_frame(serf_http2_protocol_t *h2,
                          serf_bucket_t *frame,
                          int pump);

/* Creates a new stream */
serf_http2_stream_t *
serf_http2__stream_create(serf_http2_protocol_t *h2,
                          apr_int32_t streamid,
                          apr_uint32_t lr_window,
                          apr_uint32_t rl_window,
                          serf_bucket_alloc_t *alloc);

/* Allocates a new stream id for a stream.
   BATON is a serf_http2_stream_t * instance.

   Passed to serf__bucket_http2_frame_create when writing for
   a stream.
*/
apr_int32_t
serf_http2__allocate_stream_id(void *baton,
                               apr_int32_t *streamid);

void
serf_http2__stream_cleanup(serf_http2_stream_t *stream);

serf_http2_stream_t *
serf_http2__stream_get_by_id(serf_http2_protocol_t *h2,
                             apr_int32_t streamid,
                             int create_for_remote,
                             int move_first);

/* Sets up STREAM to handle REQUEST */
apr_status_t
serf_http2__stream_setup_request(serf_http2_stream_t *stream,
                                 serf_hpack_table_t *hpack_tbl,
                                 serf_request_t *request);



#ifdef __cplusplus
}
#endif

#endif