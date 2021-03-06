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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"


typedef struct iovec_context_t {
    struct iovec *vecs;

    /* Total number of buffer stored in the vecs var. */
    int vecs_len;
    /* Points to the first unread buffer. */
    int current_vec;
    /* First buffer offset. */
    int offset;
} iovec_context_t;

serf_bucket_t *serf_bucket_iovec_create(
    struct iovec vecs[],
    int len,
    serf_bucket_alloc_t *allocator)
{
    iovec_context_t *ctx;
    int i;

    void *buf = serf_bucket_mem_alloc(allocator, sizeof(*ctx) +
                                                 len * sizeof(struct iovec));
    ctx = buf;
    ctx->vecs = (struct iovec *)((char*)buf + sizeof(*ctx));
    ctx->vecs_len = len;
    ctx->current_vec = 0;
    ctx->offset = 0;

    /* copy all buffers to our iovec. */
    for (i = 0; i < len; i++) {
        /* ### skip if iov_len == 0. (and adjust ->vecs_len)  */
        ctx->vecs[i].iov_base = vecs[i].iov_base;
        ctx->vecs[i].iov_len = vecs[i].iov_len;
    }

    return serf_bucket_create(&serf_bucket_type_iovec, allocator, ctx);
}

static apr_status_t serf_iovec_read_iovec(serf_bucket_t *bucket,
                                          apr_size_t requested,
                                          int vecs_size,
                                          struct iovec *vecs,
                                          int *vecs_used)
{
    iovec_context_t *ctx = bucket->data;

    *vecs_used = 0;

    /* copy the requested amount of buffers to the provided iovec. */
    for (; ctx->current_vec < ctx->vecs_len; ctx->current_vec++) {
        struct iovec vec = ctx->vecs[ctx->current_vec];
        apr_size_t remaining;

        if (requested != SERF_READ_ALL_AVAIL && requested <= 0)
            break;
        if (*vecs_used >= vecs_size)
            break;

        /* ### skip returning a vec, if its iov_len will be 0.  */
        vecs[*vecs_used].iov_base = (char*)vec.iov_base + ctx->offset;
        remaining = vec.iov_len - ctx->offset;

        /* Less bytes requested than remaining in the current buffer. */
        if (requested != SERF_READ_ALL_AVAIL && requested < remaining) {
            vecs[*vecs_used].iov_len = requested;
            ctx->offset += requested;
            requested = 0;
            (*vecs_used)++;
            break;
        } else {
            /* Copy the complete buffer. */
            vecs[*vecs_used].iov_len = remaining;
            ctx->offset = 0;
            if (requested != SERF_READ_ALL_AVAIL)
                requested -= remaining;
            (*vecs_used)++;
        }
    }

    if (ctx->current_vec == ctx->vecs_len && !ctx->offset)
        return APR_EOF;

    return APR_SUCCESS;
}

static apr_status_t serf_iovec_read(serf_bucket_t *bucket,
                                    apr_size_t requested,
                                    const char **data, apr_size_t *len)
{
    struct iovec vec[1];
    apr_status_t status;
    int vecs_used;

    status = serf_iovec_read_iovec(bucket, requested, 1, vec, &vecs_used);

    if (vecs_used) {
        *data = vec[0].iov_base;
        *len = vec[0].iov_len;
    } else {
        *len = 0;
    }

    return status;
}

static apr_status_t serf_iovec_peek(serf_bucket_t *bucket,
                                    const char **data,
                                    apr_size_t *len)
{
    iovec_context_t *ctx = bucket->data;

    if (ctx->current_vec >= ctx->vecs_len) {
        *len = 0;
        return APR_EOF;
    }

    /* Return the first unread buffer, don't bother combining all
       remaining data. */
    /* ### skip current_vec if iov_len will be 0.  */
    *data = (const char *)ctx->vecs[ctx->current_vec].iov_base + ctx->offset;
    *len = ctx->vecs[ctx->current_vec].iov_len - ctx->offset;

    if (ctx->current_vec + 1 == ctx->vecs_len)
        return APR_EOF;

    return APR_SUCCESS;
}

static apr_uint64_t serf_iovec_get_remaining(serf_bucket_t *bucket)
{
    iovec_context_t *ctx = bucket->data;
    apr_uint64_t total = 0;
    int i;

    for (i = ctx->current_vec; i < ctx->vecs_len; i++)
      {
        total += ctx->vecs[i].iov_len;
      }

    return total - ctx->offset;
}

const serf_bucket_type_t serf_bucket_type_iovec = {
    "IOVEC",
    serf_iovec_read,
    serf_default_readline,
    serf_iovec_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_iovec_peek,
    serf_default_destroy_and_data,
    serf_default_read_bucket,
    serf_iovec_get_remaining,
    serf_default_ignore_config
};
