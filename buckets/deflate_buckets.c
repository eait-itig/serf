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

#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_strings.h>

#include <zlib.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

/* magic header */
static char deflate_magic[2] = { '\037', '\213' };
#define DEFLATE_MAGIC_SIZE 10
#define DEFLATE_VERIFY_SIZE 8
#define DEFLATE_BUFFER_SIZE 8096

static const int DEFLATE_WINDOW_SIZE = -15;
static const int DEFLATE_MEMLEVEL = 9;

typedef struct deflate_context_t {
    serf_bucket_t *stream;
    serf_bucket_t *inflate_stream;

    int format;                 /* Are we 'deflate' or 'gzip'? */

    enum deflate_state_t {
        STATE_READING_HEADER,   /* reading the gzip header */
        STATE_HEADER,           /* read the gzip header */
        STATE_INIT,             /* init'ing zlib functions */
        STATE_INFLATE,          /* inflating the content now */
        STATE_READING_VERIFY,   /* reading the final gzip CRC */
        STATE_VERIFY,           /* verifying the final gzip CRC */
        STATE_FINISH,           /* clean up after reading body */
        STATE_DONE,             /* body is done; we'll return EOF here */

        /* When handling things the other way around */
        STATE_WRITING_HEADER,   /* produces a gzip header */
        STATE_COMPRESS_INIT,    /* initializes zlib for compression */
        STATE_COMPRESS_FINISH,  /* clean up after producing body */
    } state;

    z_stream zstream;
    char hdr_buffer[DEFLATE_MAGIC_SIZE];
    unsigned char buffer[DEFLATE_BUFFER_SIZE];
    unsigned long crc;
    int windowSize;
    int memLevel;              /* -1 when decompressing.
                                  Otherwise the memlevel to use*/
    int bufferSize;

    /* How much of the chunk, or the terminator, do we have left to read? */
    apr_size_t stream_left;

    /* How much are we supposed to read? */
    apr_size_t stream_size;

    int stream_status; /* What was the last status we read? */

    serf_config_t *config;
} deflate_context_t;

/* Inputs a string and returns a long.  */
static unsigned long getLong(unsigned char *string)
{
    return ((unsigned long)string[0])
          | (((unsigned long)string[1]) << 8)
          | (((unsigned long)string[2]) << 16)
          | (((unsigned long)string[3]) << 24);
}

/* zlib alloc function. opaque is the bucket allocator. */
static voidpf zalloc_func(voidpf opaque, uInt items, uInt size)
{
    serf_bucket_alloc_t *allocator = opaque;
    apr_size_t alloc_size = items * size;
    return serf_bucket_mem_alloc(allocator, alloc_size);
}

/* zlib free function */
static void zfree_func(voidpf opaque, voidpf address)
{
    if (address) {
        serf_bucket_alloc_t *allocator = opaque;
        serf_bucket_mem_free(allocator, address);
    }
}

serf_bucket_t *serf_bucket_deflate_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator,
    int format)
{
    deflate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->stream_status = APR_SUCCESS;
    ctx->inflate_stream = serf_bucket_aggregate_create(allocator);
    ctx->format = format;
    ctx->crc = 0;
    ctx->config = NULL;
    /* zstream must be NULL'd out. */
    memset(&ctx->zstream, 0, sizeof(ctx->zstream));

    /* Configure alloc/free callbacks to allocate memory from bucket
     * allocator. */
    ctx->zstream.zalloc = zalloc_func;
    ctx->zstream.zfree = zfree_func;
    ctx->zstream.opaque = allocator;

    switch (ctx->format) {
        case SERF_DEFLATE_GZIP:
            ctx->state = STATE_READING_HEADER;
            break;
        case SERF_DEFLATE_DEFLATE:
            /* deflate doesn't have a header. */
            ctx->state = STATE_INIT;
            break;
        default:
            /* Not reachable */
            return NULL;
    }

    /* Initial size of gzip header. */
    ctx->stream_left = ctx->stream_size = DEFLATE_MAGIC_SIZE;

    ctx->windowSize = DEFLATE_WINDOW_SIZE;
    ctx->memLevel = -1;
    ctx->bufferSize = DEFLATE_BUFFER_SIZE;

    return serf_bucket_create(&serf_bucket_type_deflate, allocator, ctx);
}

serf_bucket_t *serf_bucket_deflate_compress_create(
    serf_bucket_t *stream,
    int memlevel,
    int format,
    serf_bucket_alloc_t *allocator)
{
    deflate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->stream_status = APR_SUCCESS;
    ctx->inflate_stream = serf_bucket_aggregate_create(allocator);
    ctx->format = format;
    ctx->crc = 0;
    ctx->config = NULL;
    /* zstream must be NULL'd out. */
    memset(&ctx->zstream, 0, sizeof(ctx->zstream));

    /* Configure alloc/free callbacks to allocate memory from bucket
     * allocator. */
    ctx->zstream.zalloc = zalloc_func;
    ctx->zstream.zfree = zfree_func;
    ctx->zstream.opaque = allocator;

    switch (ctx->format) {
        case SERF_DEFLATE_GZIP:
            ctx->state = STATE_WRITING_HEADER;
            break;
        case SERF_DEFLATE_DEFLATE:
            /* deflate doesn't have a header. */
            ctx->state = STATE_COMPRESS_INIT;
            break;
      default:
            /* Not reachable */
            return NULL;
    }

    /* Initial size of gzip header. */
    ctx->stream_left = ctx->stream_size = DEFLATE_MAGIC_SIZE;

    ctx->windowSize = DEFLATE_WINDOW_SIZE;
    ctx->memLevel = (memlevel > 0) ? memlevel : DEFLATE_MEMLEVEL;
    ctx->bufferSize = DEFLATE_BUFFER_SIZE;

    return serf_bucket_create(&serf_bucket_type_deflate, allocator, ctx);
}

static void serf_deflate_destroy_and_data(serf_bucket_t *bucket)
{
    deflate_context_t *ctx = bucket->data;

    if ((ctx->state > STATE_INIT && ctx->state <= STATE_FINISH)
        || (ctx->state > STATE_COMPRESS_INIT
            && ctx->state < STATE_COMPRESS_FINISH))
    {
        if (ctx->memLevel >= 0)
            deflateEnd(&ctx->zstream);
        else
            inflateEnd(&ctx->zstream);
    }

    /* We may have appended stream into the inflate bucket.
     * If so, avoid free'ing it twice.
     */
    serf_bucket_destroy(ctx->inflate_stream);
    if (ctx->stream)
        serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_deflate_refill(serf_bucket_t *bucket)
{
    deflate_context_t *ctx = bucket->data;
    apr_status_t status;
    int zRC;
    int flush_v = Z_NO_FLUSH;

    /* We have nothing buffered. Fetch more. */

    /* It is possible that we maxed out avail_out before
      * exhausting avail_in; therefore, continue using the
      * previous buffer.  Otherwise, fetch more data from
      * our stream bucket.
      */
    if (ctx->zstream.avail_in == 0) {
        const char *private_data;
        apr_size_t private_len;

        /* When we empty our inflated stream, we'll return this
          * status - this allow us to eventually pass up EAGAINs.
          */
        ctx->stream_status = serf_bucket_read(ctx->stream,
                                              ctx->bufferSize,
                                              &private_data,
                                              &private_len);

        if (SERF_BUCKET_READ_ERROR(ctx->stream_status)) {
            return ctx->stream_status;
        }

        if (!private_len && APR_STATUS_IS_EAGAIN(ctx->stream_status)) {
            status = ctx->stream_status;
            ctx->stream_status = APR_SUCCESS;
            return status;
        }

        if (APR_STATUS_IS_EOF(ctx->stream_status))
            flush_v = Z_FINISH;

        /* Make valgrind happy and explictly initialize next_in to specific
          * value for empty buffer. */
        if (private_len) {
            ctx->zstream.next_in = (unsigned char*)private_data;
            ctx->zstream.avail_in = private_len;
            if (ctx->memLevel >= 0)
                ctx->crc = crc32(ctx->crc, (const Bytef *)private_data,
                                 private_len);
        } else {
            ctx->zstream.next_in = Z_NULL;
            ctx->zstream.avail_in = 0;
        }
    }

    while (1) {

        if (ctx->memLevel < 0) {
            zRC = inflate(&ctx->zstream, flush_v);
            if (zRC == Z_BUF_ERROR && APR_STATUS_IS_EOF(ctx->stream_status) &&
                ctx->zstream.avail_out > 0) {
                /* Zlib can't continue, although there's still space in the
                   output buffer.  This can happen either if the stream is
                   truncated or corrupted.  As we don't know for sure,
                   return a generic error. */
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
        }
        else {
            zRC = deflate(&ctx->zstream, flush_v);
        }

        if (zRC == Z_BUF_ERROR || ctx->zstream.avail_out == 0) {
            /* We're full or zlib requires more space. Either case, clear
               out our buffer, reset, and return. */
            apr_size_t private_len;
            serf_bucket_t *tmp;

            ctx->zstream.next_out = ctx->buffer;
            private_len = ctx->bufferSize - ctx->zstream.avail_out;

            if (ctx->memLevel < 0)
              ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer,
                               private_len);

            /* FIXME: There probably needs to be a free func. */
            tmp = SERF_BUCKET_SIMPLE_STRING_LEN((char *)ctx->buffer,
                                                private_len,
                                                bucket->allocator);
            serf_bucket_aggregate_append(ctx->inflate_stream, tmp);
            ctx->zstream.avail_out = ctx->bufferSize;

            zRC = Z_OK;
            break;
        }

        if (zRC == Z_STREAM_END) {
            apr_size_t private_len;
            serf_bucket_t *tmp;

            private_len = ctx->bufferSize - ctx->zstream.avail_out;
            if (ctx->memLevel < 0)
              ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer,
                               private_len);
            /* FIXME: There probably needs to be a free func. */
            tmp = SERF_BUCKET_SIMPLE_STRING_LEN((char *)ctx->buffer,
                                                private_len,
                                                bucket->allocator);
            serf_bucket_aggregate_append(ctx->inflate_stream, tmp);

            ctx->zstream.avail_out = ctx->bufferSize;

            if (ctx->zstream.avail_in) {
                /* Push back the remaining data to be read. */
                tmp = serf_bucket_aggregate_create(bucket->allocator);
                serf_bucket_set_config(tmp, ctx->config);
                serf_bucket_aggregate_prepend(tmp, ctx->stream);
                ctx->stream = tmp;

                /* We now need to take the remaining avail_in and
                 * throw it in ctx->stream so our next read picks it up.
                 */

                tmp = SERF_BUCKET_SIMPLE_STRING_LEN(
                                (const char*)ctx->zstream.next_in,
                                              ctx->zstream.avail_in,
                                              bucket->allocator);
                serf_bucket_aggregate_prepend(ctx->stream, tmp);
            }

            switch (ctx->format) {
            case SERF_DEFLATE_GZIP:
                if (ctx->memLevel >= 0) {
                     char *verify_header = serf_bucket_mem_alloc(
                                                bucket->allocator,
                                                DEFLATE_VERIFY_SIZE);

                     verify_header[0] =  ctx->crc        & 0xFF;
                     verify_header[1] = (ctx->crc >>  8) & 0xFF;
                     verify_header[2] = (ctx->crc >> 16) & 0xFF;
                     verify_header[3] = (ctx->crc >> 24) & 0xFF;

                     verify_header[4] =  ctx->zstream.total_in & 0xFF;
                     verify_header[5] = (ctx->zstream.total_in >>  8) & 0xFF;
                     verify_header[6] = (ctx->zstream.total_in >> 16) & 0xFF;
                     verify_header[7] = (ctx->zstream.total_in >> 24) & 0xFF;

                     serf_bucket_aggregate_append(
                              ctx->inflate_stream,
                              serf_bucket_simple_own_create(verify_header,
                                                            DEFLATE_VERIFY_SIZE,
                                                            bucket->allocator));
                     ctx->state = STATE_COMPRESS_FINISH;
                }
                else {
                    ctx->stream_left = ctx->stream_size =
                                              DEFLATE_VERIFY_SIZE;
                    ctx->state++;
                }
                break;
            case SERF_DEFLATE_DEFLATE:
                /* Deflate does not have a verify footer. */
                if (ctx->memLevel >= 0)
                    ctx->state = STATE_COMPRESS_FINISH;
                else
                    ctx->state = STATE_FINISH;
                break;
            default:
                /* Not reachable */
                return APR_EGENERAL;
            }

            break;
        }

        /* Any other error? */
        if (zRC != Z_OK) {
            serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__,
                      ctx->config, "inflate error %d - %s\n",
                      zRC, ctx->zstream.msg);
            return SERF_ERROR_DECOMPRESSION_FAILED;
        }

        /* As long as zRC == Z_OK, just keep looping. */
    }

    if (zRC != Z_OK && zRC != Z_STREAM_END)
        return SERF_ERROR_DECOMPRESSION_FAILED;
    else
        return APR_SUCCESS;
}

static apr_status_t serf_deflate_wait_for_data(serf_bucket_t *bucket)
{
    deflate_context_t *ctx = bucket->data;
    apr_status_t status;
    const char *private_data;
    apr_size_t private_len;
    int zRC;

    while (1) {
        switch (ctx->state) {
        case STATE_READING_HEADER:
        case STATE_READING_VERIFY:
            status = serf_bucket_read(ctx->stream, ctx->stream_left,
                                      &private_data, &private_len);

            if (SERF_BUCKET_READ_ERROR(status)) {
                return status;
            }

            /* The C99 standard (7.21.1/2) requires valid data pointer
             * even for zero length array for all functions unless explicitly
             * stated otherwise. So don't copy data even most mempy()
             * implementations have special handling for zero length copy. */
            if (private_len) {
                memcpy(ctx->hdr_buffer + (ctx->stream_size - ctx->stream_left),
                       private_data, private_len);

                ctx->stream_left -= private_len;
            }

            if (ctx->stream_left == 0) {
                ctx->state++;
                if (APR_STATUS_IS_EAGAIN(status)) {
                    return status;
                }
            }
            else if (status) {
                return status;
            }
            break;
        case STATE_HEADER:
            if (ctx->hdr_buffer[0] != deflate_magic[0] ||
                ctx->hdr_buffer[1] != deflate_magic[1]) {

                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "Incorrect magic number. Actual:%hhx%hhx.\n",
                          ctx->hdr_buffer[0], ctx->hdr_buffer[1]);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            if (ctx->hdr_buffer[3] != 0) {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "Incorrect magic number (at offset 3). Actual: "
                          "%x\n", ctx->hdr_buffer[3]);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            ctx->state++;
            break;
        case STATE_VERIFY:
        {
            unsigned long compCRC, compLen, actualLen;

            /* Do the checksum computation. */
            compCRC = getLong((unsigned char*)ctx->hdr_buffer);
            if (ctx->crc != compCRC) {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "Incorrect crc. Expected: %ld, Actual:%ld\n",
                          compCRC, ctx->crc);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            compLen = getLong((unsigned char*)ctx->hdr_buffer + 4);
            /* The length in the trailer is module 2^32, so do the same for
               the actual length. */
            actualLen = ctx->zstream.total_out;
            actualLen &= 0xFFFFFFFF;
            if (actualLen != compLen) {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "Incorrect length. Expected: %ld, Actual:%ld\n",
                          compLen, ctx->zstream.total_out);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            ctx->state++;
            break;
        }
        case STATE_INIT:
            zRC = inflateInit2(&ctx->zstream, ctx->windowSize);
            if (zRC != Z_OK) {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "inflateInit2 error %d - %s\n",
                          zRC, ctx->zstream.msg);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            ctx->zstream.next_out = ctx->buffer;
            ctx->zstream.avail_out = ctx->bufferSize;
            ctx->state++;
            break;
        case STATE_FINISH:
            inflateEnd(&ctx->zstream);
            serf_bucket_aggregate_append(ctx->inflate_stream,
                                         ctx->stream);
            ctx->stream = NULL;
            ctx->state = STATE_DONE;
            break;
        case STATE_INFLATE:
            return APR_SUCCESS;
        case STATE_DONE:
            /* We're done inflating.  Use our finished buffer. */
            return ctx->inflate_stream ? APR_SUCCESS : APR_EOF;


        case STATE_WRITING_HEADER:
            {
              char *header = serf_bucket_mem_calloc(bucket->allocator,
                                                    DEFLATE_MAGIC_SIZE);
              memcpy(header, deflate_magic, sizeof(deflate_magic));
              header[2] = Z_DEFLATED;
              /* No mtime. DOS/Default OS */

              serf_bucket_aggregate_append(
                      ctx->inflate_stream,
                      serf_bucket_simple_own_create(header, DEFLATE_MAGIC_SIZE,
                                                    bucket->allocator));
              ctx->state++;
              break;
            }
        case STATE_COMPRESS_INIT:
            zRC = deflateInit2(&ctx->zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                               ctx->windowSize, ctx->memLevel, Z_DEFAULT_STRATEGY);
            if (zRC != Z_OK) {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__, ctx->config,
                          "deflateInit2 error %d - %s\n",
                          zRC, ctx->zstream.msg);
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            ctx->zstream.next_out = ctx->buffer;
            ctx->zstream.avail_out = ctx->bufferSize;
            ctx->state = STATE_INFLATE;
            break;
        case STATE_COMPRESS_FINISH:
            deflateEnd(&ctx->zstream);
            serf_bucket_aggregate_append(ctx->inflate_stream,
                                         ctx->stream);
            ctx->stream = NULL;
            ctx->state = STATE_DONE;
            break;
        default:
            /* Not reachable */
            return APR_EGENERAL;
        }
    }

    /* NOTREACHED */
}

static apr_status_t serf_deflate_read(serf_bucket_t *bucket,
                                      apr_size_t requested,
                                      const char **data, apr_size_t *len)
{
    deflate_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_deflate_wait_for_data(bucket);
    if (status || (ctx->state != STATE_INFLATE && ctx->state != STATE_DONE)) {
        *data = "";
        *len = 0;
        return status;
    }

    status = serf_bucket_read(ctx->inflate_stream, requested, data, len);
    if (APR_STATUS_IS_EOF(status) && ctx->state != STATE_DONE)
        status = APR_SUCCESS;

    if (status || *len || ctx->state != STATE_INFLATE) {
        return status;
    }

    status = serf_deflate_refill(bucket);

    if (status) {
        *data = "";
        *len = 0;
        return status;
    }

    /* Okay, we've inflated.  Try to read again. */
    status = serf_bucket_read(ctx->inflate_stream, requested, data, len);
    /* Hide EOF. */
    if (APR_STATUS_IS_EOF(status)) {

        /* If the inflation wasn't finished, return APR_SUCCESS. */
        if (ctx->state != STATE_DONE)
            return APR_SUCCESS; /* Not at EOF yet */

        /* If our stream is finished too and all data was inflated,
         * return SUCCESS so we'll iterate one more time.
         */
        if (APR_STATUS_IS_EOF(ctx->stream_status)) {
            /* No more data to read from the stream, and everything
                inflated. If all data was received correctly, state
                should have been advanced to STATE_READING_VERIFY or
                STATE_FINISH. If not, then the data was incomplete
                and we have an error. */
            if (ctx->state != STATE_DONE)
                return APR_SUCCESS;
            else {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__,
                          ctx->config,
                          "Unexpected EOF on input stream\n");
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
        }
    }

    return status;
}

static apr_status_t serf_deflate_peek(serf_bucket_t *bucket,
                                      const char **data,
                                      apr_size_t *len)
{
    deflate_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_deflate_wait_for_data(bucket);
    if (status || (ctx->state != STATE_INFLATE && ctx->state != STATE_DONE)) {
        *data = "";
        *len = 0;
        return status;
    }

    status = serf_bucket_peek(ctx->inflate_stream, data, len);
    if (APR_STATUS_IS_EOF(status))
        status = APR_SUCCESS;

    if (status || *len || ctx->state != STATE_INFLATE) {
        return status;
    }

    status = serf_deflate_refill(bucket);

    if (status) {
        *data = "";
        *len = 0;
        return status;
    }

    /* Okay, we've inflated.  Try to peek again. */
    status = serf_bucket_peek(ctx->inflate_stream, data, len);
    /* Hide EOF. */
    if (APR_STATUS_IS_EOF(status)) {

        /* If the inflation wasn't finished, return APR_SUCCESS. */
        if (ctx->state == STATE_INFLATE)
            return APR_SUCCESS; /* Not at EOF yet */

        /* If our stream is finished too and all data was inflated,
         * return SUCCESS so we'll iterate one more time.
         */
        if (APR_STATUS_IS_EOF(ctx->stream_status)) {
            /* No more data to read from the stream, and everything
                inflated. If all data was received correctly, state
                should have been advanced to STATE_READING_VERIFY or
                STATE_FINISH. If not, then the data was incomplete
                and we have an error. */
            if (ctx->state != STATE_INFLATE)
                return APR_SUCCESS;
            else {
                serf__log(LOGLVL_ERROR, LOGCOMP_COMPR, __FILE__,
                          ctx->config,
                          "Unexpected EOF on input stream\n");
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
        }
    }

    return status;
}

static apr_status_t serf_deflate_set_config(serf_bucket_t *bucket,
                                            serf_config_t *config)
{
    deflate_context_t *ctx = bucket->data;

    ctx->config = config;

    if (ctx->stream)
        return serf_bucket_set_config(ctx->stream, config);

    return APR_SUCCESS;
}

const serf_bucket_type_t serf_bucket_type_deflate = {
    "DEFLATE",
    serf_deflate_read,
    serf_default_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_deflate_peek,
    serf_deflate_destroy_and_data,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_deflate_set_config,
};
