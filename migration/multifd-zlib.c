/*
 * Multifd zlib compression implementation
 *
 * Copyright (c) 2020 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <zlib.h>
#include "qemu/rcu.h"
#include "system/ramblock.h"
#include "exec/target_page.h"
#include "qapi/error.h"
#include "migration.h"
#include "trace.h"
#include "options.h"
#include "multifd.h"

struct zlib_data {
    /* stream for compression */
    z_stream zs;
    /* compressed buffer */
    uint8_t *zbuff;
    /* size of compressed buffer */
    uint32_t zbuff_len;
    /* uncompressed buffer of size qemu_target_page_size() */
    uint8_t *buf;
};

/* Multifd zlib compression */

static int multifd_zlib_send_setup(MultiFDSendParams *p, Error **errp)
{
    struct zlib_data *z = g_new0(struct zlib_data, 1);
    z_stream *zs = &z->zs;
    const char *err_msg;

    zs->zalloc = Z_NULL;
    zs->zfree = Z_NULL;
    zs->opaque = Z_NULL;
    if (deflateInit(zs, migrate_multifd_zlib_level()) != Z_OK) {
        err_msg = "deflate init failed";
        goto err_free_z;
    }
    /* This is the maximum size of the compressed buffer */
    z->zbuff_len = compressBound(MULTIFD_PACKET_SIZE);
    z->zbuff = g_try_malloc(z->zbuff_len);
    if (!z->zbuff) {
        err_msg = "out of memory for zbuff";
        goto err_deflate_end;
    }
    z->buf = g_try_malloc(qemu_target_page_size());
    if (!z->buf) {
        err_msg = "out of memory for buf";
        goto err_free_zbuff;
    }
    p->compress_data = z;

    /* Needs 2 IOVs, one for packet header and one for compressed data */
    p->iov = g_new0(struct iovec, 2);

    if (migrate_xbzrle()) {
        uint32_t page_count = multifd_ram_page_count();
        uint32_t nchannels = migrate_multifd_channels();
        uint64_t total_cache = migrate_xbzrle_cache_size();
        uint64_t cache_size;

        if (nchannels <= 1) {
            cache_size = total_cache;
        } else if (p->id == 0) {
            cache_size = total_cache / 2;
        } else {
            cache_size = (total_cache / 2) / (nchannels - 1);
        }
        if (multifd_xbzrle_state_alloc(&p->xbzrle, cache_size,
                                       page_count, errp)) {
            multifd_zlib_send_cleanup(p, NULL);
            return -1;
        }
    }

    return 0;

err_free_zbuff:
    g_free(z->zbuff);
err_deflate_end:
    deflateEnd(zs);
err_free_z:
    g_free(z);
    error_setg(errp, "multifd %u: %s", p->id, err_msg);
    return -1;
}

static void multifd_zlib_send_cleanup(MultiFDSendParams *p, Error **errp)
{
    struct zlib_data *z = p->compress_data;

    deflateEnd(&z->zs);
    g_free(z->zbuff);
    z->zbuff = NULL;
    g_free(z->buf);
    z->buf = NULL;
    g_free(p->compress_data);
    p->compress_data = NULL;

    multifd_xbzrle_state_free(&p->xbzrle);
    g_free(p->iov);
    p->iov = NULL;
}

static int multifd_zlib_send_prepare(MultiFDSendParams *p, Error **errp)
{
    MultiFDPages_t *pages = &p->data->u.ram;
    struct zlib_data *z = p->compress_data;
    z_stream *zs = &z->zs;
    uint32_t out_size = 0;
    uint32_t page_size = multifd_ram_page_size();
    bool use_xbzrle = migrate_xbzrle() && p->xbzrle.cache;
    int ret;
    uint32_t i;

    if (!multifd_send_prepare_common(p)) {
        goto out;
    }

    if (use_xbzrle && pages->normal_num > 0) {
        /*
         * XBZRLE-encode first, then deflate the compacted blob.
         * This gives double compression: delta + zlib.
         */
        multifd_xbzrle_encode_pages(p);

        deflateReset(zs);
        zs->avail_in = p->next_packet_size;
        zs->next_in = p->xbzrle.data_buf;
        zs->avail_out = z->zbuff_len;
        zs->next_out = z->zbuff;

        ret = deflate(zs, Z_FINISH);
        if (ret != Z_STREAM_END) {
            error_setg(errp, "multifd %u: deflate xbzrle data failed %d",
                       p->id, ret);
            return -1;
        }
        out_size = z->zbuff_len - zs->avail_out;
        goto fill_iov;
    }

    for (i = 0; i < pages->normal_num; i++) {
        uint32_t available = z->zbuff_len - out_size;
        int flush = Z_NO_FLUSH;

        if (i == pages->normal_num - 1) {
            flush = Z_SYNC_FLUSH;
        }

        /*
         * Since the VM might be running, the page may be changing concurrently
         * with compression. zlib does not guarantee that this is safe,
         * therefore copy the page before calling deflate().
         */
        memcpy(z->buf, pages->block->host + pages->offset[i], page_size);
        zs->avail_in = page_size;
        zs->next_in = z->buf;

        zs->avail_out = available;
        zs->next_out = z->zbuff + out_size;

        /*
         * Welcome to deflate semantics
         *
         * We need to loop while:
         * - return is Z_OK
         * - there are stuff to be compressed
         * - there are output space free
         */
        do {
            ret = deflate(zs, flush);
        } while (ret == Z_OK && zs->avail_in && zs->avail_out);
        if (ret == Z_OK && zs->avail_in) {
            error_setg(errp, "multifd %u: deflate failed to compress all input",
                       p->id);
            return -1;
        }
        if (ret != Z_OK) {
            error_setg(errp, "multifd %u: deflate returned %d instead of Z_OK",
                       p->id, ret);
            return -1;
        }
        out_size += available - zs->avail_out;
    }
fill_iov:
    p->iov[p->iovs_num].iov_base = z->zbuff;
    p->iov[p->iovs_num].iov_len = out_size;
    p->iovs_num++;
    p->next_packet_size = out_size;

out:
    p->flags |= MULTIFD_FLAG_ZLIB;
    if (use_xbzrle && pages->normal_num > 0) {
        p->flags |= MULTIFD_FLAG_XBZRLE;
    }
    multifd_send_fill_packet(p);
    if (p->flags & MULTIFD_FLAG_XBZRLE) {
        multifd_xbzrle_ext_write(p);
    }
    return 0;
}

static int multifd_zlib_recv_setup(MultiFDRecvParams *p, Error **errp)
{
    struct zlib_data *z = g_new0(struct zlib_data, 1);
    z_stream *zs = &z->zs;

    zs->zalloc = Z_NULL;
    zs->zfree = Z_NULL;
    zs->opaque = Z_NULL;
    zs->avail_in = 0;
    zs->next_in = Z_NULL;
    if (inflateInit(zs) != Z_OK) {
        error_setg(errp, "multifd %u: inflate init failed", p->id);
        g_free(z);
        return -1;
    }
    /* To be safe, we reserve twice the size of the packet */
    z->zbuff_len = MULTIFD_PACKET_SIZE * 2;
    z->zbuff = g_try_malloc(z->zbuff_len);
    if (!z->zbuff) {
        inflateEnd(zs);
        error_setg(errp, "multifd %u: out of memory for zbuff", p->id);
        g_free(z);
        return -1;
    }

    p->compress_data = z;

    if (migrate_xbzrle()) {
        uint32_t page_count = multifd_ram_page_count();
        uint32_t nchannels = migrate_multifd_channels();
        uint64_t total_cache = migrate_xbzrle_cache_size();
        uint64_t cache_size;

        if (nchannels <= 1) {
            cache_size = total_cache;
        } else if (p->id == 0) {
            cache_size = total_cache / 2;
        } else {
            cache_size = (total_cache / 2) / (nchannels - 1);
        }
        if (multifd_xbzrle_state_alloc(&p->xbzrle, cache_size,
                                       page_count, errp)) {
            multifd_zlib_recv_cleanup(p);
            return -1;
        }
    }

    return 0;
}

static void multifd_zlib_recv_cleanup(MultiFDRecvParams *p)
{
    struct zlib_data *z = p->compress_data;

    inflateEnd(&z->zs);
    g_free(z->zbuff);
    z->zbuff = NULL;
    g_free(p->compress_data);
    p->compress_data = NULL;
    multifd_xbzrle_state_free(&p->xbzrle);
}

static int multifd_zlib_recv(MultiFDRecvParams *p, Error **errp)
{
    struct zlib_data *z = p->compress_data;
    z_stream *zs = &z->zs;
    uint32_t in_size = p->next_packet_size;
    uint32_t page_size = multifd_ram_page_size();
    uint32_t flags = p->flags & MULTIFD_FLAG_COMPRESSION_MASK;
    int ret;

    if (flags != MULTIFD_FLAG_ZLIB) {
        error_setg(errp, "multifd %u: flags received %x flags expected %x",
                   p->id, flags, MULTIFD_FLAG_ZLIB);
        return -1;
    }

    multifd_recv_zero_page_process(p);

    if (!p->normal_num) {
        assert(in_size == 0);
        return 0;
    }

    ret = qio_channel_read_all(p->c, (void *)z->zbuff, in_size, errp);

    if (ret != 0) {
        return ret;
    }

    if (p->flags & MULTIFD_FLAG_XBZRLE) {
        if (!p->xbzrle.cache) {
            error_setg(errp, "multifd %u: received XBZRLE packet but "
                       "XBZRLE is not enabled", p->id);
            return -1;
        }
        inflateReset(zs);
        zs->avail_in = in_size;
        zs->next_in = z->zbuff;
        zs->avail_out = multifd_ram_page_count() * page_size;
        zs->next_out = p->xbzrle.data_buf;

        ret = inflate(zs, Z_FINISH);
        if (ret != Z_STREAM_END) {
            error_setg(errp, "multifd %u: inflate xbzrle data failed %d",
                       p->id, ret);
            return -1;
        }

        return multifd_xbzrle_decode_pages(p, errp);
    }

    /* Fallback to standard page-by-page decompression */
    /* we measure the change of total_out */
    uint32_t out_size = zs->total_out;
    uint32_t expected_size = p->normal_num * page_size;
    int i;

    zs->avail_in = in_size;
    zs->next_in = z->zbuff;

    for (i = 0; i < p->normal_num; i++) {
        int flush = Z_NO_FLUSH;
        unsigned long start = zs->total_out;

        ramblock_recv_bitmap_set_offset(p->block, p->normal[i]);
        if (i == p->normal_num - 1) {
            flush = Z_SYNC_FLUSH;
        }

        zs->avail_out = page_size;
        zs->next_out = p->host + p->normal[i];

        /*
         * Welcome to inflate semantics
         *
         * We need to loop while:
         * - return is Z_OK
         * - there are input available
         * - we haven't completed a full page
         */
        do {
            ret = inflate(zs, flush);
        } while (ret == Z_OK && zs->avail_in
                             && (zs->total_out - start) < page_size);
        if (ret == Z_OK && (zs->total_out - start) < page_size) {
            error_setg(errp, "multifd %u: inflate generated too few output",
                       p->id);
            return -1;
        }
        if (ret != Z_OK) {
            error_setg(errp, "multifd %u: inflate returned %d instead of Z_OK",
                       p->id, ret);
            return -1;
        }
    }
    out_size = zs->total_out - out_size;
    if (out_size != expected_size) {
        error_setg(errp, "multifd %u: packet size received %u size expected %u",
                   p->id, out_size, expected_size);
        return -1;
    }

    return 0;
}

static const MultiFDMethods multifd_zlib_ops = {
    .send_setup = multifd_zlib_send_setup,
    .send_cleanup = multifd_zlib_send_cleanup,
    .send_prepare = multifd_zlib_send_prepare,
    .recv_setup = multifd_zlib_recv_setup,
    .recv_cleanup = multifd_zlib_recv_cleanup,
    .recv = multifd_zlib_recv
};

static void multifd_zlib_register(void)
{
    multifd_register_ops(MULTIFD_COMPRESSION_ZLIB, &multifd_zlib_ops);
}

migration_init(multifd_zlib_register);
