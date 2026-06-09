/*
 * Multifd XBZRLE compression implementation
 *
 * Copyright (c) 2024 Red Hat Inc
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "exec/target_page.h"
#include "system/ramblock.h"
#include "qapi/error.h"
#include "migration.h"
#include "migration-stats.h"
#include "trace.h"
#include "multifd.h"
#include "page_cache.h"
#include "xbzrle.h"

int multifd_xbzrle_state_alloc(MultiFDXBZRLEState *s,
                               uint64_t cache_size,
                               uint32_t page_count,
                               Error **errp)
{
    size_t num_pages = cache_size / TARGET_PAGE_SIZE;

    if (num_pages == 0) {
        error_setg(errp, "multifd xbzrle: cache too small");
        return -1;
    }
    /* cache_init requires num_pages to be a power of two */
    num_pages = pow2floor(num_pages);
    s->cache = cache_init((uint64_t)num_pages * TARGET_PAGE_SIZE,
                          TARGET_PAGE_SIZE, errp);
    if (!s->cache) {
        return -1;
    }
    s->encoded_buf = g_try_malloc(TARGET_PAGE_SIZE);
    if (!s->encoded_buf) {
        error_setg(errp, "multifd xbzrle: failed to allocate encoded_buf");
        goto err_cache;
    }
    s->meta_buf = g_try_malloc(TARGET_PAGE_SIZE);
    if (!s->meta_buf) {
        error_setg(errp, "multifd xbzrle: failed to allocate meta_buf");
        goto err_encoded;
    }
    s->data_buf = g_try_malloc((size_t)page_count * TARGET_PAGE_SIZE);
    if (!s->data_buf) {
        error_setg(errp, "multifd xbzrle: failed to allocate data_buf");
        goto err_meta;
    }
    s->cache_hits   = 0;
    s->cache_misses = 0;
    s->overflows    = 0;
    return 0;

err_meta:
    g_free(s->meta_buf);
    s->meta_buf = NULL;
err_encoded:
    g_free(s->encoded_buf);
    s->encoded_buf = NULL;
err_cache:
    cache_fini(s->cache);
    s->cache = NULL;
    return -1;
}

void multifd_xbzrle_state_free(MultiFDXBZRLEState *s)
{
    g_free(s->data_buf);
    s->data_buf = NULL;
    g_free(s->meta_buf);
    s->meta_buf = NULL;
    g_free(s->encoded_buf);
    s->encoded_buf = NULL;
    if (s->cache) {
        cache_fini(s->cache);
        s->cache = NULL;
    }
}

void multifd_xbzrle_encode_pages(MultiFDSendParams *p)
{
    MultiFDPages_t *pages = &p->data->u.ram;
    uint32_t page_size = multifd_ram_page_size();
    uint32_t page_count = multifd_ram_page_count();
    uint32_t generation = qatomic_read(&mig_stats.dirty_sync_count);
    uint32_t bitmap_size = DIV_ROUND_UP(page_count, 8);
    uint8_t *bitmap = p->xbzrle.meta_buf;
    uint32_t *len_arr = (uint32_t *)(bitmap + bitmap_size);
    uint32_t data_offset = 0;

    memset(bitmap, 0, bitmap_size);

    for (int i = 0; i < pages->normal_num; i++) {
        uint8_t *page_data = pages->block->host + pages->offset[i];
        uint64_t cache_addr = pages->block->offset + pages->offset[i];

        if (cache_is_cached(p->xbzrle.cache, cache_addr, generation)) {
            uint8_t *old_data = get_cached_data(p->xbzrle.cache, cache_addr);
            int encoded_len = xbzrle_encode_buffer(
                old_data, page_data, page_size,
                p->xbzrle.encoded_buf, page_size);

            if (encoded_len >= 0 && (uint32_t)encoded_len < page_size) {
                /* Delta encoding viable */
                bitmap[i / 8] |= (1 << (i % 8));
                len_arr[i] = cpu_to_be32((uint32_t)encoded_len);
                memcpy(p->xbzrle.data_buf + data_offset,
                       p->xbzrle.encoded_buf, encoded_len);
                data_offset += encoded_len;
                p->xbzrle.cache_hits++;
            } else {
                /* Overflow: send full page */
                len_arr[i] = cpu_to_be32(page_size);
                memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
                data_offset += page_size;
                p->xbzrle.overflows++;
                cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
            }
        } else {
            /* Cache miss */
            len_arr[i] = cpu_to_be32(page_size);
            memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
            data_offset += page_size;
            p->xbzrle.cache_misses++;
            cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
        }
    }

    p->next_packet_size = data_offset;
}

int multifd_xbzrle_decode_pages(MultiFDRecvParams *p, Error **errp)
{
    uint32_t page_size = multifd_ram_page_size();
    uint32_t page_count = multifd_ram_page_count();
    uint32_t generation = qatomic_read(&mig_stats.dirty_sync_count);
    const uint8_t *bitmap;
    const uint32_t *len_arr;
    uint32_t data_offset = 0;

    multifd_xbzrle_ext_read(p->packet, page_count, &bitmap, &len_arr);

    for (int i = 0; i < p->normal_num; i++) {
        uint8_t *dst = p->host + p->normal[i];
        uint64_t cache_addr = p->block->offset + p->normal[i];
        uint32_t page_len = be32_to_cpu(len_arr[i]);

        if (bitmap[i / 8] & (1 << (i % 8))) {
            /* Delta-encoded page */
            if (!cache_is_cached(p->xbzrle.cache, cache_addr, generation)) {
                error_setg(errp,
                           "multifd %u: xbzrle cache miss for delta page %d",
                           p->id, i);
                return -1;
            }
            uint8_t *old_data = get_cached_data(p->xbzrle.cache, cache_addr);
            memcpy(dst, old_data, page_size);
            int decoded = xbzrle_decode_buffer(
                p->xbzrle.data_buf + data_offset, page_len,
                dst, page_size);
            if (decoded < 0) {
                error_setg(errp,
                           "multifd %u: xbzrle decode failed for page %d",
                           p->id, i);
                return -1;
            }
            /*
             * We don't cache_insert here since the old base entry stays in
             * cache (age refreshed by cache_is_cached), mirroring the
             * sender's behaviour on a delta hit.
             */
        } else {
            /* Full page: Cache miss or overflow on sender */
            memcpy(dst, p->xbzrle.data_buf + data_offset, page_size);
            cache_insert(p->xbzrle.cache, cache_addr, dst, generation);
        }
        data_offset += page_len;
        ramblock_recv_bitmap_set_offset(p->block, p->normal[i]);
    }

    return 0;
}

void multifd_xbzrle_ext_write(MultiFDSendParams *p)
{
    MultiFDPacket_t *packet = p->packet;
    uint32_t page_count = multifd_ram_page_count();
    uint32_t bitmap_size = DIV_ROUND_UP(page_count, 8);
    uint8_t *bitmap_dst = (uint8_t *)p->packet + sizeof(MultiFDPacket_t)
                         + sizeof(uint64_t) * page_count;
    uint32_t *len_dst = (uint32_t *)(bitmap_dst + bitmap_size);

    memcpy(bitmap_dst, p->xbzrle.meta_buf, bitmap_size);
    memcpy(len_dst, p->xbzrle.meta_buf + bitmap_size,
           page_count * sizeof(uint32_t));

    packet->unused32[0] = cpu_to_be32(p->next_packet_size);
}

void multifd_xbzrle_ext_read(const MultiFDPacket_t *packet,
                             uint32_t page_count,
                             const uint8_t **bitmap,
                             const uint32_t **len_arr)
{
    const uint8_t *ext = (const uint8_t *)packet + sizeof(MultiFDPacket_t)
                         + sizeof(uint64_t) * page_count;
    *bitmap = ext;
    *len_arr = (const uint32_t *)(ext + DIV_ROUND_UP(page_count, 8));
}
