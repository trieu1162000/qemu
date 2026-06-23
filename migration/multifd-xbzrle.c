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
    s->num_cache_entries = (uint32_t)num_pages;
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
    fprintf(stderr, "DBG ENCODE p=%d normal_num=%u\n", p->id, p->data->u.ram.normal_num);
    MultiFDPages_t *pages = &p->data->u.ram;
    uint32_t page_size = multifd_ram_page_size();
    uint32_t page_count = multifd_ram_page_count();
    uint32_t generation = qatomic_read(&mig_stats.dirty_sync_count);
    /* Record sender's generation into per-channel state so ext_write can
     * export it to the receiver for identical aging decisions. */
    p->xbzrle.generation = generation;
    uint32_t bitmap_size = DIV_ROUND_UP(page_count, 8);
    uint8_t *bitmap = p->xbzrle.meta_buf;
    uint32_t *len_arr = (uint32_t *)(bitmap + bitmap_size);
    uint32_t data_offset = 0;

    memset(bitmap, 0, bitmap_size);

    uint32_t enc_attempts = 0;
    uint32_t enc_success = 0;
    uint64_t enc_sum = 0;

    for (int i = 0; i < pages->normal_num; i++) {
        uint8_t *page_data = pages->block->host + pages->offset[i];
        uint64_t cache_addr = pages->block->offset + pages->offset[i];
        size_t cache_pos = page_cache_get_pos(p->xbzrle.cache, cache_addr);

        fprintf(stderr, "DBG XBZRLE_CHECK p=%d idx=%d cache_addr=0x%lx gen=%u pos=%zu\n",
                p->id, i, (unsigned long)cache_addr, generation, cache_pos);

        if (cache_is_cached(p->xbzrle.cache, cache_addr, generation)) {
            uint8_t *old_data = get_cached_data(p->xbzrle.cache, cache_addr);
            enc_attempts++;
            int encoded_len = xbzrle_encode_buffer(
                old_data, page_data, page_size,
                p->xbzrle.encoded_buf, page_size);

            if (encoded_len >= 0 && (uint32_t)encoded_len < page_size) {
                /* Delta encoding viable */
                enc_success++;
                enc_sum += (uint32_t)encoded_len;
                bitmap[i / 8] |= (1 << (i % 8));
                len_arr[i] = cpu_to_be32((uint32_t)encoded_len);
                memcpy(p->xbzrle.data_buf + data_offset,
                       p->xbzrle.encoded_buf, encoded_len);
                data_offset += encoded_len;
                p->xbzrle.cache_hits++;
                fprintf(stderr, "DBG XBZRLE_PAGE p=%d idx=%d cache_addr=0x%lx action=DELTA len=%d data_offset=%u\n",
                        p->id, i, (unsigned long)cache_addr, encoded_len, data_offset);
            } else {
                /* Overflow: send full page */
                len_arr[i] = cpu_to_be32(page_size);
                memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
                data_offset += page_size;
                p->xbzrle.overflows++;
                cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
                fprintf(stderr, "DBG XBZRLE_PAGE p=%d idx=%d cache_addr=0x%lx action=OVERFLOW len=%u data_offset=%u\n",
                        p->id, i, (unsigned long)cache_addr, page_size, data_offset);
            }
        } else {
            /* Cache miss */
            len_arr[i] = cpu_to_be32(page_size);
            memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
            data_offset += page_size;
            p->xbzrle.cache_misses++;
            cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
            fprintf(stderr, "DBG XBZRLE_PAGE p=%d idx=%d cache_addr=0x%lx action=MISS len=%u data_offset=%u\n",
                    p->id, i, (unsigned long)cache_addr, page_size, data_offset);
        }
    }

    p->next_packet_size = data_offset;
    fprintf(stderr, "DBG XBZRLE p=%d pages=%u hits=%lu misses=%lu overflows=%lu data_size=%u\n",
        p->id, p->data->u.ram.normal_num, p->xbzrle.cache_hits,
        p->xbzrle.cache_misses, p->xbzrle.overflows, p->next_packet_size);

    /* Per-packet encode stats: attempts, successes, average encoded len */
    if (enc_attempts > 0) {
        uint32_t avg = (uint32_t)(enc_sum / enc_attempts);
        fprintf(stderr, "DBG XBZRLE_ENCODE_STATS p=%d attempts=%u successes=%u avg_len=%u\n",
                p->id, enc_attempts, enc_success, avg);
    } else {
        fprintf(stderr, "DBG XBZRLE_ENCODE_STATS p=%d attempts=0 successes=0 avg_len=0\n", p->id);
    }
}

int multifd_xbzrle_decode_pages(MultiFDRecvParams *p, Error **errp)
{
    uint32_t page_size = multifd_ram_page_size();
    uint32_t page_count = multifd_ram_page_count();
    /* Use sender-provided generation from packet to ensure both sides use
     * the identical bitmap generation for cache aging decisions. */
    uint32_t generation = (uint32_t)be64_to_cpu(p->packet->unused64[0]);
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
            fprintf(stderr, "DBG XBZRLE_DECODE p=%d idx=%d cache_addr=0x%lx type=DELTA len=%u data_offset=%u\n",
                    p->id, i, (unsigned long)cache_addr, page_len, data_offset);
            /*
             * We don't cache_insert here since the old base entry stays in
             * cache (age refreshed by cache_is_cached), mirroring the
             * sender's behaviour on a delta hit.
             */
        } else {
            /* Full page: Cache miss or overflow on sender */
            memcpy(dst, p->xbzrle.data_buf + data_offset, page_size);
            cache_insert(p->xbzrle.cache, cache_addr, dst, generation);
            fprintf(stderr, "DBG XBZRLE_DECODE p=%d idx=%d cache_addr=0x%lx type=FULL len=%u data_offset=%u\n",
                    p->id, i, (unsigned long)cache_addr, page_len, data_offset);
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

    /* Export packet payload size and sender's generation so receiver can
     * use identical generation for cache aging. */
    packet->unused32[0] = cpu_to_be32(p->next_packet_size);
    packet->unused64[0] = cpu_to_be64((uint64_t)p->xbzrle.generation);
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
