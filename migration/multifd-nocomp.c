/*
 * Multifd RAM migration without compression
 *
 * Copyright (c) 2019-2020 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "system/ramblock.h"
#include "exec/target_page.h"
#include "file.h"
#include "migration-stats.h"
#include "multifd.h"
#include "multifd-colo.h"
#include "options.h"
#include "migration.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "trace.h"
#include "qemu-file.h"
#include "page_cache.h"
#include "xbzrle.h"

/* Knuth multiplicative hash */
#define KNUTH_MULTIPLICATIVE 2654435761ULL
/* Hot-page routing threshold */
#define XBZRLE_HOT_THRESHOLD 2

static MultiFDSendData **channel_send;
static int num_channels;

/*
 * Maps a page address to one of n buckets deterministically.
 * Used to distribute cold pages across the cold channel pool.
 */
static uint32_t gpa_hash(ram_addr_t addr, uint32_t n)
{
    if (n <= 1) {
        return 0;
    }
    return (uint32_t)((addr * KNUTH_MULTIPLICATIVE) % n);
}

/*
 * page_is_hot: check if a page is "hot" based on its 2-bit counter.
 *
 * A page is hot when its saturating counter (updated at bitmap_sync)
 * is >= XBZRLE_HOT_THRESHOLD (default 2). Returns false when XBZRLE
 * is not enabled (counters will be NULL).
 */
static bool page_is_hot(RAMBlock *block, unsigned long page_index)
{
    if (!migrate_xbzrle() || !block->hotness_counters) {
        return false;
    }
    return block->hotness_counters[page_index] >= XBZRLE_HOT_THRESHOLD;
}

/*
 * route_page: determine target channel for a page based on hotness.
 *
 * Hot pages -> channel 0 (dedicated hot channel with large XBZRLE cache).
 * Cold pages -> channels 1..N-1 (distributed via GPA hash).
 *
 * When XBZRLE is not enabled, all pages are "cold" and distributed
 * across all channels for better load balancing.
 */
static int route_page(RAMBlock *block, ram_addr_t offset)
{
    uint32_t nchannels = migrate_multifd_channels();

    if (nchannels <= 1) {
        return 0;
    }

    if (!page_is_hot(block, offset >> TARGET_PAGE_BITS)) {
        /* Cold: distribute across cold pool */
        uint32_t cold_start = 0;
        uint32_t n_cold = nchannels;

        if (migrate_xbzrle()) {
            cold_start = 1;
            n_cold = nchannels - 1;
        }

        if (n_cold <= 1) {
            return (int)cold_start;
        }
        return (int)(cold_start + gpa_hash(offset, n_cold));
    }

    /* Hot page -> dedicated hot channel */
    return 0;
}

/*
 * multifd_xbzrle_state_alloc: allocate per-thread XBZRLE state.
 *
 * Called from send_setup and recv_setup when migrate_xbzrle() is true.
 * cache_size is the share of the global XBZRLE cache assigned to this thread.
 */
static int multifd_xbzrle_state_alloc(MultiFDXBZRLEState *s,
                                      uint64_t cache_size,
                                      uint32_t page_count,
                                      Error **errp)
{
    s->cache = cache_init(cache_size, TARGET_PAGE_SIZE, errp);
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

/*
 * multifd_xbzrle_state_free: release per-thread XBZRLE state.
 */
static void multifd_xbzrle_state_free(MultiFDXBZRLEState *s)
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

void multifd_ram_payload_alloc(MultiFDPages_t *pages)
{
    pages->offset = g_new0(ram_addr_t, multifd_ram_page_count());
}

void multifd_ram_payload_free(MultiFDPages_t *pages)
{
    g_clear_pointer(&pages->offset, g_free);
}

void multifd_ram_save_setup(void)
{
    num_channels = migrate_multifd_channels();
    channel_send = g_new0(MultiFDSendData *, num_channels);
    for (int i = 0; i < num_channels; i++) {
        channel_send[i] = multifd_send_data_alloc();
    }
}

void multifd_ram_save_cleanup(void)
{
    for (int i = 0; i < num_channels; i++) {
        g_clear_pointer(&channel_send[i], multifd_send_data_free);
    }
    g_free(channel_send);
    channel_send = NULL;
    num_channels = 0;
}

static void multifd_set_file_bitmap(MultiFDSendParams *p)
{
    MultiFDPages_t *pages = &p->data->u.ram;

    assert(pages->block);

    for (int i = 0; i < pages->normal_num; i++) {
        ramblock_set_file_bmap_atomic(pages->block, pages->offset[i], true);
    }

    for (int i = pages->normal_num; i < pages->num; i++) {
        ramblock_set_file_bmap_atomic(pages->block, pages->offset[i], false);
    }
}

static int multifd_nocomp_send_setup(MultiFDSendParams *p, Error **errp)
{
    uint32_t page_count = multifd_ram_page_count();

    if (migrate_zero_copy_send()) {
        p->write_flags |= QIO_CHANNEL_WRITE_FLAG_ZERO_COPY;
    }

    if (!migrate_mapped_ram()) {
        /* We need one extra place for the packet header */
        p->iov = g_new0(struct iovec, page_count + 1);
    } else {
        p->iov = g_new0(struct iovec, page_count);
    }

    if (migrate_xbzrle()) {
        uint32_t nchannels = migrate_multifd_channels();
        uint64_t total_cache = migrate_xbzrle_cache_size();
        /*
         * Thread 0 is the hot-page thread and receives a larger share.
         * Remaining threads share the rest equally.
         * With only one channel, it gets the full cache.
         */
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
            g_free(p->iov);
            p->iov = NULL;
            return -1;
        }
    }

    return 0;
}

static void multifd_nocomp_send_cleanup(MultiFDSendParams *p, Error **errp)
{
    multifd_xbzrle_state_free(&p->xbzrle);
    g_free(p->iov);
    p->iov = NULL;
}

static void multifd_ram_prepare_header(MultiFDSendParams *p)
{
    p->iov[0].iov_len = p->packet_len;
    p->iov[0].iov_base = p->packet;
    p->iovs_num++;
}

static void multifd_send_prepare_iovs(MultiFDSendParams *p)
{
    MultiFDPages_t *pages = &p->data->u.ram;
    uint32_t page_size = multifd_ram_page_size();

    for (int i = 0; i < pages->normal_num; i++) {
        p->iov[p->iovs_num].iov_base = pages->block->host + pages->offset[i];
        p->iov[p->iovs_num].iov_len = page_size;
        p->iovs_num++;
    }

    p->next_packet_size = pages->normal_num * page_size;
}

/*
 * XBZRLE encode: encode all normal pages using per-thread cache and
 * pack the results into data_buf.
 *
 * On cache hit: attempt delta encoding via xbzrle_encode_buffer().
 *   - If encoded output is smaller than a full page: mark as delta
 *     (bitmap bit = 1) and copy encoded data to data_buf.
 *   - If encoded output overflows (>= full page): send as full page
 *     and update cache with the new page content.
 * On cache miss: send the full page and insert into cache.
 *
 * Metadata (bitmap + len[]) is stored temporarily in meta_buf and
 * written to the packet's extended area later (after multifd_send_fill_packet
 * zeroes the packet).
 */
static void multifd_send_prepare_iovs_xbzrle(MultiFDSendParams *p)
{
    MultiFDPages_t *pages = &p->data->u.ram;
    uint32_t page_size = multifd_ram_page_size();
    uint32_t page_count = multifd_ram_page_count();
    uint32_t generation = qatomic_read(&mig_stats.dirty_sync_count);
    uint32_t bitmap_size = DIV_ROUND_UP(page_count, 8);
    /* Scratch area: meta_buf bitmaps TARGET_PAGE_SIZE, ample for metadata */
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
                /* Overflow: delta >= full page, send raw */
                len_arr[i] = cpu_to_be32(page_size);
                memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
                data_offset += page_size;
                p->xbzrle.overflows++;
                cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
            }
        } else {
            /* Cache miss: first time on this thread */
            len_arr[i] = cpu_to_be32(page_size);
            memcpy(p->xbzrle.data_buf + data_offset, page_data, page_size);
            data_offset += page_size;
            p->xbzrle.cache_misses++;
            cache_insert(p->xbzrle.cache, cache_addr, page_data, generation);
        }
    }

    p->next_packet_size = data_offset;

    /*
     * iov[0] is already set to the packet header by
     * multifd_ram_prepare_header(). Add iov[1] for the
     * compacted data payload.
     */
    if (data_offset > 0) {
        p->iov[p->iovs_num].iov_base = p->xbzrle.data_buf;
        p->iov[p->iovs_num].iov_len = data_offset;
        p->iovs_num++;
    }
}

/*
 * Write the XBZRLE extended metadata (bitmap + len[]) into the packet's
 * extended header area. Must be called after multifd_send_fill_packet()
 * because that function zeroes the entire packet buffer including the
 * extended area.
 *
 * Also sets unused32[0] to the total compressed data size so the receiver
 * knows how many bytes to read for the data payload.
 */
static void multifd_send_write_xbzrle_ext(MultiFDSendParams *p)
{
    MultiFDPacket_t *packet = p->packet;
    uint32_t page_count = multifd_ram_page_count();
    uint32_t bitmap_size = DIV_ROUND_UP(page_count, 8);

    /* Extended area sits right after the offset[] array */
    uint8_t *bitmap_dst = (uint8_t *)p->packet + sizeof(MultiFDPacket_t)
                         + sizeof(uint64_t) * page_count;
    uint32_t *len_dst = (uint32_t *)(bitmap_dst + bitmap_size);

    memcpy(bitmap_dst, p->xbzrle.meta_buf, bitmap_size);
    memcpy(len_dst, p->xbzrle.meta_buf + bitmap_size,
           page_count * sizeof(uint32_t));

    packet->unused32[0] = cpu_to_be32(p->next_packet_size);
}

static int multifd_nocomp_send_prepare(MultiFDSendParams *p, Error **errp)
{
    bool use_zero_copy_send = migrate_zero_copy_send();
    bool use_xbzrle = migrate_xbzrle() && p->xbzrle.cache;
    MultiFDPages_t *pages = &p->data->u.ram;
    int ret;

    multifd_send_zero_page_detect(p);

    if (migrate_mapped_ram()) {
        multifd_send_prepare_iovs(p);
        multifd_set_file_bitmap(p);

        return 0;
    }

    if (!use_zero_copy_send) {
        /*
         * Only !zerocopy needs the header in IOV; zerocopy will
         * send it separately.
         */
        multifd_ram_prepare_header(p);
    }

    if (use_xbzrle && pages->normal_num > 0) {
        multifd_send_prepare_iovs_xbzrle(p);
        p->flags |= MULTIFD_FLAG_NOCOMP | MULTIFD_FLAG_XBZRLE;
    } else {
        multifd_send_prepare_iovs(p);
        p->flags |= MULTIFD_FLAG_NOCOMP;
    }

    multifd_send_fill_packet(p);

    if (p->flags & MULTIFD_FLAG_XBZRLE) {
        /*
         * fill_packet zeroes the entire packet buffer, so extended
         * metadata must be written after it.
         */
        multifd_send_write_xbzrle_ext(p);
    }

    if (use_zero_copy_send) {
        /* Send header first, without zerocopy */
        ret = qio_channel_write_all(p->c, (void *)p->packet,
                                    p->packet_len, errp);
        if (ret != 0) {
            return -1;
        }

        qatomic_add(&mig_stats.multifd_bytes, p->packet_len);
    }

    return 0;
}

static int multifd_nocomp_recv_setup(MultiFDRecvParams *p, Error **errp)
{
    uint32_t page_count = multifd_ram_page_count();

    p->iov = g_new0(struct iovec, page_count);

    if (migrate_xbzrle()) {
        uint32_t nchannels = migrate_multifd_channels();
        uint64_t total_cache = migrate_xbzrle_cache_size();
        uint64_t cache_size;

        /* Mirror the same cache split as the sender. */
        if (nchannels <= 1) {
            cache_size = total_cache;
        } else if (p->id == 0) {
            cache_size = total_cache / 2;
        } else {
            cache_size = (total_cache / 2) / (nchannels - 1);
        }
        if (multifd_xbzrle_state_alloc(&p->xbzrle, cache_size,
                                       page_count, errp)) {
            g_free(p->iov);
            p->iov = NULL;
            return -1;
        }
    }

    return 0;
}

static void multifd_nocomp_recv_cleanup(MultiFDRecvParams *p)
{
    multifd_xbzrle_state_free(&p->xbzrle);
    g_free(p->iov);
    p->iov = NULL;
}

static int multifd_nocomp_recv(MultiFDRecvParams *p, Error **errp)
{
    uint32_t flags;

    if (migrate_mapped_ram()) {
        return multifd_file_recv_data(p, errp);
    }

    flags = p->flags & MULTIFD_FLAG_COMPRESSION_MASK;

    if (flags != MULTIFD_FLAG_NOCOMP) {
        error_setg(errp, "multifd %u: flags received %x flags expected %x",
                   p->id, flags, MULTIFD_FLAG_NOCOMP);
        return -1;
    }

    multifd_recv_zero_page_process(p);

    if (!p->normal_num) {
        return 0;
    }

    for (int i = 0; i < p->normal_num; i++) {
        p->iov[i].iov_base = p->host + p->normal[i];
        p->iov[i].iov_len = multifd_ram_page_size();
        ramblock_recv_bitmap_set_offset(p->block, p->normal[i]);
    }
    return qio_channel_readv_all(p->c, p->iov, p->normal_num, errp);
}

static void multifd_pages_reset(MultiFDPages_t *pages)
{
    /*
     * We don't need to touch offset[] array, because it will be
     * overwritten later when reused.
     */
    pages->num = 0;
    pages->normal_num = 0;
    pages->block = NULL;
}

void multifd_ram_fill_packet(MultiFDSendParams *p)
{
    MultiFDPacket_t *packet = p->packet;
    MultiFDPages_t *pages = &p->data->u.ram;
    uint32_t zero_num = pages->num - pages->normal_num;

    packet->pages_alloc = cpu_to_be32(multifd_ram_page_count());
    packet->normal_pages = cpu_to_be32(pages->normal_num);
    packet->zero_pages = cpu_to_be32(zero_num);

    if (pages->block) {
        pstrcpy(packet->ramblock, sizeof(packet->ramblock),
                pages->block->idstr);
    }

    for (int i = 0; i < pages->num; i++) {
        /* there are architectures where ram_addr_t is 32 bit */
        uint64_t temp = pages->offset[i];

        packet->offset[i] = cpu_to_be64(temp);
    }

    trace_multifd_send_ram_fill(p->id, pages->normal_num,
                                zero_num);
}

int multifd_ram_unfill_packet(MultiFDRecvParams *p, Error **errp)
{
    MultiFDPacket_t *packet = p->packet;
    uint32_t page_count = multifd_ram_page_count();
    uint32_t page_size = multifd_ram_page_size();
    uint32_t pages_per_packet = be32_to_cpu(packet->pages_alloc);
    int i;

    if (pages_per_packet > page_count) {
        error_setg(errp, "multifd: received packet with %u pages, expected %u",
                   pages_per_packet, page_count);
        return -1;
    }

    p->normal_num = be32_to_cpu(packet->normal_pages);
    if (p->normal_num > pages_per_packet) {
        error_setg(errp, "multifd: received packet with %u non-zero pages, "
                   "which exceeds maximum expected pages %u",
                   p->normal_num, pages_per_packet);
        return -1;
    }

    p->zero_num = be32_to_cpu(packet->zero_pages);
    if (p->zero_num > pages_per_packet - p->normal_num) {
        error_setg(errp,
                   "multifd: received packet with %u zero pages, expected maximum %u",
                   p->zero_num, pages_per_packet - p->normal_num);
        return -1;
    }

    if (p->normal_num == 0 && p->zero_num == 0) {
        return 0;
    }

    /* make sure that ramblock is 0 terminated */
    packet->ramblock[255] = 0;
    p->block = qemu_ram_block_by_name(packet->ramblock);
    if (!p->block) {
        error_setg(errp, "multifd: unknown ram block %s",
                   packet->ramblock);
        return -1;
    }

    for (i = 0; i < p->normal_num; i++) {
        uint64_t offset = be64_to_cpu(packet->offset[i]);

        if (offset > (p->block->used_length - page_size)) {
            error_setg(errp, "multifd: offset too long %" PRIu64
                       " (max " RAM_ADDR_FMT ")",
                       offset, p->block->used_length);
            return -1;
        }
        p->normal[i] = offset;
    }

    for (i = 0; i < p->zero_num; i++) {
        uint64_t offset = be64_to_cpu(packet->offset[p->normal_num + i]);

        if (offset > (p->block->used_length - page_size)) {
            error_setg(errp, "multifd: offset too long %" PRIu64
                       " (max " RAM_ADDR_FMT ")",
                       offset, p->block->used_length);
            return -1;
        }
        p->zero[i] = offset;
    }

    if (migrate_colo()) {
        multifd_colo_prepare_recv(p);
        assert(p->block->colo_cache);
        p->host = p->block->colo_cache;
    } else {
        p->host = p->block->host;
    }

    return 0;
}

static inline bool multifd_queue_empty(MultiFDPages_t *pages)
{
    return pages->num == 0;
}

static inline bool multifd_queue_full(MultiFDPages_t *pages)
{
    return pages->num == multifd_ram_page_count();
}

static inline void multifd_enqueue(MultiFDPages_t *pages, ram_addr_t offset)
{
    pages->offset[pages->num++] = offset;
}

/* Returns true if enqueue successful, false otherwise */
bool multifd_queue_page(RAMBlock *block, ram_addr_t offset)
{
    int ch = route_page(block, offset);
    MultiFDPages_t *pages = &channel_send[ch]->u.ram;

    if (multifd_payload_empty(channel_send[ch])) {
        multifd_pages_reset(pages);
        multifd_set_payload_type(channel_send[ch], MULTIFD_PAYLOAD_RAM);
    }

    if (multifd_queue_empty(pages)) {
        pages->block = block;
        multifd_enqueue(pages, offset);
    } else {
        /*
         * Flush if block changed or page count is full.
         * Only the target channel is flushed — other channels'
         * accumulators stay intact.
         */
        if (pages->block != block || multifd_queue_full(pages)) {
            if (!multifd_send_channel(&channel_send[ch], ch)) {
                return false;
            }
            /* After swap: channel_send[ch] is now the channel's empty data */
            pages = &channel_send[ch]->u.ram;
            if (multifd_payload_empty(channel_send[ch])) {
                multifd_pages_reset(pages);
                multifd_set_payload_type(channel_send[ch], MULTIFD_PAYLOAD_RAM);
            }
            pages->block = block;
            multifd_enqueue(pages, offset);
        } else {
            multifd_enqueue(pages, offset);
        }
    }

    return true;
}

/*
 * We have two modes for multifd flushes:
 *
 * - Per-section mode: this is the legacy way to flush, it requires one
 *   MULTIFD_FLAG_SYNC message for each RAM_SAVE_FLAG_EOS.
 *
 * - Per-round mode: this is the modern way to flush, it requires one
 *   MULTIFD_FLAG_SYNC message only for each round of RAM scan.  Normally
 *   it's paired with a new RAM_SAVE_FLAG_MULTIFD_FLUSH message in network
 *   based migrations.
 *
 * One thing to mention is mapped-ram always use the modern way to sync.
 */

/* Do we need a per-section multifd flush (legacy way)? */
bool multifd_ram_sync_per_section(void)
{
    if (!migrate_multifd()) {
        return false;
    }

    if (migrate_mapped_ram()) {
        return false;
    }

    return migrate_multifd_flush_after_each_section();
}

/* Do we need a per-round multifd flush (modern way)? */
bool multifd_ram_sync_per_round(void)
{
    if (!migrate_multifd()) {
        return false;
    }

    if (migrate_mapped_ram()) {
        return true;
    }

    return !migrate_multifd_flush_after_each_section();
}

int multifd_ram_flush_and_sync(QEMUFile *f)
{
    MultiFDSyncReq req;
    int ret;

    if (!migrate_multifd() || migration_in_postcopy()) {
        return 0;
    }

    /* Flush all non-empty per-channel accumulators */
    for (int i = 0; i < num_channels; i++) {
        if (!multifd_queue_empty(&channel_send[i]->u.ram)) {
            if (!multifd_send_channel(&channel_send[i], i)) {
                error_report("%s: multifd_send_channel fail", __func__);
                return -1;
            }
        }
    }

    /* File migrations only need to sync with threads */
    req = migrate_mapped_ram() ? MULTIFD_SYNC_LOCAL : MULTIFD_SYNC_ALL;

    ret = multifd_send_sync_main(req);
    if (ret) {
        return ret;
    }

    /* If we don't need to sync with remote at all, nothing else to do */
    if (req == MULTIFD_SYNC_LOCAL) {
        return 0;
    }

    /*
     * Old QEMUs don't understand RAM_SAVE_FLAG_MULTIFD_FLUSH, it relies
     * on RAM_SAVE_FLAG_EOS instead.
     */
    if (migrate_multifd_flush_after_each_section()) {
        return 0;
    }

    qemu_put_be64(f, RAM_SAVE_FLAG_MULTIFD_FLUSH);
    qemu_fflush(f);

    return 0;
}

bool multifd_send_prepare_common(MultiFDSendParams *p)
{
    MultiFDPages_t *pages = &p->data->u.ram;
    multifd_ram_prepare_header(p);
    multifd_send_zero_page_detect(p);

    if (!pages->normal_num) {
        p->next_packet_size = 0;
        return false;
    }

    return true;
}

static const MultiFDMethods multifd_nocomp_ops = {
    .send_setup = multifd_nocomp_send_setup,
    .send_cleanup = multifd_nocomp_send_cleanup,
    .send_prepare = multifd_nocomp_send_prepare,
    .recv_setup = multifd_nocomp_recv_setup,
    .recv_cleanup = multifd_nocomp_recv_cleanup,
    .recv = multifd_nocomp_recv
};

static void multifd_nocomp_register(void)
{
    multifd_register_ops(MULTIFD_COMPRESSION_NONE, &multifd_nocomp_ops);
}

migration_init(multifd_nocomp_register);
