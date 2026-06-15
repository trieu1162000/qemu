/*
 * Multifd common functions
 *
 * Copyright (c) 2019-2020 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_MIGRATION_MULTIFD_H
#define QEMU_MIGRATION_MULTIFD_H

#include "exec/target_page.h"
#include "ram.h"
#include "page_cache.h"

typedef struct MultiFDRecvData MultiFDRecvData;
typedef struct MultiFDSendData MultiFDSendData;

/*
 * Per-thread XBZRLE delta compression state.
 *
 * Each multifd send/recv thread owns one of these independently.
 * No locking is required because only the owning thread accesses it.
 *
 * The cache maps page addresses to their previously-sent content.
 * When a dirty page hits in the cache, only the XOR delta (encoded
 * with run-length encoding) is sent instead of the full page.
 */
typedef struct MultiFDXBZRLEState {
    /* Per-thread page history: addr -> previous page content */
    PageCache  *cache;
    /* Scratch buffer for the XOR-RLE encoded output (TARGET_PAGE_SIZE) */
    uint8_t    *encoded_buf;
    /* Scratch buffer for per-packet metadata (bitmap + len[]) */
    uint8_t    *meta_buf;
    /* Buffer for compacted per-page payload (page_count * TARGET_PAGE_SIZE) */
    uint8_t    *data_buf;
    /* Statistics */
    uint64_t    cache_hits;
    uint64_t    cache_misses;
    /* Pages where encoded delta was larger than full page; sent as full */
    uint64_t    overflows;
    /*
     * Actual number of cache entries after pow2floor rounding.
     * Channels with too few entries skip XBZRLE to avoid overhead.
     * Set by multifd_xbzrle_state_alloc().
     */
    uint32_t    num_cache_entries;
    /*
     * Sender's dirty_sync_count when this packet was encoded.
     * Written into packet->unused64[0] by ext_write on the sender,
     * read by multifd_xbzrle_decode_pages on the receiver so both
     * sides use the identical generation for cache aging decisions.
     */
    uint32_t    generation;
} MultiFDXBZRLEState;

/* Minimum cache entries for XBZRLE to be worthwhile.
 * Below this threshold the channel falls back to nocomp to avoid
 * the per-page overhead (cache_is_cached + cache_insert + memcpy)
 * that provides zero benefit with a thrashing cache.
 * 2048 entries ≈ 16 multifd packets (at 4K/page × 128 pages/packet). */
#define XBZRLE_MIN_CACHE_ENTRIES 2048

typedef enum {
    /* No sync request */
    MULTIFD_SYNC_NONE = 0,
    /* Sync locally on the sender threads without pushing messages */
    MULTIFD_SYNC_LOCAL,
    /*
     * Sync not only on the sender threads, but also push MULTIFD_FLAG_SYNC
     * message to the wire for each iochannel (which is for a remote sync).
     *
     * When remote sync is used, need to be paired with a follow up
     * RAM_SAVE_FLAG_EOS / RAM_SAVE_FLAG_MULTIFD_FLUSH message on the main
     * channel.
     */
    MULTIFD_SYNC_ALL,
} MultiFDSyncReq;

bool multifd_send_setup(void);
void multifd_send_shutdown(void);
void multifd_send_channel_created(void);
int multifd_recv_setup(Error **errp);
void multifd_recv_cleanup(void);
void multifd_recv_shutdown(void);
bool multifd_recv_all_channels_created(void);
bool multifd_recv_new_channel(QIOChannel *ioc, Error **errp);
void multifd_recv_sync_main(void);
int multifd_send_sync_main(MultiFDSyncReq req);
bool multifd_queue_page(RAMBlock *block, ram_addr_t offset);
bool multifd_recv(void);
MultiFDRecvData *multifd_get_recv_data(void);

/* Multiple fd's */

#define MULTIFD_MAGIC 0x11223344U
#define MULTIFD_VERSION 1

/* Multifd Compression flags */
#define MULTIFD_FLAG_SYNC (1 << 0)

/* We reserve 5 bits for compression methods */
#define MULTIFD_FLAG_COMPRESSION_MASK (0x1f << 1)
/* we need to be compatible. Before compression value was 0 */
#define MULTIFD_FLAG_NOCOMP (0 << 1)
#define MULTIFD_FLAG_ZLIB (1 << 1)
#define MULTIFD_FLAG_ZSTD (2 << 1)
#define MULTIFD_FLAG_QPL (4 << 1)
#define MULTIFD_FLAG_UADK (8 << 1)
#define MULTIFD_FLAG_QATZIP (16 << 1)

/*
 * If set it means that this packet contains device state
 * (MultiFDPacketDeviceState_t), not RAM data (MultiFDPacket_t).
 */
#define MULTIFD_FLAG_DEVICE_STATE (32 << 1)

/* To indicate the decompressed payload is XBZRLE-delta-encoded. */
#define MULTIFD_FLAG_XBZRLE (64 << 1)

/* This value needs to be a multiple of qemu_target_page_size() */
#define MULTIFD_PACKET_SIZE (512 * 1024)

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
} __attribute__((packed)) MultiFDPacketHdr_t;

typedef struct {
    MultiFDPacketHdr_t hdr;

    /* maximum number of allocated pages */
    uint32_t pages_alloc;
    /* non zero pages */
    uint32_t normal_pages;
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    uint64_t packet_num;
    /* zero pages */
    uint32_t zero_pages;
    uint32_t unused32[1];    /* Reserved for future use */
    uint64_t unused64[3];    /* Reserved for future use */
    char ramblock[256];
    /*
     * This array contains the pointers to:
     *  - normal pages (initial normal_pages entries)
     *  - zero pages (following zero_pages entries)
     */
    uint64_t offset[];
} __attribute__((packed)) MultiFDPacket_t;

typedef struct {
    MultiFDPacketHdr_t hdr;

    char idstr[256];
    uint32_t instance_id;

    /* size of the next packet that contains the actual data */
    uint32_t next_packet_size;
} __attribute__((packed)) MultiFDPacketDeviceState_t;

typedef struct {
    /* number of used pages */
    uint32_t num;
    /* number of normal pages */
    uint32_t normal_num;
    /*
     * Pointer to the ramblock.  NOTE: it's caller's responsibility to make
     * sure the pointer is always valid!
     */
    RAMBlock *block;
    /* offset array of each page, managed by multifd */
    ram_addr_t *offset;
} MultiFDPages_t;

struct MultiFDRecvData {
    void *opaque;
    size_t size;
    /* for preadv */
    off_t file_offset;
};

typedef struct {
    char *idstr;
    uint32_t instance_id;
    char *buf;
    size_t buf_len;
} MultiFDDeviceState_t;

typedef enum {
    MULTIFD_PAYLOAD_NONE,
    MULTIFD_PAYLOAD_RAM,
    MULTIFD_PAYLOAD_DEVICE_STATE,
} MultiFDPayloadType;

typedef struct MultiFDPayload {
    MultiFDPages_t ram;
    MultiFDDeviceState_t device_state;
} MultiFDPayload;

struct MultiFDSendData {
    MultiFDPayloadType type;
    /*
     * Set when these pages were redirected to a non-preferred channel.
     * When true, the channel thread should skip XBZRLE encoding (send
     * full pages) to avoid cache incoherence between sender and receiver.
     */
    bool redirected;
    MultiFDPayload u;
};

static inline bool multifd_payload_empty(MultiFDSendData *data)
{
    return data->type == MULTIFD_PAYLOAD_NONE;
}

static inline bool multifd_payload_device_state(MultiFDSendData *data)
{
    return data->type == MULTIFD_PAYLOAD_DEVICE_STATE;
}

static inline void multifd_set_payload_type(MultiFDSendData *data,
                                            MultiFDPayloadType type)
{
    assert(multifd_payload_empty(data));
    assert(type != MULTIFD_PAYLOAD_NONE);

    data->type = type;
}

typedef struct {
    /* Fields are only written at creating/deletion time */
    /* No lock required for them, they are read only */

    /* channel number */
    uint8_t id;
    /* channel thread name */
    char *name;
    /* channel thread id */
    QemuThread thread;
    bool thread_created;
    QemuThread tls_thread;
    bool tls_thread_created;
    /* communication channel */
    QIOChannel *c;
    /* packet allocated len */
    uint32_t packet_len;
    /* multifd flags for sending ram */
    int write_flags;

    /* sem where to wait for more work */
    QemuSemaphore sem;
    /* syncs main thread and channels */
    QemuSemaphore sem_sync;

    /* multifd flags for each packet */
    uint32_t flags;
    /*
     * The sender thread has work to do if either of below field is set.
     *
     * @pending_job:  a job is pending
     * @pending_sync: a sync request is pending
     *
     * For both of these fields, they're only set by the requesters, and
     * cleared by the multifd sender threads.
     */
    bool pending_job;
    MultiFDSyncReq pending_sync;

    MultiFDSendData *data;

    /* thread local variables. No locking required */

    /* pointers to the possible packet types */
    MultiFDPacket_t *packet;
    MultiFDPacketDeviceState_t *packet_device_state;
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    /* packets sent through this channel */
    uint64_t packets_sent;
    /* buffers to send */
    struct iovec *iov;
    /* number of iovs used */
    uint32_t iovs_num;
    /* used for compression methods */
    void *compress_data;
    /* per-thread XBZRLE delta compression state */
    MultiFDXBZRLEState xbzrle;
}  MultiFDSendParams;

typedef struct {
    /* Fields are only written at creating/deletion time */
    /* No lock required for them, they are read only */

    /* channel number */
    uint8_t id;
    /* channel thread name */
    char *name;
    /* channel thread id */
    QemuThread thread;
    bool thread_created;
    /* communication channel */
    QIOChannel *c;
    /* packet allocated len */
    uint32_t packet_len;

    /* syncs main thread and channels */
    QemuSemaphore sem_sync;
    /* sem where to wait for more work */
    QemuSemaphore sem;

    /* this mutex protects the following parameters */
    QemuMutex mutex;
    /* should this thread finish */
    bool quit;
    /* multifd flags for each packet */
    uint32_t flags;
    /* global number of generated multifd packets */
    uint64_t packet_num;
    int pending_job;
    MultiFDRecvData *data;

    /* thread local variables. No locking required */

    /* pointers to the possible packet types */
    MultiFDPacket_t *packet;
    MultiFDPacketDeviceState_t *packet_dev_state;
    /* size of the next packet that contains pages */
    uint32_t next_packet_size;
    /* packets received through this channel */
    uint64_t packets_recved;
    /* ramblock */
    RAMBlock *block;
    /*
     * Normally, it points to ramblock's host address.  When COLO
     * is enabled, it points to the mirror cache for the ramblock.
     */
    uint8_t *host;
    /* buffers to recv */
    struct iovec *iov;
    /* Pages that are not zero */
    ram_addr_t *normal;
    /* num of non zero pages */
    uint32_t normal_num;
    /* Pages that are zero */
    ram_addr_t *zero;
    /* num of zero pages */
    uint32_t zero_num;
    /* used for de-compression methods */
    void *compress_data;
    /* per-thread XBZRLE delta decompression state */
    MultiFDXBZRLEState xbzrle;
    /* Flags for the QIOChannel */
    int read_flags;
} MultiFDRecvParams;

typedef struct {
    /*
     * The send_setup, send_cleanup, send_prepare are only called on
     * the QEMU instance at the migration source.
     */

    /*
     * Setup for sending side. Called once per channel during channel
     * setup phase.
     *
     * Must allocate p->iov. If packets are in use (default), one
     * extra iovec must be allocated for the packet header. Any memory
     * allocated in this hook must be released at send_cleanup.
     *
     * p->write_flags may be used for passing flags to the QIOChannel.
     *
     * p->compression_data may be used by compression methods to store
     * compression data.
     */
    int (*send_setup)(MultiFDSendParams *p, Error **errp);

    /*
     * Cleanup for sending side. Called once per channel during
     * channel cleanup phase.
     */
    void (*send_cleanup)(MultiFDSendParams *p, Error **errp);

    /*
     * Prepare the send packet. Called as a result of multifd_send()
     * on the client side, with p pointing to the MultiFDSendParams of
     * a channel that is currently idle.
     *
     * Must populate p->iov with the data to be sent, increment
     * p->iovs_num to match the amount of iovecs used and set
     * p->next_packet_size with the amount of data currently present
     * in p->iov.
     *
     * Must indicate whether this is a compression packet by setting
     * p->flags.
     *
     * As a last step, if packets are in use (default), must prepare
     * the packet by calling multifd_send_fill_packet().
     */
    int (*send_prepare)(MultiFDSendParams *p, Error **errp);

    /*
     * The recv_setup, recv_cleanup, recv are only called on the QEMU
     * instance at the migration destination.
     */

    /*
     * Setup for receiving side. Called once per channel during
     * channel setup phase. May be empty.
     *
     * May allocate data structures for the receiving of data. May use
     * p->iov. Compression methods may use p->compress_data.
     */
    int (*recv_setup)(MultiFDRecvParams *p, Error **errp);

    /*
     * Cleanup for receiving side. Called once per channel during
     * channel cleanup phase. May be empty.
     */
    void (*recv_cleanup)(MultiFDRecvParams *p);

    /*
     * Data receive method. Called as a result of multifd_recv() on
     * the client side, with p pointing to the MultiFDRecvParams of a
     * channel that is currently idle. Only called if there is data
     * available to receive.
     *
     * Must validate p->flags according to what was set at
     * send_prepare.
     *
     * Must read the data from the QIOChannel p->c.
     */
    int (*recv)(MultiFDRecvParams *p, Error **errp);
} MultiFDMethods;

void multifd_register_ops(int method, const MultiFDMethods *ops);
void multifd_send_fill_packet(MultiFDSendParams *p);
bool multifd_send_prepare_common(MultiFDSendParams *p);
void multifd_send_zero_page_detect(MultiFDSendParams *p);
void multifd_recv_zero_page_process(MultiFDRecvParams *p);

void multifd_channel_connect(MultiFDSendParams *p, QIOChannel *ioc);
bool multifd_send(MultiFDSendData **send_data);
bool multifd_send_channel(MultiFDSendData **send_data, int ch);
MultiFDSendData *multifd_send_data_alloc(void);
void multifd_send_data_clear(MultiFDSendData *data);
void multifd_send_data_free(MultiFDSendData *data);

static inline uint32_t multifd_ram_page_size(void)
{
    return qemu_target_page_size();
}

static inline uint32_t multifd_ram_page_count(void)
{
    return MULTIFD_PACKET_SIZE / qemu_target_page_size();
}

void multifd_ram_save_setup(void);
void multifd_ram_save_cleanup(void);
int multifd_ram_flush_and_sync(QEMUFile *f);
bool multifd_ram_sync_per_round(void);
bool multifd_ram_sync_per_section(void);
void multifd_ram_payload_alloc(MultiFDPages_t *pages);
void multifd_ram_payload_free(MultiFDPages_t *pages);
void multifd_ram_fill_packet(MultiFDSendParams *p);
int multifd_ram_unfill_packet(MultiFDRecvParams *p, Error **errp);

void multifd_send_data_clear_device_state(MultiFDDeviceState_t *device_state);

void multifd_device_state_send_setup(void);
void multifd_device_state_send_cleanup(void);

void multifd_device_state_send_prepare(MultiFDSendParams *p);

/*
 * XBZRLE shared helpers: usable from any compression ops table
 * (nocomp, zlib, zstd, etc.).
 */
int multifd_xbzrle_state_alloc(MultiFDXBZRLEState *s,
                               uint64_t cache_size,
                               uint32_t page_count,
                               Error **errp);
void multifd_xbzrle_state_free(MultiFDXBZRLEState *s);
void multifd_xbzrle_encode_pages(MultiFDSendParams *p);
int multifd_xbzrle_decode_pages(MultiFDRecvParams *p, Error **errp);
void multifd_xbzrle_ext_write(MultiFDSendParams *p);
void multifd_xbzrle_ext_read(const MultiFDPacket_t *packet,
                             uint32_t page_count,
                             const uint8_t **bitmap,
                             const uint32_t **len_arr);

#endif
