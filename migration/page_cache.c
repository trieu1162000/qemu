/*
 * Page cache for QEMU
 * The cache is base on a hash of the page address
 *
 * Copyright 2012 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Orit Wasserman  <owasserm@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "qapi/qmp/qerror.h"
#include "qapi/error.h"
#include "qemu/host-utils.h"
#include "page_cache.h"
#include "trace.h"

/* the page in cache will not be replaced in two cycles */
#define CACHED_PAGE_LIFETIME 1

#define CACHE_WAYS 4

typedef struct CacheItem CacheItem;

struct CacheItem {
    uint64_t it_addr;
    uint64_t it_age;
    uint8_t *it_data;
};

struct PageCache {
    CacheItem *page_cache; /* flat array: num_sets * num_ways */
    size_t page_size;
    size_t max_num_items; /* number of sets */
    size_t num_items;     /* number of allocated slots */
    size_t num_ways;      /* associativity */
    size_t total_entries; /* num_sets * num_ways */
};

PageCache *cache_init(uint64_t new_size, size_t page_size, Error **errp)
{
    int64_t i;
    size_t num_pages = new_size / page_size; /* requested number of entries */
    PageCache *cache;

    if (new_size < page_size) {
        error_setg(errp, "cache size is smaller than target page size");
        return NULL;
    }

    if (num_pages < CACHE_WAYS) {
        error_setg(errp, "cache size too small for %d-way cache", CACHE_WAYS);
        return NULL;
    }

    /* round down to the nearest power of 2 */
    num_pages = pow2floor(num_pages);
    /* ensure total entries divisible by associativity */
    while ((num_pages % CACHE_WAYS) != 0) {
        num_pages >>= 1;
        if (num_pages == 0) {
            error_setg(errp, "cache size too small after adjustment");
            return NULL;
        }
    }

    /* We prefer not to abort if there is no memory */
    cache = g_try_malloc(sizeof(*cache));
    if (!cache) {
        error_setg(errp, "Failed to allocate cache");
        return NULL;
    }
    cache->page_size = page_size;
    cache->num_items = 0;
    cache->num_ways = CACHE_WAYS;
    cache->total_entries = num_pages; /* total entries across all sets */
    cache->max_num_items = num_pages / cache->num_ways; /* number of sets */

    trace_migration_pagecache_init(cache->max_num_items);

    /* We prefer not to abort if there is no memory */
    cache->page_cache = g_try_malloc((cache->total_entries) *
                                     sizeof(*cache->page_cache));
    if (!cache->page_cache) {
        error_setg(errp, "Failed to allocate page cache");
        g_free(cache);
        return NULL;
    }

    for (i = 0; i < (int64_t)cache->total_entries; i++) {
        cache->page_cache[i].it_data = NULL;
        cache->page_cache[i].it_age = 0;
        cache->page_cache[i].it_addr = -1;
    }

    return cache;
}

int cache_prealloc(PageCache *cache)
{
    for (size_t i = 0; i < cache->total_entries; i++) {
        if (!cache->page_cache[i].it_data) {
            cache->page_cache[i].it_data = g_try_malloc(cache->page_size);
            if (!cache->page_cache[i].it_data) {
                return -1;
            }
            cache->num_items++;
        }
    }
    return 0;
}

void cache_fini(PageCache *cache)
{
    int64_t i;

    g_assert(cache);
    g_assert(cache->page_cache);

    for (i = 0; i < (int64_t)cache->total_entries; i++) {
        g_free(cache->page_cache[i].it_data);
    }

    g_free(cache->page_cache);
    cache->page_cache = NULL;
    g_free(cache);
}

static size_t cache_get_cache_pos(const PageCache *cache,
                                  uint64_t address)
{
    g_assert(cache->max_num_items);

    /* Use a multiplicative hash of the page number to reduce direct-mapped
     * collisions. Then map to set index. */
    uint64_t page_number = address / cache->page_size;
    const uint64_t KNUTH_MULT = 2654435761ULL; /* Knuth multiplicative constant */
    uint64_t hash = page_number * KNUTH_MULT;
    return (size_t)(hash & (cache->max_num_items - 1));
}

/* Public wrapper matching header declaration for diagnostics */
size_t page_cache_get_pos(const PageCache *cache, uint64_t addr)
{
    return cache_get_cache_pos(cache, addr);
}

static int cache_find_slot(const PageCache *cache, uint64_t addr)
{
    size_t set = cache_get_cache_pos(cache, addr);
    size_t base = set * cache->num_ways;

    for (size_t w = 0; w < cache->num_ways; w++) {
        if (cache->page_cache[base + w].it_addr == addr) {
            return (int)(base + w);
        }
    }
    return -1;
}

static CacheItem *cache_get_by_addr(const PageCache *cache, uint64_t addr)
{
    int idx = cache_find_slot(cache, addr);
    if (idx >= 0) {
        return &cache->page_cache[idx];
    }
    /* Return first way in the set as a hint for insertion */
    size_t set = cache_get_cache_pos(cache, addr);
    return &cache->page_cache[set * cache->num_ways];
}

uint8_t *get_cached_data(const PageCache *cache, uint64_t addr)
{
    int idx = cache_find_slot(cache, addr);
    if (idx >= 0) {
        return cache->page_cache[idx].it_data;
    }
    return NULL;
}

bool cache_is_cached(const PageCache *cache, uint64_t addr,
                     uint64_t current_age)
{
    int idx = cache_find_slot(cache, addr);
    size_t set = cache_get_cache_pos(cache, addr);

    if (idx >= 0) {
        CacheItem *it = &cache->page_cache[idx];
        /* update the it_age when the cache hit */
        it->it_age = current_age;
        size_t way = (size_t)(idx - set * cache->num_ways);
        fprintf(stderr, "DBG PAGECACHE HIT addr=0x%lx age=%lu pos=%zu way=%zu\n",
                (unsigned long)addr, (unsigned long)current_age, set, way);
        return true;
    }

    /* For MISS logging show first slot stored_addr as an indication */
    CacheItem *first = &cache->page_cache[set * cache->num_ways];
    fprintf(stderr, "DBG PAGECACHE MISS addr=0x%lx age=%lu pos=%zu stored_addr=0x%lx\n",
            (unsigned long)addr, (unsigned long)current_age, set,
            (unsigned long)first->it_addr);
    return false;
}

int cache_insert(PageCache *cache, uint64_t addr, const uint8_t *pdata,
                 uint64_t current_age)
{
    size_t set = cache_get_cache_pos(cache, addr);
    size_t base = set * cache->num_ways;

    /* If already present, update in-place */
    for (size_t w = 0; w < cache->num_ways; w++) {
        CacheItem *it = &cache->page_cache[base + w];
        if (it->it_addr == addr) {
            if (!it->it_data) {
                it->it_data = g_try_malloc(cache->page_size);
                if (!it->it_data) {
                    trace_migration_pagecache_insert();
                    fprintf(stderr, "DBG PAGECACHE ALLOC_FAIL addr=0x%lx pos=%zu way=%zu\n",
                            (unsigned long)addr, set, w);
                    return -1;
                }
                cache->num_items++;
                fprintf(stderr, "DBG PAGECACHE ALLOC addr=0x%lx pos=%zu way=%zu\n",
                        (unsigned long)addr, set, w);
            }
            memcpy(it->it_data, pdata, cache->page_size);
            it->it_age = current_age;
            it->it_addr = addr;
            fprintf(stderr, "DBG PAGECACHE INSERT addr=0x%lx pos=%zu way=%zu age=%lu\n",
                    (unsigned long)addr, set, w, (unsigned long)current_age);
            return 0;
        }
    }

    /* Find empty slot */
    for (size_t w = 0; w < cache->num_ways; w++) {
        CacheItem *it = &cache->page_cache[base + w];
        if (!it->it_data || it->it_addr == (uint64_t)-1) {
            if (!it->it_data) {
                it->it_data = g_try_malloc(cache->page_size);
                if (!it->it_data) {
                    trace_migration_pagecache_insert();
                    fprintf(stderr, "DBG PAGECACHE ALLOC_FAIL addr=0x%lx pos=%zu way=%zu\n",
                            (unsigned long)addr, set, w);
                    return -1;
                }
                cache->num_items++;
                fprintf(stderr, "DBG PAGECACHE ALLOC addr=0x%lx pos=%zu way=%zu\n",
                        (unsigned long)addr, set, w);
            }
            memcpy(it->it_data, pdata, cache->page_size);
            it->it_age = current_age;
            it->it_addr = addr;
            fprintf(stderr, "DBG PAGECACHE INSERT addr=0x%lx pos=%zu way=%zu age=%lu\n",
                    (unsigned long)addr, set, w, (unsigned long)current_age);
            return 0;
        }
    }

    /* All slots occupied: pick oldest entry to replace unless all are fresh */
    size_t victim = 0;
    uint64_t min_age = (uint64_t)-1;
    bool any_replaceable = false;
    for (size_t w = 0; w < cache->num_ways; w++) {
        CacheItem *it = &cache->page_cache[base + w];
        if (it->it_age + CACHED_PAGE_LIFETIME <= current_age) {
            any_replaceable = true;
            if (it->it_age < min_age) {
                min_age = it->it_age;
                victim = w;
            }
        }
    }
    if (!any_replaceable) {
        /* Do not replace very recent entries */
        CacheItem *it = &cache->page_cache[base];
        fprintf(stderr, "DBG PAGECACHE SKIP_REPLACE addr=0x%lx pos=%zu stored_addr=0x%lx stored_age=%lu cur_age=%lu\n",
                (unsigned long)addr, set, (unsigned long)it->it_addr,
                (unsigned long)it->it_age, (unsigned long)current_age);
        return -1;
    }

    /* Replace victim */
    CacheItem *vit = &cache->page_cache[base + victim];
    memcpy(vit->it_data, pdata, cache->page_size);
    vit->it_age = current_age;
    vit->it_addr = addr;
    fprintf(stderr, "DBG PAGECACHE INSERT addr=0x%lx pos=%zu way=%zu age=%lu (replaced)\n",
            (unsigned long)addr, set, victim, (unsigned long)current_age);

    return 0;
}
