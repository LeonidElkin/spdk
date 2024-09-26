/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2019 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "bdev_raid.h"

#include "spdk/tree.h"
#include "spdk/log.h"
#include "spdk/bdev.h"
#include "spdk/bdev_module.h"
#include "bdev_internal.h"

#include "raid_request_merge.h"
#include "ht.h"

static int
addr_cmp(struct raid_write_request *c1, struct raid_write_request *c2)
{
    return (c1->addr < c2->addr ? -1 : c1->addr > c2->addr);
}

RB_GENERATE_STATIC(raid_addr_tree, raid_write_request, link, addr_cmp);

ht *raid_ht = NULL;

static void
clear_tree(struct raid_request_tree *tree)
{
    struct raid_write_request *current_request;

    RB_FOREACH(current_request, raid_addr_tree, &tree->tree)
    {
        RB_REMOVE(raid_addr_tree, &tree->tree, current_request);
    }
    tree->size = 0;
}

static uint64_t
get_stripe_index(struct raid_bdev_io *raid_io) 
{
    struct spdk_bdev_io *bdev_io;
    struct raid_bdev *raid_bdev;
    uint64_t start_strip_idx;

    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    raid_bdev = raid_io->raid_bdev;
    start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
    
    return start_strip_idx / (raid_bdev->num_base_bdevs - PARITY_STRIP);
}

static int
raid_create_big_write_request(char *stripe_key, struct raid_bdev_io **big_raid_bdev_io)
{
    struct spdk_bdev_io *current_request_bdev_io;
    struct spdk_bdev_io *min_request_bdev_io;
    struct raid_request_tree *stripe_tree;
    struct raid_write_request *current_request;
    struct raid_write_request *min_request ;
    struct raid_bdev *raid_bdev ;
    struct spdk_bdev *bdev ;
    struct iovec *iovs = malloc(sizeof(struct iovec));
    size_t iovs_size = 0;
    uint64_t num_blocks = 0;
    int iovcnt = 0;
    
    SPDK_ERRLOG("Block 1\n");
    stripe_tree = ht_get(raid_ht, stripe_key);
    min_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);
    min_request_bdev_io = spdk_bdev_io_from_ctx(min_request->bdev_io);
    raid_bdev = min_request->bdev_io->raid_bdev;
    bdev = &raid_bdev->bdev;

    
    SPDK_ERRLOG("Block 4\n");
    RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree)
    {
        current_request_bdev_io = spdk_bdev_io_from_ctx(current_request->bdev_io);
        iovs_size += sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt;
        iovs = realloc(iovs, iovs_size);
        for (int i = 0; i < current_request_bdev_io->u.bdev.iovcnt; i++)
        {
            num_blocks += current_request_bdev_io->u.bdev.iovs[i].iov_len / bdev->blocklen;
        }
        memcpy(iovs + iovcnt, current_request_bdev_io->u.bdev.iovs, sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt);
        iovcnt += current_request_bdev_io->u.bdev.iovcnt;
    }

    SPDK_ERRLOG("Block 5\n");
    min_request_bdev_io->u.bdev.iovs = iovs;
    min_request_bdev_io->u.bdev.iovcnt = iovcnt;

    SPDK_ERRLOG("Block 7\n");

    *big_raid_bdev_io = min_request->bdev_io;

    return 0;

}

static int
raid_merge_request_complete(char *stripe_key, struct raid_bdev_io **big_raid_bdev_io)
{
    struct raid_request_tree *stripe_tree;
    int rc;

    stripe_tree = ht_get(raid_ht, stripe_key);
    
    rc = raid_create_big_write_request(stripe_key, big_raid_bdev_io);
    if (rc != 0) return RAID_REQUEST_MERGE_STATUS_FAILED;

    struct raid_write_request *min_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);
    struct raid_write_request *current_request;

    RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree) 
    {
        if (min_request != current_request) raid_bdev_io_complete(current_request->bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
    }
    clear_tree(stripe_tree); 
    ht_remove(raid_ht, stripe_key);
    free(stripe_tree);
    return RAID_REQUEST_MERGE_STATUS_COMPLETE;
}

void 
get_status(int **raid_request_merge_status, struct raid_bdev_io *raid_io)
{
    struct raid_request_tree *stripe_tree;
    char stripe_key[MAX_HT_STRING_LEN];
    uint64_t stripe_index = get_stripe_index(raid_io);

    snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);

    stripe_tree = ht_get(raid_ht, stripe_key);
    *(raid_request_merge_status) = &(stripe_tree->raid_request_merge_status);
}


int
raid_request_catch(struct raid_bdev_io *raid_io, struct raid_bdev_io **big_raid_bdev_io)
{
    struct raid_write_request *write_request;
    struct spdk_bdev_io *bdev_io;
    struct raid_bdev *raid_bdev;
    struct raid_request_tree *stripe_tree;
    char stripe_key[MAX_HT_STRING_LEN];
    uint64_t stripe_index;
    uint8_t max_tree_size;

    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    raid_bdev = raid_io->raid_bdev;
    stripe_index = get_stripe_index(raid_io);
    max_tree_size = raid_bdev->num_base_bdevs - PARITY_STRIP;

    write_request = malloc(sizeof(struct raid_write_request));
    write_request->bdev_io = raid_io;
    write_request->addr = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

    snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);

    if (raid_ht == NULL) raid_ht = ht_create(); 
    
    stripe_tree = ht_get(raid_ht, stripe_key); 

    if (stripe_tree == NULL) 
    {
        stripe_tree = malloc(sizeof(struct raid_request_tree));
        stripe_tree->size = 0;
        RB_INIT(&stripe_tree->tree);
        ht_set(raid_ht, stripe_key, stripe_tree);
    }

    RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
    stripe_tree->size++;
    stripe_tree->last_request_time = spdk_get_ticks() / spdk_get_ticks_hz();

    if (stripe_tree->size == max_tree_size) {
        stripe_tree->raid_request_merge_status = raid_merge_request_complete(stripe_key, big_raid_bdev_io);
        return stripe_tree->raid_request_merge_status;
    }
    stripe_tree->raid_request_merge_status = RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS;
    return RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS;
}

void 
raid_merge_request_abort(struct raid_bdev_io *raid_io)
{
    struct raid_write_request *current_request;
    struct raid_request_tree *stripe_tree;
    char stripe_key[MAX_HT_STRING_LEN];
    uint64_t stripe_index = get_stripe_index(raid_io);

    snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);

    stripe_tree = ht_get(raid_ht, stripe_key);

    RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree)
    {
        raid_bdev_io_complete(current_request->bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
    }
    clear_tree(stripe_tree);
    ht_remove(raid_ht, stripe_key);
    free(stripe_tree);
}

int 
raid_request_merge_immediately(void* args)
{
    SPDK_ERRLOG("RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS\n");
    struct merged_raid_bdev_io* merged_bdev_io = args;
    struct raid_request_tree *stripe_tree;
    uint64_t current_time;
    uint64_t stripe_index;
    char stripe_key[MAX_HT_STRING_LEN];

    current_time = spdk_get_ticks() / spdk_get_ticks_hz();
    stripe_index = get_stripe_index(merged_bdev_io->raid_io);
    snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);
    stripe_tree = ht_get(raid_ht, stripe_key); 
    if (stripe_tree->raid_request_merge_status != RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS) return 0;
    
    if (stripe_tree->raid_request_merge_status == RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS && 
            current_time - stripe_tree->last_request_time > WAIT_FOR_REQUEST_TIME) 
    {
        stripe_tree->raid_request_merge_status = RAID_REQUEST_MERGE_STATUS_COMPLETING;
        stripe_tree->raid_request_merge_status = raid_merge_request_complete(stripe_key, &(merged_bdev_io->big_raid_io));
    }
    return 0;
}

