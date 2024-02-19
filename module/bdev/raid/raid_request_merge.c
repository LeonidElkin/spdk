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

static void
tmp_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *ctx)
{
    SPDK_NOTICELOG("Unexpected event type: %d\n", type);
}

static int
raid_create_big_write_request(char *stripe_key, struct raid_bdev_io **big_raid_bdev_io)
{
    struct spdk_bdev_desc *desc;
    struct spdk_bdev_io *bdev_io;
    struct spdk_bdev_io *current_request_bdev_io;
    struct raid_bdev_io *raid_io;
    struct raid_request_tree *stripe_tree;
    struct raid_write_request *current_request;
    struct spdk_io_channel *ch;
    struct spdk_bdev_channel *channel;
    struct raid_bdev *raid_bdev = NULL;
    struct spdk_bdev *bdev = NULL;
    struct iovec *iovs = NULL;
    size_t iovs_size = 0;
    uint64_t num_blocks = 0;
    uint64_t offset_blocks;
    char *bdev_name;
    int iovcnt = 0;
    int rc;
    
    stripe_tree = ht_get(raid_ht, stripe_key);
    current_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);

    current_request_bdev_io = spdk_bdev_io_from_ctx(current_request->bdev_io);
    raid_bdev = current_request->bdev_io->raid_bdev;
    bdev = &raid_bdev->bdev;
    bdev_name = raid_bdev->bdev.name;

    offset_blocks = current_request_bdev_io->u.bdev.offset_blocks;

    rc = spdk_bdev_open_ext(bdev_name, false, tmp_bdev_event_cb, NULL, &desc);

    if (rc != 0)
    {
        SPDK_ERRLOG("Failed to open bdev with name: %s\n", bdev_name);
        return rc;
    }

    ch = spdk_bdev_get_io_channel(desc);
    channel = (struct spdk_bdev_channel *)spdk_io_channel_get_ctx(ch);

    bdev_io = (struct spdk_bdev_io *)bdev_channel_get_io(channel);
    {
        if (!bdev_io)
            return -ENOMEM;
    }

    RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree)
    {
        current_request_bdev_io = spdk_bdev_io_from_ctx(current_request->bdev_io);
        iovs_size += sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt;
        iovs = realloc(iovs, iovs_size);
        for (int i = 0; i < current_request_bdev_io->u.bdev.iovcnt; i++)
        {
            num_blocks += bdev_io->u.bdev.iovs[i].iov_len / bdev->blocklen;
        }
        memcpy(iovs + iovcnt, current_request_bdev_io->u.bdev.iovs, sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt);
        iovcnt += current_request_bdev_io->u.bdev.iovcnt;
    }

    bdev_io->internal.ch = channel;
    bdev_io->internal.desc = desc;
    bdev_io->type = SPDK_BDEV_IO_TYPE_WRITE;
    bdev_io->u.bdev.iovs = iovs;
    bdev_io->u.bdev.iovcnt = iovcnt;
    bdev_io->u.bdev.md_buf = NULL;
    bdev_io->u.bdev.num_blocks = num_blocks;
    bdev_io->u.bdev.offset_blocks = offset_blocks;
    bdev_io->u.bdev.memory_domain = NULL;
    bdev_io->u.bdev.memory_domain_ctx = NULL;
    bdev_io->u.bdev.accel_sequence = NULL;
    bdev_io_init(bdev_io, bdev, spdk_bdev_io_complete, NULL);
    bdev_io_submit(bdev_io);

    raid_io = (struct raid_bdev_io *)bdev_io->driver_ctx;

    raid_io->raid_bdev = bdev_io->bdev->ctxt;
    raid_io->raid_ch = spdk_io_channel_get_ctx(ch);
    raid_io->base_bdev_io_remaining = 0;
    raid_io->base_bdev_io_submitted = 0;
    raid_io->base_bdev_io_status = SPDK_BDEV_IO_STATUS_SUCCESS;

    *big_raid_bdev_io = raid_io;

    return 0;

}

int
raid_request_catch(struct raid_bdev_io *raid_io)
{
    struct raid_write_request *write_request;
    struct spdk_bdev_io *bdev_io;
    struct raid_bdev *raid_bdev;
    struct raid_request_tree *stripe_tree;
    char stripe_key[MAX_HT_STRING_LEN];
    uint64_t stripe_index;
    uint64_t start_strip_idx;
    uint8_t max_tree_size;
    int rc;

    write_request = malloc(sizeof(struct raid_write_request));
    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    raid_bdev = raid_io->raid_bdev;
    max_tree_size = raid_bdev->num_base_bdevs - PARITY_STRIP;

    if (raid_ht == NULL) raid_ht = ht_create();

    start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
    write_request->addr = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;
    stripe_index = start_strip_idx / (raid_bdev->num_base_bdevs - PARITY_STRIP);
    snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);
    stripe_tree = ht_get(raid_ht, stripe_key);

    if (stripe_tree == NULL)
    {
        stripe_tree = malloc(sizeof *stripe_tree);
        stripe_tree->size = 0;
        RB_INIT(&stripe_tree->tree);
        ht_set(raid_ht, stripe_key, stripe_tree);
    }

    RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
    stripe_tree->size++;

    if (stripe_tree->size == max_tree_size) {
        struct raid_bdev_io *big_raid_bdev_io;
        rc = raid_create_big_write_request(stripe_key, &big_raid_bdev_io);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to create big request\n");
            return RAID_REQUEST_MERGE_STATUS_FAILED;
        }
        struct raid_write_request *current_request;
        RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree) {
            raid_bdev_io_complete(current_request->bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
        }
        clear_tree(stripe_tree); 
        ht_remove(raid_ht, stripe_key);
        free(stripe_tree);
        return RAID_REQUEST_MERGE_STATUS_COMPLETE;
    }
    return RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS;
}

void 
raid_merge_request_abort(struct raid_bdev_io *raid_io)
{
    struct raid_write_request *current_request;
    struct raid_request_tree *stripe_tree;
    struct spdk_bdev_io *bdev_io;
    struct raid_bdev *raid_bdev;
    char stripe_key[MAX_HT_STRING_LEN];
    uint64_t stripe_index;
    uint64_t start_strip_idx;

    raid_bdev = raid_io->raid_bdev;
    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
    stripe_index = start_strip_idx / (raid_bdev->num_base_bdevs - PARITY_STRIP);
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
