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

void 
raid_clear_ht(struct raid_bdev *raid_bdev) 
{
    ht  *ht = raid_bdev->merge_ht;
	hti hti = ht_iterator(ht);

    for (bool i = ht_next(&hti); i; i = ht_next(&hti)) {
        clear_tree(hti.value);
    }

    ht_destroy(ht);
}

static bool
raid_check_io_boundaries(struct raid_bdev_io *raid_io)
{
    struct spdk_bdev_io			*bdev_io = spdk_bdev_io_from_ctx(raid_io);
	struct raid_bdev			*raid_bdev = raid_io->raid_bdev;
	uint64_t start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
	uint64_t end_strip_idx = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) >>
							raid_bdev->strip_size_shift;
	
	return (start_strip_idx <= end_strip_idx) &&
			(start_strip_idx / (raid_bdev->num_base_bdevs - 1) ==
			end_strip_idx / (raid_bdev->num_base_bdevs - 1));
}

static uint64_t
raid_get_stripe_index(struct raid_bdev_io *raid_io) 
{
    struct spdk_bdev_io *bdev_io;
    struct raid_bdev *raid_bdev;
    uint64_t start_strip_idx;

    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    raid_bdev = raid_io->raid_bdev;
    start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
    
    return start_strip_idx / (raid_bdev->num_base_bdevs - raid_bdev->parity_strip_cnt);
}

// static int
// raid_create_big_write_request(char *stripe_key, struct raid_bdev_io **big_raid_bdev_io)
// {
//     struct spdk_bdev_io *current_request_bdev_io;
//     struct spdk_bdev_io *min_request_bdev_io;
//     struct raid_request_tree *stripe_tree;
//     struct raid_write_request *current_request;
//     struct raid_write_request *min_request ;
//     struct raid_bdev *raid_bdev ;
//     struct spdk_bdev *bdev ;
//     struct iovec *iovs = malloc(sizeof(struct iovec));
//     size_t iovs_size = 0;
//     uint64_t num_blocks = 0;
//     int iovcnt = 0;
    
//     stripe_tree = ht_get(raid_ht, stripe_key);
//     min_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);
//     min_request_bdev_io = spdk_bdev_io_from_ctx(min_request->bdev_io);
//     raid_bdev = min_request->bdev_io->raid_bdev;
//     bdev = &raid_bdev->bdev;


//     RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree)
//     {
//         current_request_bdev_io = spdk_bdev_io_from_ctx(current_request->bdev_io);
//         iovs_size += sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt;
//         iovs = realloc(iovs, iovs_size);
//         for (int i = 0; i < current_request_bdev_io->u.bdev.iovcnt; i++)
//         {
//             num_blocks += current_request_bdev_io->u.bdev.iovs[i].iov_len / bdev->blocklen;
//         }
//         memcpy(iovs + iovcnt, current_request_bdev_io->u.bdev.iovs, sizeof(struct iovec) * current_request_bdev_io->u.bdev.iovcnt);
//         iovcnt += current_request_bdev_io->u.bdev.iovcnt;
//     }

//     min_request_bdev_io->u.bdev.iovs = iovs;
//     min_request_bdev_io->u.bdev.iovcnt = iovcnt;


//     *big_raid_bdev_io = min_request->bdev_io;

//     return 0;

// }

// static int
// raid_merge_request_complete(char *stripe_key, struct raid_bdev_io **big_raid_bdev_io)
// {
//     SPDK_ERRLOG("raid_merge_request_complete\n");
//     struct raid_request_tree *stripe_tree;
//     int rc;

//     stripe_tree = ht_get(raid_ht, stripe_key);
    
//     rc = raid_create_big_write_request(stripe_key, big_raid_bdev_io);
//     if (rc != 0) return RAID_REQUEST_MERGE_STATUS_FAILED;

//     struct raid_write_request *min_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);
//     struct raid_write_request *current_request;

//     RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree) 
//     {
//         if (min_request != current_request) raid_bdev_io_complete(current_request->bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
//     }
//     clear_tree(stripe_tree); 
//     ht_remove(raid_ht, stripe_key);
//     free(stripe_tree);
//     return RAID_REQUEST_MERGE_STATUS_COMPLETE;
// }

// bool
// raid_get_stripe_tree_ready(struct raid_bdev_io *raid_io) 
// {
//     bool* ready_to_merge;
//     char stripe_key[MAX_HT_STRING_LEN];
//     uint64_t stripe_index;

//     stripe_index = raid_get_stripe_index(raid_io);
//     snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);

//     if (raid_status_ht == NULL) raid_status_ht = ht_create(); 

//     ready_to_merge = ht_get(raid_status_ht, stripe_key);
    
//     if (ready_to_merge == NULL) 
//     {
//         ready_to_merge = malloc(sizeof(bool));
//         *ready_to_merge = false;
//         ht_set(raid_status_ht, stripe_key, ready_to_merge);
//     }

//     return *ready_to_merge;
// }

int 
raid_add_request_to_ht(struct raid_bdev_io *raid_io) {
    SPDK_ERRLOG("ADD TO HT\n");
    struct raid_write_request   *write_request;
    struct spdk_bdev_io         *bdev_io;
    struct raid_bdev            *raid_bdev;
    struct raid_request_tree    *stripe_tree;
    char                        stripe_key[MAX_HT_STRING_LEN];
    uint64_t                    stripe_index;
    ht                          *ht;
    int                         ret;

    SPDK_ERRLOG("CHECKING IO BOUNDARIES\n");
    if (!raid_check_io_boundaries(raid_io)) {
        SPDK_ERRLOG("Request is beyond one stripe! Can't write to the tree!\n");
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		assert(false);
		return -EIO;
    }

    bdev_io = spdk_bdev_io_from_ctx(raid_io);
    raid_bdev = raid_io->raid_bdev;
    ht = raid_bdev->merge_ht;

    SPDK_ERRLOG("CHECKING HT\n");
    if (ht == NULL) {
        SPDK_WARNLOG("%s hasn't got hashtable for merging\n", raid_bdev->bdev.name);
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        return -ENODEV;
    }

    stripe_index = raid_get_stripe_index(raid_io);

    write_request = malloc(sizeof(struct raid_write_request));
    SPDK_ERRLOG("CHECKING WRITE REQUEST\n");
    if (write_request == NULL) {
        SPDK_WARNLOG("Allocation of the tree node is failed\n");
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        return -ENOMEM;
    }

    write_request->bdev_io = raid_io;
    write_request->addr = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

    ret = snprintf(stripe_key, sizeof stripe_key, "%lu", stripe_index);
    SPDK_ERRLOG("CHECKING SNPRINTF\n");
    if (ret == 0) {
        SPDK_WARNLOG("Couldn't identify stripe index\n");
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        return -ENOMEM;
    }
    
    stripe_tree = ht_get(ht, stripe_key); 

    SPDK_ERRLOG("CREATING TREE\n");
    if (stripe_tree == NULL) 
    {
        stripe_tree = malloc(sizeof(struct raid_request_tree));

        if (write_request == NULL) {
            SPDK_WARNLOG("Allocation of the tree is failed\n");
            raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
            return -ENOMEM;
        }

        stripe_tree->size = 0;
        RB_INIT(&stripe_tree->tree);
        ht_set(ht, stripe_key, stripe_tree);
    }

    RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
    stripe_tree->size++;
    stripe_tree->last_request_time = spdk_get_ticks() / spdk_get_ticks_hz();

    SPDK_ERRLOG("ADDING IS DONE\n");
    return 0;
}

int
raid_request_merge_poller(void *args)
{
    struct raid_bdev            *raid_bdev;
    struct raid_request_tree    *stripe_tree;
    uint64_t                    current_time;
    uint8_t                     max_tree_size;
    ht                          *ht;
    hti                         hti;

    raid_bdev = args;
    ht = raid_bdev->merge_ht;
    if (ht->length == 0) return 0;
    hti = ht_iterator(ht);
    current_time = spdk_get_ticks() / spdk_get_ticks_hz();
    max_tree_size = raid_bdev->num_base_bdevs - raid_bdev->parity_strip_cnt;
    
    for (bool i = ht_next(&hti); i; i = ht_next(&hti)) {
        stripe_tree = hti.value;
        if (stripe_tree != NULL && (stripe_tree->size == max_tree_size ||
            (current_time - stripe_tree->last_request_time > WAIT_FOR_REQUEST_TIME))) {
            SPDK_ERRLOG("THROWING REQUESTS\n");
            struct raid_write_request *current_request;

            RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree)
            {
                SPDK_ERRLOG("THROW ONE REQUEST\n");
                raid_bdev->module->poller_request(current_request->bdev_io);
            }

            clear_tree(stripe_tree);
            ht_remove(ht, hti.key);
        }
    }

    return 0;
}