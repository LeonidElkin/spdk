/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2019 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_BDEV_RAID_MERGE_REQUESTS_INTERNAL_H
#define SPDK_BDEV_RAID_MERGE_REQUESTS_INTERNAL_H

#include "bdev_raid.h"

#include "spdk/tree.h"
#include "spdk/log.h"
#include "spdk/bdev.h"
#include "spdk/bdev_module.h"
#include "ht.h"

#define MAX_HT_STRING_LEN 35
#define PARITY_STRIP 0

enum raid_request_merge_status {
    RAID_REQUEST_MERGE_STATUS_COMPLETE = 0,
    RAID_REQUEST_MERGE_STATUS_WAITING_FOR_REQUESTS = 1,
    RAID_REQUEST_MERGE_STATUS_FAILED = -1,
};

struct raid_write_request {
    uint32_t addr;
    RB_ENTRY(raid_write_request) link;
    struct raid_bdev_io *bdev_io;
};

struct raid_bdev_merged_request {
    struct raid_base_bdev_info	*base_info;
    struct spdk_io_channel		*base_ch;
    uint64_t pd_lba;
	uint64_t pd_blocks;
    struct spdk_bdev_ext_io_opts io_opts;
};

struct raid_request_tree {
    RB_HEAD(raid_addr_tree, raid_write_request) tree;
    uint64_t size;
};

int raid_request_catch(struct raid_bdev_io *raid_io, struct raid_bdev_io **big_raid_io);
void raid_merge_request_abort(struct raid_bdev_io *raid_io);

#endif /* SPDK_BDEV_RAID_MERGE_REQUESTS_INTERNAL_H*/
