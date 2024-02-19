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
#define PARITY_STRIP 1

#define SPDK_NOTICELOG(...) \
    spdk_log(SPDK_LOG_NOTICE, __FILE__, __LINE__, __func__, __VA_ARGS__)

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

struct raid_request_tree {
    RB_HEAD(raid_addr_tree, raid_write_request) tree;
    uint64_t size;
};

int raid_request_catch(struct raid_bdev_io *raid_io);
void raid_merge_request_abort(struct raid_bdev_io *raid_io);

#endif /* SPDK_BDEV_RAID_MERGE_REQUESTS_INTERNAL_H*/
