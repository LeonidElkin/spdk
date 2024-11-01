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
#define WAIT_FOR_REQUEST_TIME 2
#define POLLER_MERGE_PERIOD_MILLISECONDS 500

struct raid_bdev_merge_info {
	ht *merge_ht;
	uint8_t max_tree_size;
};

struct raid_write_request {
	uint32_t addr;
	RB_ENTRY(raid_write_request) link;
	struct raid_bdev_io *raid_io;
};

struct raid_request_tree {
	RB_HEAD(raid_addr_tree, raid_write_request) tree;
	uint64_t size;
	uint64_t last_request_time;
	struct spdk_poller *merge_request_poller;
	struct raid_bdev *raid_bdev;
};


void raid_clear_ht(struct raid_bdev *raid_bdev);
int raid_request_merge_poller(void *args);
void raid_submit_rw_request_with_merge(struct raid_bdev_io *raid_io);
void raid_merge_other_requests_handler(bool success, struct raid_request_tree *stripe_tree);
void raid_remove_min(struct raid_request_tree *stripe_tree);


#endif /* SPDK_BDEV_RAID_MERGE_REQUESTS_INTERNAL_H*/
