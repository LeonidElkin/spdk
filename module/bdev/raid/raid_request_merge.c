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
	struct raid_write_request *previous_request = NULL;

	RB_FOREACH(current_request, raid_addr_tree, &tree->tree) {
		free(previous_request);
		RB_REMOVE(raid_addr_tree, &tree->tree, current_request);
		previous_request = current_request;
	}

	free(previous_request);
	if (tree->merge_request_poller) spdk_poller_unregister(&(tree->merge_request_poller));
	free(tree->stripe_key);
	free(tree);
}

void
raid_clear_ht(struct raid_bdev *raid_bdev)
{
	ht *ht = raid_bdev->merge_info->merge_ht;
	hti hti = ht_iterator(ht);

	for (bool i = ht_next(&hti); i; i = ht_next(&hti)) {
		ht_remove(ht, hti.key);
		if (hti.value) clear_tree(hti.value);
	}

	ht_destroy(ht);
}

static bool
raid_check_io_boundaries(struct raid_bdev_io *raid_io)
{
	struct spdk_bdev_io			*bdev_io = spdk_bdev_io_from_ctx(raid_io);
	struct raid_bdev			*raid_bdev = raid_io->raid_bdev;
	uint64_t					start_strip_idx;
	uint64_t					end_strip_idx;

	start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
	end_strip_idx = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) >>
			raid_bdev->strip_size_shift;

	return (start_strip_idx <= end_strip_idx) &&
	       (start_strip_idx / (raid_bdev->num_base_bdevs - 1) ==
		end_strip_idx / (raid_bdev->num_base_bdevs - 1));
}

static int
raid_get_stripe_key(char *stripe_key, struct raid_bdev_io *raid_io)
{
	struct spdk_bdev_io		*bdev_io;
	struct raid_bdev		*raid_bdev;
	uint64_t				start_strip_idx;
	uint64_t				stripe_index;
	int					 	ret;


	bdev_io = spdk_bdev_io_from_ctx(raid_io);
	raid_bdev = raid_io->raid_bdev;
	start_strip_idx = bdev_io->u.bdev.offset_blocks >> raid_bdev->strip_size_shift;
	stripe_index = start_strip_idx / (raid_bdev->num_base_bdevs - 1);
	ret = snprintf(stripe_key, MAX_HT_STRING_LEN, "%lu", stripe_index);

	return ret;
}

static int
raid_create_big_write_request(struct raid_bdev_io **_new_raid_io, struct raid_request_tree *stripe_tree)
{
	struct spdk_bdev_io 		*current_bdev_io;
	struct spdk_bdev_io 		*min_bdev_io;
	struct raid_write_request 	*current_request;
	struct raid_write_request 	*min_request;
	struct raid_bdev_io 		*new_raid_io;
	struct raid_bdev_io			**merged_requests;
	struct spdk_bdev_io			*new_bdev_io;
	struct iovec 				*new_iovs;
	int 						acc_iovcnt = 0;
	int 						iovcnt = 0;
	uint64_t 					num_blocks = 0;

	min_request = RB_MIN(raid_addr_tree, &stripe_tree->tree);
	min_bdev_io = spdk_bdev_io_from_ctx(min_request->raid_io);

	merged_requests = calloc(stripe_tree->size, sizeof(struct raid_bdev_io *));

	RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree) {
		current_bdev_io = spdk_bdev_io_from_ctx(current_request->raid_io);
		iovcnt += current_bdev_io->u.bdev.iovcnt;
		num_blocks += current_bdev_io->u.bdev.num_blocks;
		merged_requests[acc_iovcnt++] = current_request->raid_io;
	}

	acc_iovcnt = 0;

	new_iovs = calloc(iovcnt, sizeof(struct iovec));

	if (new_iovs == NULL) {
		SPDK_WARNLOG("Couldn't realloc first request!\n");
		return -ENOMEM;
	}

	new_bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct raid_bdev_io));

	if (new_bdev_io == NULL) {
		SPDK_WARNLOG("Couldn't alloc a new request!\n");
		free(new_iovs);
		return -ENOMEM;
	}

	RB_FOREACH(current_request, raid_addr_tree, &stripe_tree->tree) {
		current_bdev_io = spdk_bdev_io_from_ctx(current_request->raid_io);
		for (int i = 0; i < current_bdev_io->u.bdev.iovcnt; ++i) {
			new_iovs[i + acc_iovcnt].iov_base = current_bdev_io->u.bdev.iovs[i].iov_base;
			new_iovs[i + acc_iovcnt].iov_len = current_bdev_io->u.bdev.iovs[i].iov_len;
		}
		acc_iovcnt += current_bdev_io->u.bdev.iovcnt;
	}

	new_bdev_io->u.bdev.iovs = new_iovs;
	new_bdev_io->u.bdev.iovcnt = iovcnt;
	new_bdev_io->u.bdev.num_blocks = num_blocks;
	new_bdev_io->u.bdev.offset_blocks = min_bdev_io->u.bdev.offset_blocks;
	new_bdev_io->type = SPDK_BDEV_IO_TYPE_WRITE;

	new_raid_io = (struct raid_bdev_io *) new_bdev_io->driver_ctx;
	new_raid_io->raid_bdev = min_request->raid_io->raid_bdev;
	new_raid_io->raid_ch = min_request->raid_io->raid_ch;
	new_raid_io->base_bdev_io_remaining = min_request->raid_io->base_bdev_io_remaining;
	new_raid_io->base_bdev_io_status = min_request->raid_io->base_bdev_io_status;
	new_raid_io->base_bdev_io_submitted = min_request->raid_io->base_bdev_io_submitted;

	new_raid_io->merged_requests = merged_requests;
	new_raid_io->merged_request_count = stripe_tree->size;

	*_new_raid_io = new_raid_io;

	return 0;
}

void
raid_other_requests_handler(struct raid_bdev_io *raid_io) 
{
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);

	if (bdev_io->type != SPDK_BDEV_IO_TYPE_WRITE || raid_io->raid_bdev->merge_info == NULL) {
		raid_bdev_io_complete(raid_io, raid_io->base_bdev_io_status);
		return;
	}

	for (int i = 0; i < raid_io->merged_request_count; ++i) {
		raid_bdev_io_complete(raid_io->merged_requests[i], raid_io->base_bdev_io_status);
	}

	free(raid_io->merged_requests);
	free(bdev_io->u.bdev.iovs);

	free(bdev_io);

}

static int
raid_execute_big_request(struct raid_request_tree *stripe_tree)
{
	struct raid_bdev			*raid_bdev;
	struct raid_bdev_io			*new_raid_io = NULL;
	ht							*ht;
	int							ret;

	raid_bdev = stripe_tree->raid_bdev;
	ht = raid_bdev->merge_info->merge_ht;

	ret = raid_create_big_write_request(&new_raid_io, stripe_tree);
	if (ret) {
		SPDK_WARNLOG("Couldn't create a new request!\n"); 
		return ret;
	}

	raid_bdev->module->poller_request(new_raid_io);

	// ht_remove(ht, stripe_tree->stripe_key);
	// clear_tree(stripe_tree);

	return 0;
}

static int
raid_add_request_to_ht(struct raid_bdev_io *raid_io)
{
	struct raid_write_request	*write_request;
	struct spdk_bdev_io		 	*bdev_io;
	struct raid_bdev			*raid_bdev;
	struct raid_request_tree	*stripe_tree;
	char						*stripe_key;
	ht							*ht;
	int						 	ret;
	struct raid_write_request	*old_request;

	bdev_io = spdk_bdev_io_from_ctx(raid_io);
	raid_bdev = raid_io->raid_bdev;

	if (!raid_check_io_boundaries(raid_io)) {
		SPDK_ERRLOG("Request is beyond one stripe! Can't write to the tree!\n");
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		assert(false);
		return -EIO;
	}

	ht = raid_bdev->merge_info->merge_ht;

	if (ht == NULL) {
		SPDK_WARNLOG("%s hasn't got hashtable for merging\n", raid_bdev->bdev.name);
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		return -ENODEV;
	}

	write_request = calloc(1, sizeof(struct raid_write_request));
	if (write_request == NULL) {
		SPDK_WARNLOG("Allocation of the tree node is failed\n");
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		return -ENOMEM;
	}

	write_request->raid_io = raid_io;
	write_request->addr = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

	stripe_key = calloc(MAX_HT_STRING_LEN, sizeof(char));
	if (stripe_key == NULL) {
		free(write_request);
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		return -ENOMEM;
	}

	ret = raid_get_stripe_key(stripe_key, raid_io);
	if (!ret) {
		SPDK_WARNLOG("Couldn't identify stripe index\n");
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		free(write_request);
		free(stripe_key);
		return -ENOMEM;
	}

	SPDK_ERRLOG("STRIPE_KEY: %s\n", stripe_key);

	stripe_tree = ht_get(ht, stripe_key);

	if (stripe_tree == NULL) {
		stripe_tree = calloc(1, sizeof(struct raid_request_tree));

		if (stripe_tree == NULL) {
			SPDK_WARNLOG("Allocation of the tree is failed\n");
			free(write_request);
			free(stripe_key);
			raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
			return -ENOMEM;
		}

		// stripe_tree->merge_request_poller = SPDK_POLLER_REGISTER(raid_request_merge_poller, stripe_tree,
		// 				    POLLER_MERGE_PERIOD_MILLISECONDS);
		stripe_tree->size = 0;
		stripe_tree->raid_bdev = raid_bdev;
		stripe_tree->stripe_key = stripe_key;

		RB_INIT(&stripe_tree->tree);
		ht_set(ht, stripe_key, stripe_tree);

	}


	old_request = RB_FIND(raid_addr_tree, &stripe_tree->tree, write_request);

	if (old_request == NULL) {
		SPDK_ERRLOG("NORMAL\n");
		RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
		stripe_tree->size++;
	} else {
		SPDK_ERRLOG("BRUH\n");
		RB_REMOVE(raid_addr_tree, &stripe_tree->tree, old_request);
		raid_bdev_io_complete(old_request->raid_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		free(old_request);
		RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
	}

	stripe_tree->last_request_time = spdk_get_ticks();

	if (stripe_tree->size == stripe_tree->raid_bdev->merge_info->max_tree_size) {
		SPDK_ERRLOG("MAX_TREE_SIZE!\n");
		ret = raid_execute_big_request(stripe_tree);
		if (ret) {
			assert(false);
			return ret;
		}
	}

	SPDK_ERRLOG("ADDED TO HT!\n");

	return 0;
}

void
raid_submit_rw_request_with_merge(struct raid_bdev_io *raid_io)
{
	struct spdk_bdev_io 	*bdev_io;
	struct raid_bdev		*raid_bdev;
	int 					ret;

	bdev_io = spdk_bdev_io_from_ctx(raid_io);
	raid_bdev = raid_io->raid_bdev;

	if (bdev_io->type != SPDK_BDEV_IO_TYPE_WRITE || raid_bdev->merge_info == NULL) {
		raid_bdev->module->poller_request(raid_io);
	} else {
		ret = raid_add_request_to_ht(raid_io);
		if (ret) {
			assert(false);
			return;
		}
	}
}

int
raid_request_merge_poller(void *args)
{
	struct raid_request_tree	*stripe_tree;
	uint64_t					current_time;
	int							ret;

	stripe_tree = args;
	current_time = spdk_get_ticks();

	if (stripe_tree != NULL && (current_time - stripe_tree->last_request_time > WAIT_FOR_REQUEST_TIME_SECONDS * spdk_get_ticks_hz())) {

		SPDK_ERRLOG("POLLER\n");

		ret = raid_execute_big_request(stripe_tree);

		if (ret) { return ret; }
		
	}

	return 0;
}
