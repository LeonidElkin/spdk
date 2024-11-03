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
	spdk_poller_unregister(&(tree->merge_request_poller));
	free(tree->stripe_key);
	free(tree);
}

static void
reset_tree(struct raid_request_tree *tree)
{
	struct raid_write_request *current_request;
	struct raid_write_request *previous_request = NULL;

	RB_FOREACH(current_request, raid_addr_tree, &tree->tree) {
		free(previous_request);
		RB_REMOVE(raid_addr_tree, &tree->tree, current_request);
		previous_request = current_request;
	}

	free(previous_request);
	tree->size = 0;
	tree->is_pollable = true;
}


/**
 * Clear the hash table of raid requests.
 *
 * This function clears the hash table, and then destroys it.
 *
 * @param raid_bdev The raid bdev to operate on.
 */
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

	if (!new_iovs) {
		SPDK_WARNLOG("Couldn't realloc first request!\n");
		return -ENOMEM;
	}

	new_bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct raid_bdev_io));

	if (!new_bdev_io) {
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

/**
 * raid_other_requests_handler - free merged requests and complete them with
 *                               the result of the merged request
 *
 * @raid_io: pointer to the merged request
 *
 * Free the iovecs and the merged requests itself and complete them with the
 * result of the merged request.
 */
void
raid_other_requests_handler(struct raid_bdev_io *raid_io) 
{
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(raid_io);

	if (bdev_io->type != SPDK_BDEV_IO_TYPE_WRITE || !raid_io->raid_bdev->merge_info) {
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
	struct raid_bdev_io			*new_raid_io = NULL;
	int							ret;

	ret = raid_create_big_write_request(&new_raid_io, stripe_tree);
	if (ret) {
		SPDK_WARNLOG("Couldn't create a new request!\n"); 
		return ret;
	}

	stripe_tree->raid_bdev->module->poller_request(new_raid_io);

	reset_tree(stripe_tree);

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

	if (!ht) {
		SPDK_WARNLOG("%s hasn't got hashtable for merging\n", raid_bdev->bdev.name);
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		return -ENODEV;
	}

	write_request = calloc(1, sizeof(struct raid_write_request));
	if (!write_request) {
		SPDK_WARNLOG("Allocation of the tree node is failed\n");
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
		return -ENOMEM;
	}

	write_request->raid_io = raid_io;
	write_request->addr = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

	stripe_key = calloc(MAX_HT_STRING_LEN, sizeof(char));
	if (!stripe_key) {
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

	stripe_tree = ht_get(ht, stripe_key);

	if (!stripe_tree) {
		stripe_tree = calloc(1, sizeof(struct raid_request_tree));

		if (!stripe_tree) {
			SPDK_WARNLOG("Allocation of the tree is failed\n");
			free(write_request);
			free(stripe_key);
			raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
			return -ENOMEM;
		}

		stripe_tree->merge_request_poller = SPDK_POLLER_REGISTER(raid_request_merge_poller, stripe_tree,
						    POLLER_MERGE_PERIOD_MICROSECONDS);
		stripe_tree->size = 0;
		stripe_tree->raid_bdev = raid_bdev;
		stripe_tree->stripe_key = stripe_key;
		stripe_tree->is_pollable = true;

		RB_INIT(&stripe_tree->tree);
		ht_set(ht, stripe_key, stripe_tree);

	} else {
		free(stripe_key);
	}

	stripe_tree->last_request_time = spdk_get_ticks() * WAIT_FOR_REQUEST_TIME_MULTIPLIER / spdk_get_ticks_hz();

	old_request = RB_FIND(raid_addr_tree, &stripe_tree->tree, write_request);

	if (!old_request) {
		RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
		stripe_tree->size++;
	} else {
		RB_REMOVE(raid_addr_tree, &stripe_tree->tree, old_request);
		raid_bdev_io_complete(old_request->raid_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		free(old_request);
		RB_INSERT(raid_addr_tree, &stripe_tree->tree, write_request);
	}

	if (stripe_tree->size == stripe_tree->raid_bdev->merge_info->max_tree_size) {
		stripe_tree->is_pollable = false;
		ret = raid_execute_big_request(stripe_tree);
		if (ret) {
			assert(false);
			return ret;
		}
	}

	return 0;
}

/**
 * Submit a read or write request to the raid bdev module, with support for merging
 * multiple write requests on a per-stripe basis.
 *
 * If the request is a write request, and the raid bdev module has been configured to
 * merge requests, the request is added to the hash table of stripe trees. If the
 * stripe is already in the hash table, the request is merged with any existing
 * requests in the stripe. If the stripe is not in the hash table, a new stripe tree
 * is created and the request is added to it. Once the maximum number of requests
 * in a stripe tree has been reached, the stripe tree is executed and removed from
 * the hash table.
 *
 * @param raid_io Pointer to the raid bdev io to be submitted.
 */
void
raid_submit_rw_request_with_merge(struct raid_bdev_io *raid_io)
{
	struct spdk_bdev_io 	*bdev_io;
	struct raid_bdev		*raid_bdev;
	int 					ret;

	bdev_io = spdk_bdev_io_from_ctx(raid_io);
	raid_bdev = raid_io->raid_bdev;

	if (bdev_io->type != SPDK_BDEV_IO_TYPE_WRITE || !raid_bdev->merge_info) {
		raid_bdev->module->poller_request(raid_io);
	} else {
		ret = raid_add_request_to_ht(raid_io);
		if (ret) {
			assert(false);
			return;
		}
	}
}

/**
 * Poller function to merge requests on a per-stripe basis. Periodically checks
 * if the stripe is pollable and if the time since the last request has exceeded
 * the wait time limit. If so, merge all the requests in the stripe and
 * execute the merged request. Additionally, remove the stripe from the hash
 * table and free the stripe tree after the destroy time limit has been exceeded.
 *
 * @param args Pointer to the stripe tree of the stripe to be processed.
 *
 * @return 0 on success, non-zero on failure.
 */
int
raid_request_merge_poller(void *args)
{
	struct raid_request_tree	*stripe_tree;
	uint64_t					current_time;
	int							ret;
	ht							*ht;

	stripe_tree = args;
	current_time = spdk_get_ticks() * WAIT_FOR_REQUEST_TIME_MULTIPLIER / spdk_get_ticks_hz();

	if (stripe_tree && stripe_tree->is_pollable && 
		(current_time - stripe_tree->last_request_time > WAIT_FOR_REQUEST_TIME_LIMIT_MICROSECONDS) && (stripe_tree->size != 0)) {

		ret = raid_execute_big_request(stripe_tree);

		if (ret) { return ret; }
		
	}

	if (current_time - stripe_tree->last_request_time > WAIT_FOR_REQUEST_DESTROY_TIME_LIMIT_MICROSECONDS) {
		ht = stripe_tree->raid_bdev->merge_info->merge_ht;
		ht_remove(ht, stripe_tree->stripe_key);
		clear_tree(stripe_tree);
	}

	return 0;
}
