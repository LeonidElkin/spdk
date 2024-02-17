/*   SPDX-License-Identifier: BSD-3-Clause
 *   All rights reserved.
 */

#ifndef SPDK_HT_H
#define SPDK_HT_H

#include "spdk/stdinc.h"
#include "string.h"

#define INITIAL_CAPACITY 16
#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

typedef struct {
    const char *key;
    void *value;
} ht_entry;

typedef struct {
    ht_entry *entries;
    size_t capacity;
    size_t length;
} ht;

typedef struct {
    const char *key;
    void *value;

    ht *_table;
    size_t _index;
} hti;

ht * ht_create(void);
void ht_destroy(ht *table);
void * ht_get(ht *table, const char *key);
const char * ht_set(ht *table, const char *key, void *value);
void * ht_remove(ht *table, const char *key);
size_t ht_length(ht *table);
hti ht_iterator(ht *table);
bool ht_next(hti *it);

#endif
