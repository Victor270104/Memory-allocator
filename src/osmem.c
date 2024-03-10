// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define THRESHOLD_MALLOC (1024 * 128)
#define THRESHOLD_CALLOC (1024 * 4)

int global_variable;
struct block_meta *head;

size_t align(size_t n)
{
	if (n % 8 == 0)
		return n;
	else
		return ((n / 8) + 1) * 8;
}

struct block_meta *find_last_block(struct block_meta *head)
{
	struct block_meta *aux = head;

	while (aux->next != NULL)
		aux = aux->next;
	return aux;
}

void *extind_block(struct block_meta *block, size_t size_new)
{
	sbrk(align(size_new - block->size));
	block->size = align(size_new);
	block->status = STATUS_ALLOC;
	return (((void *)block) + 32);
}

void coal(struct block_meta *initial)
{
	initial->size = initial->size + initial->next->size + 32;
	initial->next = initial->next->next;
	if (initial->next != NULL)
		initial->next->prev = initial;
}

void *split(struct block_meta *initial, size_t size)
{
	struct block_meta *newBlock = (struct block_meta *)((char *)initial + size + 32);

	newBlock->size = initial->size - size - 32;
	newBlock->status = STATUS_FREE;
	newBlock->next = initial->next;
	newBlock->prev = initial;

	if (initial->next != NULL && initial->next->status == STATUS_FREE)
		coal(newBlock);
	initial->size = size;
	initial->status = STATUS_ALLOC;
	initial->next = newBlock;
	return ((void *)initial + 32);
}

size_t min(size_t a, size_t b)
{
	size_t aux = a;

	if (b < aux)
		aux = b;
	return aux;
}

void *my_alloc(size_t nmemb, size_t size, size_t cap)
{
	size = align(size * nmemb);
	size_t block_size = size + 32;

	if (global_variable == 0) {
		if (size + 32 < cap) {
			global_variable = 1;
			void *req = sbrk(THRESHOLD_MALLOC);

			head = (struct block_meta *)req;

			head->status = STATUS_ALLOC;
			head->size = THRESHOLD_MALLOC - 32;
			head->next = NULL;
			head->prev = NULL;
			return req + 32;
		}
		void *req = mmap(NULL, block_size, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

		head = (struct block_meta *)req;
		head->status = STATUS_MAPPED;
		head->size = size;
		head->next = NULL;
		head->prev = NULL;
		return req + 32;
	}
	if (size < cap) {
		struct block_meta *cur = head;

		if (cur->status == STATUS_FREE && cur->size >= size) {
			if (size == cur->size) {
				cur->status = STATUS_ALLOC;
				return (((void *)cur) + 32);
			}
			if (cur->size < 40 + size) {
				cur->status = STATUS_ALLOC;
				return (((void *)cur) + 32);
			}
			void *req = split(cur, size);
			return req;
		}
		while (cur->next != NULL) {
			if (cur->next->status == STATUS_FREE && cur->next->size >= size) {
				if (size == cur->next->size) {
					cur->next->status = STATUS_ALLOC;
					return (((void *)cur->next) + 32);
				}
				if (cur->next->size < 40 + size) {
					cur->next->status = STATUS_ALLOC;
					return (((void *)cur->next) + 32);
				}
				void *req = split(cur->next, size);
				return req;
			}
			cur = cur->next;
		}
		cur = find_last_block(head);
		if (cur->status == STATUS_FREE)
			return extind_block(cur, size);
		void *req = sbrk(block_size);
		struct block_meta *new_node = (struct block_meta *)req;

			cur->next = new_node;
			new_node->prev = cur;
		new_node->next = NULL;
		new_node->size = size;
		new_node->status = STATUS_ALLOC;
		return req + 32;
	}
	void *req = mmap(NULL, block_size, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

	head = (struct block_meta *)req;
	head->status = STATUS_MAPPED;
	head->size = size;
	head->next = NULL;
	head->prev = NULL;
	return req + 32;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	void *ptr = my_alloc(1, size, THRESHOLD_MALLOC);

	return ptr;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *p = (struct block_meta *)(ptr - 32);

	if (p->status == STATUS_ALLOC) {
		if (p->prev != NULL && p->prev->status == STATUS_FREE) {
			coal(p->prev);
			p->status = STATUS_FREE;
			return;
		}
		if (p->next != NULL && p->next->status == STATUS_FREE)
			coal(p);
		p->status = STATUS_FREE;
	}
	if (p->status == STATUS_MAPPED) {
		if (p == head)
			global_variable = 0;
		munmap(p, p->size + 32);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	void *ptr = my_alloc(nmemb, size, THRESHOLD_CALLOC);

	memset(ptr, 0, nmemb * size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	size = align(size);
	size_t block_size = size + 32;

	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return 0;
	}
	struct block_meta *p = (struct block_meta *)(ptr - 32);
	size_t old_size = p->size;
	int old_status = p->status;

	if (p->status == STATUS_FREE)
		return NULL;
	if (old_size == size)
		return ptr;
	if (old_size > size) {
		if (old_status == STATUS_ALLOC && size <= THRESHOLD_MALLOC) {
			if (old_size >= 40 + size)
				split(p, size);
			return ptr;
		}
		if (old_status == STATUS_MAPPED && size > THRESHOLD_MALLOC) {
			void *req = mmap(NULL, block_size, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

			memcpy(req + 32, ptr, min(old_size, size));
			struct block_meta *node = p;

			p = (struct block_meta *)req;
			p->size = size;
			p->status = STATUS_MAPPED;
			p->next = node->next;
			p->prev = node->prev;
			os_free(ptr);
			return req + 32;
		}
		if (old_status == STATUS_MAPPED && size <= THRESHOLD_MALLOC) {
			if (global_variable == 0) {
				global_variable = 1;
				void *req = sbrk(THRESHOLD_MALLOC);

				memcpy(req + 32, ptr, min(old_size, size));
				p = (struct block_meta *)req;
				p->status = STATUS_ALLOC;
				os_free(ptr);
				return req + 32;
			}
			struct block_meta *cur = head;

			if (cur->status == STATUS_FREE && cur->size >= size) {
				if (size == cur->size) {
					cur->status = STATUS_ALLOC;
					memcpy(((void *)cur) + 32, ptr, min(old_size, size));
					return (((void *)cur) + 32);
				}
				if (cur->size < 40 + size) {
					cur->status = STATUS_ALLOC;
					memcpy(((void *)cur) + 32, ptr, min(old_size, size));
					return (((void *)cur) + 32);
				}
				void *req = split(cur, size);

				memcpy(req, ptr, min(old_size, size));
				return req;
			}
			while (cur->next != NULL) {
				if (cur->next->status == STATUS_FREE && cur->next->size >= size) {
					if (size == cur->next->size) {
						cur->next->status = STATUS_ALLOC;
						memcpy(((void *)cur->next) + 32, ptr, min(old_size, size));
						return (((void *)cur->next) + 32);
					}
					if (cur->next->size < 40 + size) {
						cur->next->status = STATUS_ALLOC;
						memcpy(((void *)cur->next) + 32, ptr, min(old_size, size));
						return (((void *)cur->next) + 32);
					}
					void *req = split(cur->next, size);

					memcpy(req, ptr, min(old_size, size));
					return req;
				}
				cur = cur->next;
			}
			cur = find_last_block(head);
			if (cur->status == STATUS_FREE)
				return extind_block(cur, size);
			void *req = sbrk(block_size);

			memcpy(req + 32, ptr, min(old_size, size));
			struct block_meta *new = (struct block_meta *)req;

			new->status = STATUS_ALLOC;
			new->next = NULL;
			new->size = block_size - 32;
			new->prev = cur;
			cur->next = new;
			os_free(ptr);
			return req + 32;
		}
	}

	if (old_size < size) {
		if (old_status == STATUS_ALLOC && size <= THRESHOLD_MALLOC) {
			int pcc = 1, contor = 0;
			size_t first_size = p->size;

			while (p->next != NULL && p->next->status == STATUS_FREE && p->size < size && pcc == 1) {
				pcc = 0;
				if (p->next->status == STATUS_FREE) {
					coal(p);
					pcc = 1;
					contor = 1;
				}
			}

			if (p->size >= size)
				return ptr;
			if (contor == 1)
				split(p, first_size);
			if (p->next == NULL)
				return extind_block(p, size);
			struct block_meta *cur = head;

			while (cur != NULL) {
				if (cur->status == STATUS_FREE && cur->size >= size) {
					split(cur, size);
					void *req = (void *)cur;

					memcpy(req + 32, ptr, min(old_size, size));
					p->status = STATUS_FREE;
					pcc = 1;
					struct block_meta *current = cur;

				while (current->next != NULL && pcc == 1) {
					pcc = 0;
					if (current->next->status == STATUS_FREE) {
						coal(p);
						pcc = 1;
						contor = 1;
					}
						current = current->next;
					}
					return req + 32;
				}
				cur = cur->next;
			}

			if (p->next == NULL)
				return extind_block(p, size);
			void *req = sbrk(block_size);

			memcpy(req + 32, ptr, min(old_size, size));
			struct block_meta *node = p;

			p = (struct block_meta *)req;
			p->size = size;
			p->status = STATUS_ALLOC;
			p->next = node->next;
			p->prev = node->prev;
			return req + 32;
		}
		if (old_status == STATUS_MAPPED && size > THRESHOLD_MALLOC) {
			void *req = mmap(NULL, block_size, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

			memcpy(req + 32, ptr, min(old_size, size));
			struct block_meta *node = p;

			p = (struct block_meta *)req;
			p->size = size;
			p->status = STATUS_MAPPED;
			p->next = node->next;
			p->prev = node->prev;
			os_free(ptr);
			return req + 32;
		}
		if (old_status == STATUS_ALLOC && size > THRESHOLD_MALLOC) {
			void *req = mmap(NULL, block_size, 0x1 | 0x2, 0x02 | 0x20, -1, 0);

			memcpy(req + 32, ptr, min(old_size, size));
			struct block_meta *node = p;

			p = (struct block_meta *)req;
			p->size = size;
			p->status = STATUS_MAPPED;
			p->next = node->next;
			p->prev = node->prev;
			os_free(ptr);
			return req + 32;
		}
	}
	return ptr;
}
