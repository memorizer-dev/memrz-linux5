#include "memalloc.h"
#include "kobj_metadata.h"

#include <asm/atomic.h>
#include <asm/percpu.h>

/* global timestamp counter */
atomic_t timestamp = ATOMIC_INIT(0);
long get_ts(void) { return atomic_fetch_add(1,&timestamp); }

//==-- Memorizer Initializtion --------------------------------------------==//
/**
 * memorizer_init() - initialize memorizer state
 *
 * Set enable flag to true which enables tracking for memory access and object
 * allocation. Allocate the object cache as well.
 */
void __init memorizer_init(void)
{
	/* allocate and initialize memorizer internal allocator */
	memorizer_alloc_init();

	/* initialize the lookup table */
	htbl_init();

	pr_info("XNS Detector is intialized");
}