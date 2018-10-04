#include <stdio.h>

#include "ftrace_utils.h"

int main(void) {
	set_ftrace_buffer_szie();
	init_marker_fd();
	enable_trace_kmalloc();
	enable_trace_kmalloc_node();
	enable_trace_kmem_cache_alloc_node();
	enalbe_trace_kmem_cache_alloc();

	enable_trace_kfree();
	enable_trace_kmem_cache_free();

	dump_ftrace_atexit();
}