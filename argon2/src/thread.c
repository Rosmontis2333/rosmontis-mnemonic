/* Application adapter. Upstream algorithm remains unchanged. */
#include "thread.h"
int argon2_thread_create(argon2_thread_handle_t *h,argon2_thread_func_t f,void *a) { return secure_thread_create(h,f,a); }
int argon2_thread_join(argon2_thread_handle_t h) { return secure_thread_join(h,0); }
/* Return normally through the adapter, allowing secure stack cleanup. */
void argon2_thread_exit(void) {}
