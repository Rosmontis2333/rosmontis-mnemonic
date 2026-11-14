#ifndef ROSMONTIS_PLATFORM_H
#define ROSMONTIS_PLATFORM_H
#include <stddef.h>
#include <stdint.h>
#define INPUT_CAP (1024U*1024U)
#define STACK_BYTES (1024U*1024U)
typedef struct secure_thread secure_thread;
void wipe(void *,size_t);
void *locked_alloc(size_t);
void locked_free(void *,size_t);
int secure_thread_create(secure_thread **,void *(*)(void *),void *);
int secure_thread_join(secure_thread *,void **);
int platform_init(size_t);
int terminal_is_interactive(void);
int terminal_enter(void);
void terminal_leave(void);
int terminal_readline(char *,size_t,size_t *);
double monotonic_seconds(void);
void platform_shutdown(void);
int platform_random(void *,size_t);
void platform_set_emergency_cleanup(void (*)(void));
#endif
