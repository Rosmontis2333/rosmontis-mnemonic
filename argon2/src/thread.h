#ifndef ARGON2_THREAD_H
#define ARGON2_THREAD_H
#include "platform.h"
typedef secure_thread *argon2_thread_handle_t;
typedef void *(*argon2_thread_func_t)(void *);
int argon2_thread_create(argon2_thread_handle_t *,argon2_thread_func_t,void *);
int argon2_thread_join(argon2_thread_handle_t);
void argon2_thread_exit(void);
#endif
