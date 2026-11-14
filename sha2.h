#ifndef ROSMONTIS_SHA2_H
#define ROSMONTIS_SHA2_H
#include <stddef.h>
#include <stdint.h>
void sha256(const void *,size_t,unsigned char[32]);
void sha512(const void *,size_t,unsigned char[64]);
#endif
