#ifndef ROSMONTIS_MEMZERO_H
#define ROSMONTIS_MEMZERO_H
#include "platform.h"
#define memzero(p,n) wipe((p),(n))
#endif
