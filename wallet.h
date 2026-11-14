#ifndef ROSMONTIS_WALLET_H
#define ROSMONTIS_WALLET_H
#include <stddef.h>
typedef struct { char evm[43]; char zpub[113]; } wallet_public;
int wallet_from_mnemonic(const char *,wallet_public *);
int wallet_from_entropy(const unsigned char[32],wallet_public *);
#endif
