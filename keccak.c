/* Keccak-f[1600], Keccak-256 domain separator 0x01 (not SHA3-256). */
#include "keccak.h"
#include "platform.h"
#include <stdint.h>
#include <string.h>
static uint64_t rotate(uint64_t x,unsigned n) { return n?(x<<n)|(x>>(64-n)):x; }
static void permute(uint64_t s[25]) {
    static const uint64_t rc[24]={
        0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
        0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
        0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
        0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
        0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
        0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
    static const unsigned rho[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
    uint64_t c[5],d[5],b[25];
    for(unsigned r=0;r<24;r++) {
        for(unsigned x=0;x<5;x++)c[x]=s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20];
        for(unsigned x=0;x<5;x++)d[x]=c[(x+4)%5]^rotate(c[(x+1)%5],1);
        for(unsigned y=0;y<5;y++)for(unsigned x=0;x<5;x++) {
            s[x+5*y]^=d[x]; b[y+5*((2*x+3*y)%5)]=rotate(s[x+5*y],rho[x+5*y]);
        }
        for(unsigned y=0;y<5;y++)for(unsigned x=0;x<5;x++)s[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
        s[0]^=rc[r];
    }
    wipe(c,sizeof(c));wipe(d,sizeof(d));wipe(b,sizeof(b));
}
void keccak256(const void *data,size_t n,unsigned char out[32]) {
    uint64_t state[25]={0};const unsigned char *p=data;size_t pos=0;
    while(n--) { state[pos/8]^=(uint64_t)*p++<<(8*(pos%8)); if(++pos==136) {permute(state);pos=0;} }
    state[pos/8]^=UINT64_C(1)<<(8*(pos%8));state[16]^=UINT64_C(0x80)<<56;permute(state);
    for(unsigned i=0;i<32;i++)out[i]=(unsigned char)(state[i/8]>>(8*(i%8)));
    wipe(state,sizeof(state));
}
