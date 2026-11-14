#include "platform.h"
#include "sha2.h"
#include "wallet.h"
#include "keccak.h"
#include <argon2.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "vectors.h"
#include "wallet_vectors.h"
static unsigned callbacks;
void rosmontis_argon_progress(uint32_t done,uint32_t total) { if(total==3 && done==callbacks+1) callbacks++; }
static int alloc_cb(uint8_t **p,size_t n) { *p=locked_alloc(n); return *p?0:-1; }
static void free_cb(uint8_t *p,size_t n) { locked_free(p,n); }
static int matches(const unsigned char *bytes,size_t n,const char *expected) {
    const char digits[]="0123456789abcdef";
    for(size_t i=0;i<n;i++) if(expected[i*2]!=digits[bytes[i]>>4] || expected[i*2+1]!=digits[bytes[i]&15]) return 0;
    return 1;
}
static void *tests(void *arg) {
    (void)arg;
    unsigned char input[1024],out[64],salt[32];
    for(size_t i=0;i<sizeof(input);i++) input[i]=(unsigned char)i;
    for(size_t i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++) {
        sha256(input,vectors[i].n,out); if(!matches(out,32,vectors[i].s256)) return (void *)1;
        sha512(input,vectors[i].n,out); if(!matches(out,64,vectors[i].s512)) return (void *)2;
    }
    unsigned char password[]="public test vector";
    sha256("rosmontis",9,salt);
    argon2_context ctx={0};ctx.out=out;ctx.outlen=32;ctx.pwd=password;ctx.pwdlen=sizeof(password)-1;
    ctx.salt=salt;ctx.saltlen=32;ctx.t_cost=3;ctx.m_cost=64;ctx.lanes=8;ctx.threads=8;ctx.version=19;
    ctx.allocate_cbk=alloc_cb;ctx.free_cbk=free_cb;ctx.flags=ARGON2_FLAG_CLEAR_PASSWORD;
    int rc=argon2_ctx(&ctx,Argon2_d);
    if(rc || callbacks!=3 || !matches(out,32,argon_expected)) return (void *)3;
    for(size_t i=0;i<sizeof(password)-1;i++) if(password[i]) return (void *)4;
    keccak256("",0,out);
    if(!matches(out,32,"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"))return (void *)5;
    wallet_public wallet;
    if(!wallet_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",&wallet))return (void *)6;
    if(strcmp(wallet.evm,"0x9858EfFD232B4033E47d90003D41EC34EcaEda94"))return (void *)7;
    if(strcmp(wallet.zpub,"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"))return (void *)8;
    for(size_t i=0;i<sizeof(wallet_vectors)/sizeof(wallet_vectors[0]);i++) {
        if(!wallet_from_entropy(wallet_vectors[i].entropy,&wallet))return (void *)9;
        if(strcmp(wallet.evm,wallet_vectors[i].evm)||strcmp(wallet.zpub,wallet_vectors[i].zpub))return (void *)10;
    }
    wipe(&wallet,sizeof(wallet));
    wipe(input,sizeof(input));wipe(out,sizeof(out));wipe(salt,sizeof(salt)); return NULL;
}
int main(void) {
    if(platform_init(64*1024)) { puts("Security initialization failed"); return 1; }
    secure_thread *t;void *result=NULL;
    int rc=secure_thread_create(&t,tests,NULL);
    if(!rc) rc=secure_thread_join(t,&result);
    platform_shutdown();
    if(rc || result) { printf("Self-test failed: thread=%d vector=%d\n",rc,(int)(intptr_t)result); return 1; }
    puts("PASS: SHA-256/512 vectors, Argon2d eight lanes/threads, progress, password clearing, locked stacks, BIP84 zpub and EVM vectors"); return 0;
}
