#include "platform.h"
#include "sha2.h"
#include <argon2.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "vectors.h"
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
    wipe(input,sizeof(input));wipe(out,sizeof(out));wipe(salt,sizeof(salt)); return NULL;
}
int main(void) {
    if(platform_init(64*1024)) { puts("Security initialization failed"); return 1; }
    secure_thread *t;void *result=NULL;
    int rc=secure_thread_create(&t,tests,NULL);
    if(!rc) rc=secure_thread_join(t,&result);
    platform_shutdown();
    if(rc || result) { puts("Self-test failed (hash/Argon2/progress/secure memory)"); return 1; }
    puts("PASS: SHA-256/512 vectors, Argon2d eight lanes/threads, progress, password clearing, locked stacks"); return 0;
}
