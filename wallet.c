#include "wallet.h"
#include "platform.h"
#include "sha2.h"
#include "keccak.h"
#include "vendor/ripemd160.h"
#include <secp256k1.h>
#include <secp256k1_preallocated.h>
#include <stdint.h>
#include <string.h>
#include "words.h"
static void hmac512(const void *key,size_t keylen,const void *msg,size_t len,unsigned char out[64]) {
    unsigned char block[640]={0},k[128]={0},inner[64];
    if(keylen>128) sha512(key,keylen,k); else memcpy(k,key,keylen);
    for(unsigned i=0;i<128;i++)block[i]=k[i]^0x36;
    memcpy(block+128,msg,len);sha512(block,128+len,inner);
    for(unsigned i=0;i<128;i++)block[i]=k[i]^0x5c;
    memcpy(block+128,inner,64);sha512(block,192,out);
    wipe(block,sizeof(block));wipe(k,sizeof(k));wipe(inner,sizeof(inner));
}
static void seed_from_phrase(const char *phrase,unsigned char seed[64]) {
    unsigned char u[64],v[64];const unsigned char salt[12]={'m','n','e','m','o','n','i','c',0,0,0,1};
    size_t n=strlen(phrase);hmac512(phrase,n,salt,12,u);memcpy(seed,u,64);
    for(unsigned i=1;i<2048;i++) { hmac512(phrase,n,u,64,v);memcpy(u,v,64);for(unsigned j=0;j<64;j++)seed[j]^=u[j]; }
    wipe(u,sizeof(u));wipe(v,sizeof(v));
}
typedef struct { unsigned char key[32],chain[32]; } node;
static void be32(unsigned char *p,uint32_t i) {p[0]=(unsigned char)(i>>24);p[1]=(unsigned char)(i>>16);p[2]=(unsigned char)(i>>8);p[3]=(unsigned char)i;}
static int pubkey(const secp256k1_context *ctx,const node *n,unsigned char *out,int compressed) {
    secp256k1_pubkey pub;size_t len=compressed?33:65;
    int rc=secp256k1_ec_pubkey_create(ctx,&pub,n->key);
    if(rc)rc=secp256k1_ec_pubkey_serialize(ctx,out,&len,&pub,compressed?SECP256K1_EC_COMPRESSED:SECP256K1_EC_UNCOMPRESSED);
    wipe(&pub,sizeof(pub));return rc;
}
static int child(const secp256k1_context *ctx,node *n,uint32_t index) {
    unsigned char data[37],digest[64],key[32];int rc=0;
    if(index&0x80000000U) {data[0]=0;memcpy(data+1,n->key,32);} else if(!pubkey(ctx,n,data,1))goto done;
    be32(data+33,index);hmac512(n->chain,32,data,sizeof(data),digest);memcpy(key,n->key,32);
    if(!secp256k1_ec_seckey_tweak_add(ctx,key,digest))goto done;
    memcpy(n->key,key,32);memcpy(n->chain,digest+32,32);rc=1;
done: wipe(data,sizeof(data));wipe(digest,sizeof(digest));wipe(key,sizeof(key));return rc;
}
static void hash160(const unsigned char pub[33],unsigned char out[20]) {unsigned char h[32];sha256(pub,33,h);ripemd160(h,32,out);wipe(h,32);}
static int base58check(const unsigned char payload[78],char out[113]) {
    static const char alphabet[]="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char bytes[82],h[32],digits[113]={0};size_t used=0,zeros=0;int rc=0;
    memcpy(bytes,payload,78);sha256(payload,78,h);sha256(h,32,h);memcpy(bytes+78,h,4);
    while(zeros<sizeof(bytes)&&!bytes[zeros])zeros++;
    for(size_t i=zeros;i<sizeof(bytes);i++) {
        unsigned carry=bytes[i];
        for(size_t j=0;j<used;j++) {carry+=256U*digits[j];digits[j]=(unsigned char)(carry%58);carry/=58;}
        while(carry) {if(used>=sizeof(digits))goto done;digits[used++]=(unsigned char)(carry%58);carry/=58;}
    }
    if(zeros+used>=113)goto done;
    for(size_t i=0;i<zeros;i++)out[i]='1';
    for(size_t i=0;i<used;i++)out[zeros+i]=alphabet[digits[used-1-i]];
    out[zeros+used]=0;rc=1;
done:wipe(bytes,sizeof(bytes));wipe(h,sizeof(h));wipe(digits,sizeof(digits));return rc;
}
int wallet_from_mnemonic(const char *phrase,wallet_public *out) {
    unsigned char seed[64],master[64],pub[65],h[32],fingerprint[20],payload[78],random[32];
    node root={0},eth={0},btc={0};int rc=0;void *memory=NULL;secp256k1_context *ctx=NULL;
    memset(out,0,sizeof(*out));
    /* Production phrases contain 24 ASCII English words, at most 215 bytes. */
    if(strlen(phrase)>255)return 0;
    size_t size=secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE);
    memory=locked_alloc(size);if(!memory)goto done;
    ctx=secp256k1_context_preallocated_create(memory,SECP256K1_CONTEXT_NONE);
    if(!ctx || !platform_random(random,sizeof(random)) || !secp256k1_context_randomize(ctx,random))goto done;
    seed_from_phrase(phrase,seed);hmac512("Bitcoin seed",12,seed,64,master);
    memcpy(root.key,master,32);memcpy(root.chain,master+32,32);
    if(!secp256k1_ec_seckey_verify(ctx,root.key))goto done;
    eth=root;
    if(!child(ctx,&eth,0x8000002c)||!child(ctx,&eth,0x8000003c)||!child(ctx,&eth,0x80000000)||!child(ctx,&eth,0)||!child(ctx,&eth,0)||!pubkey(ctx,&eth,pub,0))goto done;
    keccak256(pub+1,64,h);
    static const char hex[]="0123456789abcdef";
    out->evm[0]='0';out->evm[1]='x';
    for(unsigned i=0;i<20;i++){out->evm[2+2*i]=hex[h[12+i]>>4];out->evm[3+2*i]=hex[h[12+i]&15];}
    out->evm[42]=0;keccak256(out->evm+2,40,h);
    for(unsigned i=0;i<40;i++)if(out->evm[2+i]>='a'&&out->evm[2+i]<='f'&&((h[i/2]>>(i%2?0:4))&15)>=8)out->evm[2+i]-=32;
    btc=root;
    if(!child(ctx,&btc,0x80000054)||!child(ctx,&btc,0x80000000)||!pubkey(ctx,&btc,pub,1))goto done;
    hash160(pub,fingerprint);
    if(!child(ctx,&btc,0x80000000)||!pubkey(ctx,&btc,pub,1))goto done;
    be32(payload,0x04b24746);payload[4]=3;memcpy(payload+5,fingerprint,4);be32(payload+9,0x80000000);
    memcpy(payload+13,btc.chain,32);memcpy(payload+45,pub,33);
    if(!base58check(payload,out->zpub))goto done;
    rc=1;
done:
    if(ctx)secp256k1_context_preallocated_destroy(ctx);
    locked_free(memory,memory?size:0);
    wipe(seed,sizeof(seed));wipe(master,sizeof(master));wipe(pub,sizeof(pub));wipe(h,sizeof(h));
    wipe(fingerprint,sizeof(fingerprint));wipe(payload,sizeof(payload));wipe(random,sizeof(random));
    wipe(&root,sizeof(root));wipe(&eth,sizeof(eth));wipe(&btc,sizeof(btc));
    if(!rc) { wipe(out,sizeof(*out)); }
    return rc;
}
int wallet_from_entropy(const unsigned char entropy[32],wallet_public *out) {
    char phrase[256];unsigned char checksum[32];size_t used=0;sha256(entropy,32,checksum);
    for(unsigned i=0;i<24;i++) {
        unsigned index=0;
        for(unsigned j=0;j<11;j++){unsigned bit=i*11+j;unsigned char b=bit<256?entropy[bit/8]:checksum[0];index=(index<<1)|((b>>(7-bit%8))&1);}
        size_t n=strlen(words[index]);if(i)phrase[used++]=' ';memcpy(phrase+used,words[index],n);used+=n;
    }
    phrase[used]=0;int rc=wallet_from_mnemonic(phrase,out);wipe(phrase,sizeof(phrase));wipe(checksum,sizeof(checksum));return rc;
}
