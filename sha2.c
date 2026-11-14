#include "sha2.h"
#include "platform.h"
#include <string.h>
static const uint64_t K[80]={
UINT64_C(0x428a2f98d728ae22),
UINT64_C(0x7137449123ef65cd),
UINT64_C(0xb5c0fbcfec4d3b2f),
UINT64_C(0xe9b5dba58189dbbc),
UINT64_C(0x3956c25bf348b538),
UINT64_C(0x59f111f1b605d019),
UINT64_C(0x923f82a4af194f9b),
UINT64_C(0xab1c5ed5da6d8118),
UINT64_C(0xd807aa98a3030242),
UINT64_C(0x12835b0145706fbe),
UINT64_C(0x243185be4ee4b28c),
UINT64_C(0x550c7dc3d5ffb4e2),
UINT64_C(0x72be5d74f27b896f),
UINT64_C(0x80deb1fe3b1696b1),
UINT64_C(0x9bdc06a725c71235),
UINT64_C(0xc19bf174cf692694),
UINT64_C(0xe49b69c19ef14ad2),
UINT64_C(0xefbe4786384f25e3),
UINT64_C(0x0fc19dc68b8cd5b5),
UINT64_C(0x240ca1cc77ac9c65),
UINT64_C(0x2de92c6f592b0275),
UINT64_C(0x4a7484aa6ea6e483),
UINT64_C(0x5cb0a9dcbd41fbd4),
UINT64_C(0x76f988da831153b5),
UINT64_C(0x983e5152ee66dfab),
UINT64_C(0xa831c66d2db43210),
UINT64_C(0xb00327c898fb213f),
UINT64_C(0xbf597fc7beef0ee4),
UINT64_C(0xc6e00bf33da88fc2),
UINT64_C(0xd5a79147930aa725),
UINT64_C(0x06ca6351e003826f),
UINT64_C(0x142929670a0e6e70),
UINT64_C(0x27b70a8546d22ffc),
UINT64_C(0x2e1b21385c26c926),
UINT64_C(0x4d2c6dfc5ac42aed),
UINT64_C(0x53380d139d95b3df),
UINT64_C(0x650a73548baf63de),
UINT64_C(0x766a0abb3c77b2a8),
UINT64_C(0x81c2c92e47edaee6),
UINT64_C(0x92722c851482353b),
UINT64_C(0xa2bfe8a14cf10364),
UINT64_C(0xa81a664bbc423001),
UINT64_C(0xc24b8b70d0f89791),
UINT64_C(0xc76c51a30654be30),
UINT64_C(0xd192e819d6ef5218),
UINT64_C(0xd69906245565a910),
UINT64_C(0xf40e35855771202a),
UINT64_C(0x106aa07032bbd1b8),
UINT64_C(0x19a4c116b8d2d0c8),
UINT64_C(0x1e376c085141ab53),
UINT64_C(0x2748774cdf8eeb99),
UINT64_C(0x34b0bcb5e19b48a8),
UINT64_C(0x391c0cb3c5c95a63),
UINT64_C(0x4ed8aa4ae3418acb),
UINT64_C(0x5b9cca4f7763e373),
UINT64_C(0x682e6ff3d6b2b8a3),
UINT64_C(0x748f82ee5defb2fc),
UINT64_C(0x78a5636f43172f60),
UINT64_C(0x84c87814a1f0ab72),
UINT64_C(0x8cc702081a6439ec),
UINT64_C(0x90befffa23631e28),
UINT64_C(0xa4506cebde82bde9),
UINT64_C(0xbef9a3f7b2c67915),
UINT64_C(0xc67178f2e372532b),
UINT64_C(0xca273eceea26619c),
UINT64_C(0xd186b8c721c0c207),
UINT64_C(0xeada7dd6cde0eb1e),
UINT64_C(0xf57d4f7fee6ed178),
UINT64_C(0x06f067aa72176fba),
UINT64_C(0x0a637dc5a2c898a6),
UINT64_C(0x113f9804bef90dae),
UINT64_C(0x1b710b35131c471b),
UINT64_C(0x28db77f523047d84),
UINT64_C(0x32caab7b40c72493),
UINT64_C(0x3c9ebe0a15c9bebc),
UINT64_C(0x431d67c49c100d4c),
UINT64_C(0x4cc5d4becb3e42b6),
UINT64_C(0x597f299cfc657e2a),
UINT64_C(0x5fcb6fab3ad6faec),
UINT64_C(0x6c44198c4a475817)};
static const uint64_t IV[8]={UINT64_C(0x6a09e667f3bcc908),UINT64_C(0xbb67ae8584caa73b),UINT64_C(0x3c6ef372fe94f82b),UINT64_C(0xa54ff53a5f1d36f1),UINT64_C(0x510e527fade682d1),UINT64_C(0x9b05688c2b3e6c1f),UINT64_C(0x1f83d9abfb41bd6b),UINT64_C(0x5be0cd19137e2179)};
static uint64_t r64(uint64_t x,unsigned n) { return (x>>n)|(x<<(64-n)); }
static uint32_t r32(uint32_t x,unsigned n) { return (x>>n)|(x<<(32-n)); }
static void block512(uint64_t h[8],const unsigned char block[128]) {
    uint64_t w[80],a,b,c,d,e,f,g,hv,t1,t2;
    for(unsigned i=0;i<16;i++) { w[i]=0; for(unsigned j=0;j<8;j++)w[i]=(w[i]<<8)|block[i*8+j]; }
    for(unsigned i=16;i<80;i++) { uint64_t x=w[i-15],y=w[i-2]; w[i]=w[i-16]+(r64(x,1)^r64(x,8)^(x>>7))+w[i-7]+(r64(y,19)^r64(y,61)^(y>>6)); }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hv=h[7];
    for(unsigned i=0;i<80;i++) {
        t1=hv+(r64(e,14)^r64(e,18)^r64(e,41))+((e&f)^((~e)&g))+K[i]+w[i];
        t2=(r64(a,28)^r64(a,34)^r64(a,39))+((a&b)^(a&c)^(b&c));
        hv=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hv;wipe(w,sizeof(w));
}
static void block256(uint32_t h[8],const unsigned char block[64]) {
    uint32_t w[64],a,b,c,d,e,f,g,hv,t1,t2;
    for(unsigned i=0;i<16;i++) { w[i]=0; for(unsigned j=0;j<4;j++) w[i]=(w[i]<<8)|block[i*4+j]; }
    for(unsigned i=16;i<64;i++) { uint32_t x=w[i-15],y=w[i-2]; w[i]=w[i-16]+(r32(x,7)^r32(x,18)^(x>>3))+w[i-7]+(r32(y,17)^r32(y,19)^(y>>10)); }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hv=h[7];
    for(unsigned i=0;i<64;i++) {
        t1=hv+(r32(e,6)^r32(e,11)^r32(e,25))+((e&f)^((~e)&g))+(uint32_t)(K[i]>>32)+w[i];
        t2=(r32(a,2)^r32(a,13)^r32(a,22))+((a&b)^(a&c)^(b&c));
        hv=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hv;wipe(w,sizeof(w));
}
void sha512(const void *data,size_t n,unsigned char out[64]) {
    const unsigned char *p=data; size_t original=n; uint64_t h[8]; unsigned char tail[128];
    memcpy(h,IV,sizeof(h));
    while(n>=128) { block512(h,p); p+=128;n-=128; }
    memset(tail,0,sizeof(tail));memcpy(tail,p,n);tail[n]=0x80;
    if(n>=112) { block512(h,tail);memset(tail,0,sizeof(tail)); }
    uint64_t low=(uint64_t)original<<3,high=(uint64_t)original>>61;
    for(unsigned i=0;i<8;i++) { tail[127-i]=(unsigned char)(low>>(8*i));tail[119-i]=(unsigned char)(high>>(8*i)); }
    block512(h,tail);
    for(unsigned i=0;i<64;i++)out[i]=(unsigned char)(h[i/8]>>(56-8*(i%8)));
    wipe(h,sizeof(h));wipe(tail,sizeof(tail));
}
void sha256(const void *data,size_t n,unsigned char out[32]) {
    const unsigned char *p=data;size_t original=n;uint32_t h[8];unsigned char tail[64];
    for(unsigned i=0;i<8;i++)h[i]=(uint32_t)(IV[i]>>32);
    while(n>=64) { block256(h,p);p+=64;n-=64; }
    memset(tail,0,sizeof(tail));memcpy(tail,p,n);tail[n]=0x80;
    if(n>=56) { block256(h,tail);memset(tail,0,sizeof(tail)); }
    uint64_t bits=(uint64_t)original<<3;
    for(unsigned i=0;i<8;i++)tail[63-i]=(unsigned char)(bits>>(8*i));
    block256(h,tail);
    for(unsigned i=0;i<32;i++)out[i]=(unsigned char)(h[i/4]>>(24-8*(i%4)));
    wipe(h,sizeof(h));wipe(tail,sizeof(tail));
}
