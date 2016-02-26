#include "miner.h"
#include "sph_sophia.h"

#include <string.h>
#include <stdint.h>
#include "sophia-asm/grso.c"
#include "sophia-asm/grso-asm.c"


#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif


static void SophiaCoinHash(void *state, const void *input,int mode)
{
	uint32_t hash1[16];
	DATA_ALIGN16(unsigned char hashbuf[128]);
	DATA_ALIGN16(unsigned char hash[128]);
    memset(hash, 0, 128);

	grsoState sts_grs,sts_grs1;

	GRS_I;
	GRS_U;
	GRS_C;

	GRS_I_64;
	GRS_U_64;
	GRS_C_64;

	asm volatile ("emms");

    memcpy(state, hash1, 32);
}

int scanhash_sophia(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done,int alg)
{
		uint32_t n = pdata[19] - 1;
const uint32_t first_nonce = pdata[19];
const uint32_t Htarg = ptarget[7];

uint32_t hash64[8] __attribute__((aligned(32)));
uint32_t endiandata[32];

int kk=0;
for (; kk < 32; kk++)
{
be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
};

do {

pdata[19] = ++n;
be32enc(&endiandata[19], n);
SophiaCoinHash(hash64, &endiandata,0);
        if (((hash64[7]&0xFFFFFF00)==0) &&
fulltest(hash64, ptarget)) {
            *hashes_done = n - first_nonce + 1;
return true;
}
} while (n < max_nonce && !work_restart[thr_id].restart);

*hashes_done = n - first_nonce + 1;
pdata[19] = n;
return 0;
}
static void sophia_hash(const char *input, int length, char *output)
{
    uint32_t hashA[16], hashB[16];

    sph_sophia512_context ctx_sophia[2];

    sph_sophia512_init(&ctx_sophia[0]);
    sph_sophia512 (&ctx_sophia[0], input, length);
    sph_sophia512_close(&ctx_sophia[0], hashA);

    sph_sophia512_init(&ctx_sophia[1]);
    sph_sophia512 (&ctx_sophia[1], hashA, 64);
    sph_sophia512_close(&ctx_sophia[1], hashB);

    memcpy(output, hashB, 32);
}

int scanhash_sophia_(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done,int alg)
{
  uint32_t n = pdata[19] - 1;
  const uint32_t first_nonce = pdata[19];
  const uint32_t Htarg = ptarget[7];

  uint32_t hash64[8] __attribute__((aligned(32)));
  uint32_t endiandata[32];

  int kk=0;
  for (; kk < 32; kk++)
  {
    be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
  };

  do {

    pdata[19] = ++n;
    be32enc(&endiandata[19], n);
    sophia_hash(&endiandata, 80, hash64);
    if (((hash64[7]&0xFFFFFF00)==0) && fulltest(hash64, ptarget)) {
      *hashes_done = n - first_nonce + 1;
      return true;
    }
  } while (n < max_nonce && !work_restart[thr_id].restart);

  *hashes_done = n - first_nonce + 1;
  pdata[19] = n;
  return 0;
}
