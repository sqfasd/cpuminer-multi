#include "miner.h"
#include "sph_sophia.h"

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

int scanhash_sophia(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
					uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t len = 80;

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

	// we need bigendian data...
	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
#ifdef DEBUG_ALGO
	if (Htarg != 0)
		printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				sophia_hash(&endiandata, len, hash64);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						return true;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
