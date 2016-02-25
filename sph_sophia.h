/* $Id: sph_sophia.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * Sophia interface. This code implements Sophia with the recommended
 * parameters for SHA-3, with outputs of 224, 256, 384 and 512 bits.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_sophia.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_SOPHIA_H__
#define SPH_SOPHIA_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for Sophia-224.
 */
#define SPH_SIZE_sophia224   224

/**
 * Output size (in bits) for Sophia-256.
 */
#define SPH_SIZE_sophia256   256

/**
 * Output size (in bits) for Sophia-384.
 */
#define SPH_SIZE_sophia384   384

/**
 * Output size (in bits) for Sophia-512.
 */
#define SPH_SIZE_sophia512   512

/**
 * This structure is a context for Sophia-224 and Sophia-256 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a Sophia computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running Sophia
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	size_t ptr;
	union {
#if SPH_64
		sph_u64 wide[8];
#endif
		sph_u32 narrow[16];
	} state;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_sophia_small_context;

/**
 * This structure is a context for Sophia-224 computations. It is
 * identical to the common <code>sph_sophia_small_context</code>.
 */
typedef sph_sophia_small_context sph_sophia224_context;

/**
 * This structure is a context for Sophia-256 computations. It is
 * identical to the common <code>sph_sophia_small_context</code>.
 */
typedef sph_sophia_small_context sph_sophia256_context;

/**
 * This structure is a context for Sophia-384 and Sophia-512 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a Sophia computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running Sophia
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[128];    /* first field, for alignment */
	size_t ptr;
	union {
#if SPH_64
		sph_u64 wide[16];
#endif
		sph_u32 narrow[32];
	} state;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_sophia_big_context;

/**
 * This structure is a context for Sophia-384 computations. It is
 * identical to the common <code>sph_sophia_small_context</code>.
 */
typedef sph_sophia_big_context sph_sophia384_context;

/**
 * This structure is a context for Sophia-512 computations. It is
 * identical to the common <code>sph_sophia_small_context</code>.
 */
typedef sph_sophia_big_context sph_sophia512_context;

/**
 * Initialize a Sophia-224 context. This process performs no memory allocation.
 *
 * @param cc   the Sophia-224 context (pointer to a
 *             <code>sph_sophia224_context</code>)
 */
void sph_sophia224_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the Sophia-224 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sophia224(void *cc, const void *data, size_t len);

/**
 * Terminate the current Sophia-224 computation and output the result into
 * the provided buffer. The destination buffer must be wide enough to
 * accomodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the Sophia-224 context
 * @param dst   the destination buffer
 */
void sph_sophia224_close(void *cc, void *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (28 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the Sophia-224 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sophia224_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

/**
 * Initialize a Sophia-256 context. This process performs no memory allocation.
 *
 * @param cc   the Sophia-256 context (pointer to a
 *             <code>sph_sophia256_context</code>)
 */
void sph_sophia256_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the Sophia-256 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sophia256(void *cc, const void *data, size_t len);

/**
 * Terminate the current Sophia-256 computation and output the result into
 * the provided buffer. The destination buffer must be wide enough to
 * accomodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the Sophia-256 context
 * @param dst   the destination buffer
 */
void sph_sophia256_close(void *cc, void *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (32 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the Sophia-256 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sophia256_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

/**
 * Initialize a Sophia-384 context. This process performs no memory allocation.
 *
 * @param cc   the Sophia-384 context (pointer to a
 *             <code>sph_sophia384_context</code>)
 */
void sph_sophia384_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the Sophia-384 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sophia384(void *cc, const void *data, size_t len);

/**
 * Terminate the current Sophia-384 computation and output the result into
 * the provided buffer. The destination buffer must be wide enough to
 * accomodate the result (48 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the Sophia-384 context
 * @param dst   the destination buffer
 */
void sph_sophia384_close(void *cc, void *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (48 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the Sophia-384 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sophia384_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

/**
 * Initialize a Sophia-512 context. This process performs no memory allocation.
 *
 * @param cc   the Sophia-512 context (pointer to a
 *             <code>sph_sophia512_context</code>)
 */
void sph_sophia512_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the Sophia-512 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sophia512(void *cc, const void *data, size_t len);

/**
 * Terminate the current Sophia-512 computation and output the result into
 * the provided buffer. The destination buffer must be wide enough to
 * accomodate the result (64 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the Sophia-512 context
 * @param dst   the destination buffer
 */
void sph_sophia512_close(void *cc, void *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (64 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the Sophia-512 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sophia512_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#ifdef __cplusplus
}
#endif

#endif
