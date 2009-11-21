/** libdecaes is a yet another AES decrypter.
 *  Copyright 2008 Takayuki Minegishi
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation
 *  files (the "Software"), to deal in the Software without
 *  restriction, including without limitation the rights to use, copy,
 *  modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#ifdef __RENESAS_VERSION__
typedef unsigned int uint32_t;
typedef signed short int16_t;
#endif

#include "aesdec.h"
#include "tables.h"

#define ROT8(x) (((x) << 24) | ((x) >> 8))
#define ROT24(x) (((x) << 8) | ((x) >> 24))
#ifdef __RENESAS_VERSION__
#pragma inline(expansion_each, invmixcolums, invmixcolums_each, invshiftrows_subbytes, addroundkey_invmixcolums, decrypt_block)
#include <umachine.h>
#define ROT16(x) swapw(x)
#else
#define ROT16(x) (((x) << 16) | ((x) >> 16))
#endif

static void expansion_block128(uint32_t *key, int blk_num, int blk_len) {
	int i;
	int t;
	byte_t *p = (byte_t *)&key[blk_len * 2 - 1];

#ifdef WORDS_BIGENDIAN
#error "Not confirmed"
	t = ((sbox[p[2]] ^ rcon[blk_num]) << 24) | (sbox[p[1]] << 16) | (sbox[p[0]] << 8) | sbox[p[3]];
#else
	t = (sbox[p[0]] << 24) | (sbox[p[1]] ^ rcon[blk_num]) | (sbox[p[2]] << 8) | (sbox[p[3]] << 16);
#endif
	for (i = 0; i < blk_len; ++i) {
		t = key[blk_len + i] ^ t;
		key[i] = t;
		if ((blk_num == 7) && (3 <= i)) {
			break;
		}
	}
}

static void expansion_block256(uint32_t *key, int blk_num, int blk_len) {
	int i;
	uint32_t t;
	byte_t *p = (byte_t *)&key[4 + 3];
	int d = (blk_num < 6) ? 0 : 4;

#ifdef WORDS_BIGENDIAN
#error "Not confirmed"
	t = ((sbox[p[2]] ^ rcon[blk_num]) << 24) | (sbox[p[1]] << 16) | (sbox[p[0]] << 8) | sbox[p[3]];
#else
	t = (sbox[p[0]] << 24) | (sbox[p[1]] ^ rcon[blk_num]) | (sbox[p[2]] << 8) | (sbox[p[3]] << 16);
#endif
	for (i = 0; i < 4; ++i) {
		t = key[blk_len + i] ^ t;
		key[i] = t;
	}
	if (d) {
		return;
	}
	t = (sbox[(t >> 24)] << 24)
		| (sbox[(t >> 16) & 0xff] << 16)
		| (sbox[(t >> 8) & 0xff] << 8)
		| sbox[t & 0xff];
	key -= 4;
	for (i = 0; i < 4; ++i) {
		t = key[blk_len + i] ^ t;
		key[i] = t;
	}
}

static void expansion_each(uint32_t *key, const uint32_t *key_org, int blk_len, int round_num) {
	void (* expansion_block)(uint32_t *key, int blk_num, int blk_len);
	int loop_max;
	static const char loop[] = {10, 8, 7};

	key = key + (round_num + 1) * 4 - 4;
	memcpy(key, key_org, 4 * 4);
	int rest = blk_len - 4;
	if (rest) {
		memcpy(key - 4, key_org + 4, rest * 4);
	}
	expansion_block = (blk_len < 8) ? expansion_block128 : expansion_block256;
	loop_max = loop[(blk_len >> 1) - 2];
	for (int i = 0; i < loop_max; ++i) {
		key -= blk_len;
		expansion_block(key, i, blk_len);
	}
}

static void invmixcolums(uint32_t *key) {
	const byte_t *src = (const byte_t *)key;
	int i;

	for (i = 0; i < 4; ++i) {
		uint32_t t0, t1, t2, t3;
		t0 = inv_mult[*src++];
		t1 = inv_mult[*src++];
		t2 = inv_mult[*src++];
		t3 = inv_mult[*src++];
		*key = t0 ^ ROT24(t1) ^ ROT16(t2) ^ ROT8(t3);
		key += 1;
	}
}

static void invmixcolums_each(uint32_t *key, int round_num) {
	for (int i = 0; i < round_num - 1; ++i) {
		key += 4;
		invmixcolums(key);
	}
}

#if defined(__RENESAS_VERSION__) && (defined(_SH4ALDSP) || defined(_SH4A))

#pragma inline_asm(addroundkey_src, addroundkey_dst)

static void addroundkey_src(const uint32_t *src, uint32_t *dst, const uint32_t *key)
{
	MOVUA.L	@R4+, R0
	MOV.L	@R6+, R1
	MOV.L	@R6+, R3
	XOR	R0, R1
	MOVUA.L	@R4+, R0
	MOV.L	R1, @R5
	XOR	R0, R3
	MOVUA.L	@R4+, R0
	MOV.L	@R6+, R1
	MOV.L	R3, @(4, R5)
	XOR	R0, R1
	MOVUA.L	@R4+, R0
	MOV.L	@R6+, R3
	MOV.L	R1, @(8, R5)
	XOR	R0, R3
	MOV.L	R3, @(12, R5)
}

static void addroundkey_dst(const uint32_t *src, uint32_t *dst, const uint32_t *key)
{
	MOV	#4, R7
?LOOP0:
	MOV.L	@R6+, R1
	DT	R7
	MOV.L	@R4+, R0
	XOR	R1, R0
	MOV.B	R0, @R5
	SHLR8	R0
	MOV.B	R0, @(1, R5)
	SHLR8	R0
	MOV.B	R0, @(2, R5)
	SHLR8	R0
	MOV.B	R0, @(3, R5)
	BF/S	?LOOP0
	ADD	#4, R5
}

#else

/* ignore data alignment.
 */
#define addroundkey_dst addroundkey_src
static void addroundkey_src(const uint32_t *src, uint32_t *dst, const uint32_t *key) {
	dst[0] = key[0] ^ src[0];
	dst[1] = key[1] ^ src[1];
	dst[2] = key[2] ^ src[2];
	dst[3] = key[3] ^ src[3];
}

#endif


/**Decrypt a 128bit block.
 */
static inline void decrypt_block(const byte_t *src, byte_t *dst, const uint32_t *key, int blk_len) {
	uint32_t aligned[4];
	uint32_t t0, t1, t2, t3;
	int i;
	addroundkey_src((const uint32_t *)src, aligned, key);
	key += 4;
#ifdef WORDS_BIGENDIAN
#error "not confirmed."
#endif
	t0 = aligned[0]; // 15, 10, 5, 0
	t1 = aligned[1]; // 3, 14, 9, 4
	t2 = aligned[2]; // 7, 2, 13, 8
	t3 = aligned[3]; // 11, 6, 1, 12
	i = blk_len + 5;
	do {
		uint32_t u0, u1, u2;
		u0 = key[0]
			^ inv_mult_inv_sbox[t0 & 0xff]
			^ inv_mult_rot24_inv_sbox[(t3 >> 8) & 0xff]
			^ inv_mult_rot16_inv_sbox[(t2 >> 16) & 0xff]
			^ inv_mult_rot8_inv_sbox[t1 >> 24];
		u1 = key[1]
			^ inv_mult_inv_sbox[t1 & 0xff]
			^ inv_mult_rot24_inv_sbox[(t0 >> 8) & 0xff]
			^ inv_mult_rot16_inv_sbox[(t3 >> 16) & 0xff]
			^ inv_mult_rot8_inv_sbox[t2 >> 24];
		u2 = key[2]
			^ inv_mult_inv_sbox[t2 & 0xff]
			^ inv_mult_rot24_inv_sbox[(t1 >> 8) & 0xff]
			^ inv_mult_rot16_inv_sbox[(t0 >> 16) & 0xff]
			^ inv_mult_rot8_inv_sbox[t3 >> 24];
		t3 = key[3]
			^ inv_mult_inv_sbox[t3 & 0xff]
			^ inv_mult_rot24_inv_sbox[(t2 >> 8) & 0xff]
			^ inv_mult_rot16_inv_sbox[(t1 >> 16) & 0xff]
			^ inv_mult_rot8_inv_sbox[t0 >> 24];
		t0 = u0;
		t1 = u1;
		t2 = u2;
		key += 4;
	} while (--i);
	aligned[0] = (inv_sbox[t1 >> 24] << 24)
		| (inv_sbox[(t2 >> 16) & 0xff] << 16)
		| (inv_sbox[(t3 >> 8) & 0xff] << 8)
		| inv_sbox[t0 & 0xff];
	aligned[1] = (inv_sbox[t2 >> 24] << 24)
		| (inv_sbox[(t3 >> 16) & 0xff] << 16)
		| (inv_sbox[(t0 >> 8) & 0xff] << 8)
		| inv_sbox[t1 & 0xff];
	aligned[2] = (inv_sbox[t3 >> 24] << 24)
		| (inv_sbox[(t0 >> 16) & 0xff] << 16)
		| (inv_sbox[(t1 >> 8) & 0xff] << 8)
		| inv_sbox[t2 & 0xff];
	aligned[3] = (inv_sbox[t0 >> 24] << 24)
		| (inv_sbox[(t1 >> 16) & 0xff] << 16)
		| (inv_sbox[(t2 >> 8) & 0xff] << 8)
		| inv_sbox[t3 & 0xff];
	addroundkey_dst((const uint32_t *)aligned, (uint32_t *)dst, key);
}

#define INVALID(bitlen) ((bitlen) != 128 && (bitlen) != 192 && (bitlen) != 256)
#define BLKLEN(bits) ((unsigned)(bits) >> 5)

extern "C" {

int AesKeyLen(int bitlen) {
	int rounds = BLKLEN(bitlen) + 6;
	return (rounds + 1) * 4 * sizeof(uint32_t) + 4;
}

int AesInit(uint32_t *key, const uint32_t *key_org, int bitlen) {
	int blk_len;
	int round_num;

	if (!key || !key_org || INVALID(bitlen)) {
		return -1;
	}
	key[0] = bitlen;
	key += 1;
	blk_len = BLKLEN(bitlen);
	round_num = blk_len + 6;
	expansion_each(key, key_org, blk_len, round_num);
	invmixcolums_each(key, round_num);
	return 0;
}

int AesDecrypt(const uint32_t *key, const byte_t *src, byte_t *dst, int size) {
	int bitlen;
	int blk_len;
	int blk_num;

	if (!key || !src || !dst || size < 16) {
		return -1;
	}
	bitlen = key[0];
	if (INVALID(bitlen) ) {
		return -1;
	}
	key += 1;
	blk_len = BLKLEN(bitlen);
	blk_num = (unsigned)size >> 4;
	do {
		decrypt_block(src, dst, key, blk_len);
		src += 16;
		dst += 16;
	} while (--blk_num);
	return 0;
}

int AesFin(uint32_t *key) {
	int bitlen = key[0];
	if (!key || INVALID(bitlen)) {
		return -1;
	}
	memset(key, 0, AesKeyLen(bitlen));
	return 0;
}


}

