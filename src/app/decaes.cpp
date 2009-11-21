/* $Id
 */

#include <assert.h>
#include "aesdec.h"
#ifdef _M_IX86
#include <crtdbg.h>
#endif


#ifdef UNIT_TEST

#include <vector>
#include <memory>

#ifndef __RENESAS_VERSION__
using namespace std;
#endif

/**Key for unit test of key-expantion.
 */
static const byte_t test_key128[16] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

/** The key above shall be expanded as follows:
 */
static const uint32_t test_expand128[44] = {
#ifdef WORDS_BIGENDIAN
	0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
	0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
	0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
	0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
	0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
	0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
	0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
	0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
	0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
	0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
	0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
#else
        0xa8f914d0, 0x8925eec9, 0xc80c3fe1, 0xa60c63b6,
        0xf36677ac, 0x21dcfa19, 0x4129d128, 0x6e005c57,
        0x2173d2ea, 0xd2ba8db5, 0x60f52b31, 0x2f298d7f,
        0x0ef7544e, 0xf3c95f5f, 0xb24fa684, 0x4fdca64e,
        0x7aa3886d, 0xfd3e0b11, 0x4186f9db, 0xfd9300ca,
        0xf8c6d1d4, 0x879d837c, 0xbcb8f2ca, 0xbc15f911,
        0x41a544ef, 0x7f5b52a8, 0x3b2571b6, 0x00ad0bdb,
        0x7d47803d, 0x3efe1647, 0x447e231e, 0x3b887a6d,
        0xf295c2f2, 0x43b9967a, 0x7a803559, 0x7ff65973,
        0x17fefaa0, 0xb12c5488, 0x3939a323, 0x05766c2a,
        0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09,
#endif
};

static const byte_t test_key256[32] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

static const uint32_t test_expands56[44] = {
#ifdef WORDS_BIGENDIAN
#error "not tested."
#else
#endif
};

#if 0
static uint32_t bswap(uint32_t a) {
	return ((a << 24) | ((a & 0xff00) << 8) | ((a >> 8) & 0xff00) | ((a >> 24) & 0xff));
}

static void cnv(const uint32_t *src, int len) {
	for (int i = 0; i < len; i += 4) {
		printf("\t0x%08x, 0x%08x, 0x%08x, 0x%08x,\n",
			bswap(src[i]), bswap(src[i + 1]), bswap(src[i + 2]), bswap(src[i + 3]));
	}
}
#endif

static const byte_t test_decrypt_input[16] = {
	0x39, 0x25, 0x84, 0x1d,
	0x02, 0xdc, 0x09, 0xfb,
	0xdc, 0x11, 0x85, 0x97,
	0x19, 0x6a, 0x0b, 0x32,
};

static const byte_t test_decrypt_output[16] = {
	0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
	0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
};

static int memcompare(const void *s0, const void *s1, size_t len) {
	size_t i;
	const char *s08 = (const char *)s0;
	const char *s18 = (const char *)s1;

	for (i = 0; i < len; ++i) {
		if (*s08++ != *s18++) {
			break;
		}
	}
	return i == len ? 0 : (int)i;
}

static int test_decrypt()
{
	int ret;
	vector<uint32_t> key(AesKeyLen(128) / sizeof(uint32_t));

	ret = AesInit(&key[0], (const uint32_t *)test_key128, 128);
	vector<byte_t> output(sizeof(test_decrypt_input));
	ret = AesDecrypt(&key[0], test_decrypt_input, &output[0], sizeof(test_decrypt_input));
	ret = memcmp(test_decrypt_output, &output[0], sizeof(test_decrypt_output));
	return ret;
}

static int test_perf_inout[128 * 1024 * 1024 / sizeof(int)] = {
	0,
};

static int test_perf()
{
	int ret;
	vector<uint32_t> key(AesKeyLen(128) / sizeof(uint32_t));

	ret = AesInit(&key[0], (const uint32_t *)test_key128, 128);
	ret = AesDecrypt(&key[0], (const byte_t *)test_perf_inout, (byte_t *)test_perf_inout, sizeof(test_perf_inout));
	return ret;
}

int aes_unittest() {
	int ret = 0;
	ret += test_decrypt();
	ret += test_perf();
	return ret;
}
#else
int aes_unittest() {
	return 0;
}
#endif


int main(int argc, char **argv) {
	int ret;

#ifdef _M_IX86
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW);
//	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW);
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_LEAK_CHECK_DF);
#endif
	ret = aes_unittest();
#ifdef _M_IX86
	assert(_CrtCheckMemory());
#endif
	return 0;
}

