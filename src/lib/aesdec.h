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

#ifndef AESDEC_H_
#define AESDEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#include <stdint.h>
#elif !defined(__RENESAS_VERSION__)
typedef unsigned int uint32_t;
#endif

typedef unsigned char byte_t;
typedef signed char sbyte_t;

int AesKeyLen(int bitlen);
int AesInit(uint32_t *key, const uint32_t *key_org, int bitlen);
int AesDecrypt(const uint32_t *key, const byte_t *src, byte_t *dst, int size);
int AesFin(uint32_t *key);

#ifdef __cplusplus
}
#endif

#endif /* AESDEC_H_ */
