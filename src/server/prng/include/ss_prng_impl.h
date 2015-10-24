//
// Copyright (c) 2012 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//
// Copyright (c) 2012 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/**
 *	@file	ss_prng_impl.h
 */

#ifndef __SS_INTERNAL_PRNG_IMPL__
#define __SS_INTERNAL_PRNG_IMPL__

#include "ss_prng.h"

typedef unsigned char byte;
/**
 * Defines the Prng context structure.
 */
typedef struct
{
	unsigned long lenSeed;      //seed length
	unsigned long blockSize;    //block size
	unsigned long randSize;
	unsigned long curOffset;
	unsigned long lenKey;       //key length
	byte* pKey;
	byte* pSeed;
	byte* pRand;        		//holds only reference - memory pointer by this variable to be freed by caller
	struct evp_cipher_st* pAlg;   //algorithm type
} PrngContext;

typedef struct
{
	byte* pBuffer;
	int bufferLen;
} PrngByteBuffer;

/**
 * Generate and fill keys in PrngContext.
 *
 * @return		An error code.
 * @param[in]   prng    Reference to PRNG context structure.
 */
int GenerateKey(PrngContext* prng);

/**
 * Generate and fill seed in PrngContext.
 *
 * @return		An error code.
 * @param[in]   prng    Reference to PRNG context.
 */
int GenerateSeed(PrngContext* prng);

/**
 * Perform XOR operation using content in in1 and in2 and store output in out.
 *
 * @param[in]   pIn1	Pointer to input buffer 1.
 * @param[in]   pIn2    Pointer to input buffer 2.
 * @param[in]   inLen	Length of input buffer.
 * @param[out]  pOut	Pointer to out buffer to which output is stored.
 */
void PerformXor(byte* pIn1, byte* pIn2, unsigned long inLen, byte* pOut);

/**
 * Generate random number.
 *
 * @since 2.1
 * @return		An error code.
 * @param[in]   prng    Reference to PRNG context.
 * @param[in]   pSeed   Pointer to byte buffer containing date factor .
 */
int GenerateRandomBytes(PrngContext* prng, PrngByteBuffer* pSeed);

/**
 * Create PRNG context.
 *
 * @since 2.1
 * @return		Returns pointer to PRNG context on success,NULL on failure.
 */
PrngContext* CreatePrngContextN(void);


#endif
