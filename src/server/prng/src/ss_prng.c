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
 *  @file	ss_prng.cpp
 *  @brief	This file contains implementation of Pseudo Random Function based on ANSI X9.31 Appendix A.2.4.
 *
 */
#include <stdlib.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <ss_prng_impl.h>

void DestroyPrngContext(PrngContext* pPrng)
{
	if(pPrng)
	{
		if(pPrng->pKey)
		{
			free(pPrng->pKey);
			pPrng->pKey = NULL;
		}
		if(pPrng->pSeed)
		{
			free(pPrng->pSeed);
			pPrng->pSeed = NULL;
		}
		free(pPrng);
		pPrng = NULL;
	}
}

byte* GetRandomBytesN(struct evp_cipher_st* pAlg, long outLen)
{
	int r = SS_PRNG_SUCCESS;
	byte* pRetBuf = NULL; 
	if(!pAlg || outLen <= 0)
	{
		SLOGE("Input data are not valid.");
		return NULL;
	}

	PrngContext* pPrng = CreatePrngContextN();
	if(pPrng == NULL)
	{
		SLOGE("Allocating new PrngContext object failed.");
		return NULL;
	}

	byte* pOutBuf = (byte*)malloc(sizeof(byte) * outLen);
	TryCatch(pOutBuf != NULL, , "Allocating new byte buffer failed");

	// init pAlg details
	pPrng->pAlg = pAlg;
	pPrng->lenKey = pAlg->key_len;
	pPrng->blockSize = pAlg->block_size;
	pPrng->lenSeed = pPrng->blockSize;

	r = GenerateKey(pPrng);
	TryCatch(r == SS_PRNG_SUCCESS, free(pOutBuf), "Failed to generate key");

	r = GenerateSeed(pPrng);
	TryCatch(r == SS_PRNG_SUCCESS, free(pOutBuf), "Failed to generate seed");

	pPrng->pRand = pOutBuf;
	pPrng->randSize = outLen;
	pPrng->curOffset = 0;

	r = GenerateRandomBytes(pPrng, NULL);
	TryCatch(r == SS_PRNG_SUCCESS, free(pOutBuf), "Failed to generate random bytes");

	pRetBuf = pOutBuf;

CATCH:
	DestroyPrngContext(pPrng);

	return pRetBuf;
}

int GenerateKey(PrngContext* prng)
{
	unsigned long index = 0;
	unsigned long offset = 0;
	clock_t tick = NULL;

	prng->pKey = (byte*)malloc(sizeof(byte) * prng->lenKey);
	if(!prng->pKey)
	{
		SLOGE("Allocating new byte array failed.");
		return SS_PRNG_ERROR_OUT_OF_MEMORY; // E_OUT_OF_MEMORY
	}

	offset = 0;
	index = sizeof(clock_t);

	while (offset < prng->lenKey)
	{
		if ((offset + sizeof(clock_t)) > prng->lenKey)
		{
			index = prng->lenKey - offset;
		}
		tick = clock();
		PerformXor(prng->pKey + offset, (byte*)(&tick), index, prng->pKey + offset);
		offset += index;
	}

	prng->lenKey = offset;
	return SS_PRNG_SUCCESS;
}

int GenerateSeed(PrngContext* prng)
{
	unsigned long offset = 0;
	unsigned long index = 0;
	clock_t tick = 0;
	time_t miliSecond = 0;

	miliSecond = time(NULL);

	prng->pSeed = (byte*)malloc(sizeof(byte) * prng->lenSeed);
	if(!prng->pSeed)
	{
		SLOGE("Allocating new byte array failed.");
		return SS_PRNG_ERROR_OUT_OF_MEMORY; // E_OUT_OF_MEMORY
	}

	offset = 0;
	index = sizeof(clock_t);

	while (offset < prng->lenSeed)
	{
		if ((offset + sizeof(clock_t)) > prng->lenSeed)
		{
			index = prng->lenSeed - offset;
		}

		tick = clock();
		tick = tick + miliSecond;
		PerformXor(prng->pSeed + offset, (byte*)(&tick), index, prng->pSeed + offset);
		offset += index;
	}

	prng->lenSeed = offset;
	return SS_PRNG_SUCCESS;
}

void PerformXor(byte* pIn1, byte* pIn2, unsigned long inLen, byte* pOut)
{
	unsigned long index = 0;

	for (index = 0; index < inLen; index++)
	{
		pOut[index] = pIn1[index] ^ pIn2[index];
	}

}

int GenerateRandomBytes(PrngContext* prng, PrngByteBuffer* pSeed)
{
	int r = SS_PRNG_SUCCESS;
	unsigned int ret = 0;
	unsigned long tmp = 0;
	unsigned long offset = 0;
	unsigned long lenInterVal1 = 0;
	unsigned long lenInterVal2 = 0;
	unsigned long dtLen = 0;
	unsigned long blockSize = prng->blockSize;
	unsigned long randSize = prng->randSize;
	unsigned long lenInterVal1XorBlockLen = 0;
	unsigned long lenInterVal2XorInterVal1 = 0;

	byte* pBlock = NULL;
	byte* pInterVal1 = NULL;
	byte* pInterVal2 = NULL;
	byte* pInterVal1XorBlock = NULL;
	byte* pInterVal2XorInterVal1 = NULL;

	byte* pDt = NULL;
	clock_t tick = NULL;
	EVP_CIPHER_CTX cipherCtx;
	const EVP_CIPHER* pEncryptionAlgorithm = NULL;

	if (pSeed != NULL)
	{
		pDt = (byte*)pSeed->pBuffer;
		dtLen = pSeed->bufferLen; 
	}

	pBlock = (byte*)malloc(sizeof(byte) * blockSize);
	TryCatch(pBlock != NULL, r = SS_PRNG_ERROR_OUT_OF_MEMORY, "Allocating new byte array failed.");

	pInterVal1 = (byte*)malloc(sizeof(byte) * blockSize);
	TryCatch(pInterVal1 != NULL, r = SS_PRNG_ERROR_OUT_OF_MEMORY, "Allocating new byte array failed.");

	pInterVal2 = (byte*)malloc(sizeof(byte) * blockSize);
	TryCatch(pInterVal2 != NULL, r = SS_PRNG_ERROR_OUT_OF_MEMORY, "Allocating new byte array failed.");

	pInterVal1XorBlock = (byte*)malloc(sizeof(byte) * blockSize);
	TryCatch(pInterVal1XorBlock != NULL, r = SS_PRNG_ERROR_OUT_OF_MEMORY, "Allocating new byte array failed.");

	pInterVal2XorInterVal1 = (byte*)malloc(sizeof(byte) * blockSize);
	TryCatch(pInterVal2XorInterVal1 != NULL, r = SS_PRNG_ERROR_OUT_OF_MEMORY, "Allocating new byte array failed.");

	lenInterVal1 = blockSize;
	lenInterVal2 = blockSize;
	lenInterVal1XorBlockLen = blockSize;
	lenInterVal2XorInterVal1 = blockSize;

	while (prng->curOffset < randSize)
	{
		blockSize = prng->blockSize;

		if (pDt == NULL)
		{
			time_t sttime = NULL;
			sttime = time(NULL);

			//get D and append with xor of clock tick and random value in buffer till block size is reached
			memcpy(pBlock, (byte*)(&sttime), sizeof(time_t));

			offset += sizeof(time_t);
			tmp = sizeof(clock_t);
			while (offset < blockSize)
			{
				if ((offset + sizeof(clock_t)) > blockSize)
				{
					tmp = blockSize - offset;
				}

				tick = clock();
				PerformXor(pBlock + offset, (byte*)(&tick), tmp, pBlock + offset);
				offset += tmp;
			}
		}
		else
		{
			if (dtLen != blockSize)
			{
				r = SS_PRNG_ERROR_INVALID_ARG;
				SLOGE("The seed length do not match the data block size.");
				goto CATCH;
			}

			memcpy(pBlock, pDt, dtLen);
		}

		// Selects the encryption algorithm using prng.pAlg
		pEncryptionAlgorithm = prng->pAlg;

		//Cipher init operation based on op mode
		ret = EVP_CipherInit(&cipherCtx, pEncryptionAlgorithm, prng->pKey, NULL, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//if padding enabled or not
		ret = EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//cipher update operation
		ret = EVP_CipherUpdate(&cipherCtx, pInterVal1, (int*)(&lenInterVal1), pBlock, blockSize);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		TryCatch(lenInterVal1 == blockSize, r = SS_PRNG_ERROR_INVALID_ARG, "The input and output data lengths do not match.");

		PerformXor(pInterVal1, prng->pSeed, blockSize, pInterVal1XorBlock);
		lenInterVal1XorBlockLen = lenInterVal1;

		//Cipher init operation based on op mode
		ret = EVP_CipherInit(&cipherCtx, pEncryptionAlgorithm, prng->pKey, NULL, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//if padding enabled or not
		ret = EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//cipher update operation
		ret = EVP_CipherUpdate(&cipherCtx, pInterVal2, (int*)(&lenInterVal2), pInterVal1XorBlock, lenInterVal1XorBlockLen);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		TryCatch(lenInterVal2 == blockSize, r = SS_PRNG_ERROR_INVALID_ARG, "The input and output data lengths do not match.");

		PerformXor(pInterVal2, pInterVal1, blockSize, pInterVal2XorInterVal1);
		lenInterVal2XorInterVal1 = blockSize;

		//Cipher init operation based on op mode
		ret = EVP_CipherInit(&cipherCtx, pEncryptionAlgorithm, prng->pKey, NULL, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//if padding enabled or not
		ret = EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM, "An unexpected system error occurred.");

		//cipher update operation
		ret = EVP_CipherUpdate(&cipherCtx, prng->pSeed, (int*)(&(prng->lenSeed)), pInterVal2XorInterVal1, lenInterVal2XorInterVal1);
		TryCatch(ret == 1, r = SS_PRNG_ERROR_SYSTEM,"An unexpected system error occurred.");

		TryCatch(prng->lenSeed == blockSize, r = SS_PRNG_ERROR_INVALID_ARG, "The input and output data lengths do not match.");

		if ((prng->curOffset + lenInterVal2) > prng->randSize)
		{
			lenInterVal2 = prng->randSize - prng->curOffset;
		}

		memcpy(prng->pRand + prng->curOffset, pInterVal2, lenInterVal2);
		prng->curOffset += lenInterVal2;
	}

CATCH:
	free(pBlock);
	free(pInterVal1);
	free(pInterVal2);
	free(pInterVal1XorBlock);
	free(pInterVal2XorInterVal1);
	EVP_CIPHER_CTX_cleanup(&cipherCtx);

	return r;
}

PrngContext* CreatePrngContextN(void)
{
	PrngContext* pPrng = NULL;
	
	pPrng =(PrngContext*)malloc(sizeof(PrngContext));
	if(!pPrng)
	{
		SLOGE("Allocating new PrngContext object failed.");
		return NULL;
	}
	memset(pPrng, 0, sizeof(PrngContext));

	return pPrng;
}

