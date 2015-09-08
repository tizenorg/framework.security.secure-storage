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
 *	@file	ss_prng.h
 *	@brief	This header file contains declarations of Pseudo Random Function based on ANSI X9.31 Appendix A.2.4.
 */

/**
 *  Generate random numbers as per X9.31 specification using algorithm passed as input.
 */

#ifndef __SS_PRNG__
#define __SS_PRNG__

#define LOG_TAG "SECURE_STORAGE"
struct evp_cipher_st;


#define SS_PRNG_SUCCESS 0
#define SS_PRNG_ERROR_INVALID_ARG -1
#define SS_PRNG_ERROR_OUT_OF_MEMORY -2
#define SS_PRNG_ERROR_SYSTEM -3


#define TryCatch(condition, expr, ...) \
		if (!(condition)) { \
			SLOGE(__VA_ARGS__); \
			expr; \
			goto CATCH; \
		} \
		else {;}

/**
 * Generate random numbers as per X9.31 specification using algorithm passed as input.
 *
 * @return		Returns pointer to byte buffer containing generated random number.
 * @param[in]	pAlg	Pointer to algorithm used for random number generation. Supports EVP_des_ecb(), EVP_des_ede3_ecb() and EVP_AES_128_ecb().
 * @param[in]   requiredLength  Integer type indicating required size of random number.
 */
unsigned char* GetRandomBytesN(struct evp_cipher_st* pAlg, long requiredLength);

#endif
