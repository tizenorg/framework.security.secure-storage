/*
 * secure storage
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "secure_storage.h"
#include "ss_client_intf.h"

#ifndef SS_API
#define SS_API __attribute__((visibility("default")))
#endif
SS_API
int ssa_put(const char* pDataName, const char* pDataBlock, size_t inDataBlockLen, const char* pGroupId, const char* pPassword)
{
	int ret = 0;

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pDataName || !pDataBlock)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(inDataBlockLen <= 0 || inDataBlockLen > MAX_SEND_DATA_SIZE)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = SsClientPutData(pDataName, pDataBlock, inDataBlockLen, pGroupId, pPassword);

	return ret;
}

SS_API
int ssa_get(const char* pDataName, char** ppOutDataBlock, const char* pGroupId, const char* pPassword)
{
	int ret = 0;

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pDataName)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = SsClientGetData(pDataName, ppOutDataBlock, pGroupId, pPassword);
	return ret;	
}


SS_API
int ssa_delete(const char* pDataName, const char* pGroupId)
{
	int ret = 0;

	if(!pDataName)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = SsClientDeleteData(pDataName, pGroupId);

	return ret;
}

SS_API
int ssa_encrypt(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword)
{
	int ret = 0;
	int outLen = 0;
	char* pKey = "0123456789abcdef0123456789abcdef"; // to be changed

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pInDataBlock || inDataBlockLen == 0 || inDataBlockLen > MAX_SEND_DATA_SIZE)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = DoCipher(pInDataBlock, inDataBlockLen, ppOutDataBlock, &outLen, pKey, pKey, 1); // iv have to changed
	if(ret != 1)
	{		
		return SSA_CIPHER_ERROR;
	}

	return outLen;
}


SS_API
int ssa_decrypt(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword)
{
	int ret = 0;
	int outLen = 0;
	char* pKey = "0123456789abcdef0123456789abcdef";  // to be changed

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pInDataBlock || inDataBlockLen == 0)
	{
		LOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = DoCipher(pInDataBlock, inDataBlockLen, ppOutDataBlock, &outLen, pKey, pKey, 0); // iv have to changed
	if(ret != 1)
	{		
		return SSA_CIPHER_ERROR;
	}

	return outLen;
}

SS_API
int ssa_encrypt_web_application(const char* pAppId, int idLen, const char* pData, int dataLen, char** ppEncryptedData, int isPreloaded)
{
	int result = 0;

	if(!pData || dataLen ==0 || !pAppId || idLen == 0)
	{
		LOGE("Parameter error");
		return  SSA_PARAM_ERROR;
	}

	result = SsEncryptWebApplication(pAppId, idLen, pData, dataLen, ppEncryptedData, isPreloaded);
	SECURE_LOGD("result = %d", result);

	return result;
}


SS_API
int ssa_decrypt_web_application(const char* pData, int dataLen, char** ppDecryptedData, int isPreloaded)
{
	int result = 0;

	if(!pData || dataLen == 0)
	{
		if(pData == NULL)
			LOGE("pData is null");
		else
			LOGE("dataLen is null [%d]", dataLen);

		LOGE("Parameter error");
		return  SSA_PARAM_ERROR;
	}

	result = SsDecryptWebApplication(pData, dataLen, ppDecryptedData, isPreloaded);
	SECURE_LOGD("result = %d", result);

	return result;
}
