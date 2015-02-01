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

/*****************************************************************************
 * Internal Functions
 *****************************************************************************/
SS_API
int ssm_getinfo(const char* pFilePath, ssm_file_info_t *sfi, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath || !sfi)
	{
		SLOGE("Parameter error in ssm_getinfo()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	ret = SsClientGetInfo(pFilePath, sfi, flag, group_id);

	if(ret == 1)
	{
		SLOGI("Getinfo Success.\n");
		ret = 0;	// return true
	}
	else
		SLOGE("Getinfo Fail.\n");

Error:
	return ret;
}

/*****************************************************************************
 * Manager APIs
 *****************************************************************************/
SS_API
int ssm_write_file(const char* pFilePath, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath)
	{
		SLOGE("Parameter error in ssm_write_file()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	if(flag <= SSM_FLAG_NONE || flag >= SSM_FLAG_MAX)
	{
		SLOGE("Parameter error in ssm_write_file()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	ret = SsClientDataStoreFromFile(pFilePath, flag, group_id);
	if(ret == 1)
	{
		if(unlink(pFilePath) != 0)	// if fail
		{
			SLOGE("unlink fail. [%s]\n", pFilePath);
			return -1;	// return false
		}
		SLOGI("Write file Success.\n");
		return 0;	// return true
	}
	else
		SLOGE("Write file Fail.\n");
	
Error:
	return ret;
}

SS_API
int ssm_write_buffer(char* pWriteBuffer, size_t bufLen, const char* pFileName, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pWriteBuffer || !pFileName)
	{
		SLOGE("Parameter error in ssm_write_buffer()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(bufLen <= 0 || bufLen > 4096)
	{
		SLOGE("Parameter error in ssm_write_buffer()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(flag <= SSM_FLAG_NONE || flag >= SSM_FLAG_MAX)
	{
		SLOGE("Parameter error in ssm_write_buffer()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDataStoreFromBuffer(pWriteBuffer, bufLen, pFileName, flag, group_id);
	if(ret == 1)
	{
		SLOGI("Write buffer Success.\n");
		return 0;	// return true
	}
	else
		SLOGE("Write buffer Fail.\n");

Error:	
	return ret;
}

SS_API
int ssm_read(const char* pFilePath, char* pRetBuf, size_t bufLen, size_t *readLen, ssm_flag flag, const char* group_id)
{
	int ret = 0;
	ssm_file_info_t sfi;

	if(!pFilePath || !pRetBuf)
	{
		SLOGE("Parameter error in ssm_read()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(!readLen)
	{
		SLOGE("Parameter error in ssm_read()...\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	// get info 
	ret = ssm_getinfo(pFilePath, &sfi, flag, group_id);
	if(ret != 0)	// ret != true?
	{
		SLOGE("getinfo error in ssm_read()..\n");
		goto Error;
	}
	// in case of flag mismatch...
	// check flag...
	// To do :
	if((bufLen > sfi.originSize) || (sfi.reserved[0] != (flag & 0x000000ff)))
	{
		SLOGE("Flag mismatch or buffer length error in ssm_read()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDataRead(pFilePath, pRetBuf, sfi.originSize, readLen, flag, group_id);

	if(ret == 1)
	{
		SLOGI("Read Success.\n");
		return 0;	// return true
	}
	else
		SLOGE("Read Fail.\n");

Error:
	return ret;
}

SS_API
int ssm_delete_file(const char *pFilePath, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath)
	{
		SLOGE("Parameter error in ssm_delete_file()..\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDeleteFile(pFilePath, flag, group_id);

	if(ret == 1)	// success
	{
		SLOGI("Delete file Success.\n");
		return 0;
	}
	else	// fail
		SLOGE("Delete file Fail.\n");

Error:
	return ret;
}

SS_API
int ssm_encrypt_application(const char* pAppId, int idLen, const char* pBuffer, int bufLen, char** pEncryptedBuffer, int* pEncryptedBufLen)
{
	int ret = 0;

	if(!pBuffer || bufLen ==0 || !pAppId || idLen == 0 || idLen+1 > MAX_GROUP_ID_SIZE)
	{
		SLOGE("Parameter error.\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientEncryptApplication(pAppId, idLen, pBuffer, bufLen, pEncryptedBuffer, pEncryptedBufLen);

	if(ret == 1)	// success
	{
		SLOGI("Application encryption succeeded.\n");
		return 0;
	}
	else	// fail
		SLOGE("Application encryption failed.\n");

Error:
	return ret;
}

SS_API
int ssm_decrypt_application(const char* pBuffer, int bufLen, char** pDecryptedBuffer, int* pDecryptedBufLen)
{
	int ret = 0;

	if(!pBuffer || bufLen ==0)
	{
		SLOGE("Parameter error.\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDecryptApplication(pBuffer, bufLen, pDecryptedBuffer, pDecryptedBufLen);

	if(ret == 1)	// success
	{
		SLOGI("Application decryption succeeded.\n");
		return 0;
	}
	else	// fail
		SLOGE("Application decryption failed.\n");

Error:
	return ret;
}

SS_API
int ssm_encrypt_preloaded_application(const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen)
{
	int ret = 0;
	
	if(!pBuffer || bufLen ==0)
	{
		SLOGE("Parameter error.\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientEncryptPreloadedApplication(pBuffer, bufLen, ppEncryptedBuffer, pEncryptedBufLen);
	if(ret == 1)	// success
	{
		SLOGI("Application decryption succeeded.\n");
		return 0;
	}
	else	// fail
		SLOGE("Application decryption failed.\n");

Error:
	return ret;
}

SS_API
int ssm_decrypt_preloaded_application(const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pDecryptedBufLen)
{
	int ret = 0;

	if(!pBuffer || bufLen ==0)
	{
		SLOGE("Parameter error.\n");
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDecryptPreloadedApplication(pBuffer, bufLen, ppDecryptedBuffer, pDecryptedBufLen);
	if(ret == 1)	// success
	{
		SLOGI("Application decryption succeeded.\n");
		return 0;
	}
	else	// fail
		SLOGE("Application decryption failed.\n");

Error:
	return ret;
}


//////////////
//agent
/////////////
//
//

int ConvertErrorCode(int error)
{
	int convertedError = 0;

	switch(error)
	{
		case SS_FILE_OPEN_ERROR:
		case SS_PARAM_ERROR:
			convertedError = SSA_PARAM_ERROR;
			break;
		case SS_FILE_TYPE_ERROR:
		case SS_FILE_READ_ERROR:
		case SS_FILE_WRITE_ERROR:
			convertedError = SSA_IO_ERROR;
			break;
		case SS_MEMORY_ERROR:
			convertedError = SSA_UNKNOWN_ERROR;
			break;
		case SS_SOCKET_ERROR:
			convertedError = SSA_SOCKET_ERROR;
			break;
		case SS_ENCRYPTION_ERROR:
		case SS_DECRYPTION_ERROR:
			convertedError = SSA_CIPHER_ERROR;
			break;
		case SS_SIZE_ERROR:
			convertedError = SSA_UNKNOWN_ERROR;
			break;
		case SS_SECURE_STORAGE_ERROR:
			convertedError = SSA_TZ_ERROR;
			break;
		case SS_PERMISSION_DENIED:
			convertedError = SSA_PERMISSION_ERROR;
			break;
		case SS_TZ_ERROR:
			convertedError = SSA_TZ_ERROR;
			break;
		default:
			convertedError = SSA_UNKNOWN_ERROR;
			break;
	}

	SLOGE("error code = %d", convertedError);

	return convertedError;
}


SS_API
int ssa_put(const char* pDataName, const char* pDataBlock, size_t inDataBlockLen, const char* pGroupId, const char* pPassword)
{
	int ret = 0;

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pDataName || !pDataBlock)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(inDataBlockLen <= 0 || inDataBlockLen > MAX_SEND_DATA_SIZE)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = ssm_write_buffer(pDataBlock, inDataBlockLen, pDataName, SSM_FLAG_SECRET_OPERATION, pGroupId); 

	if(ret != 0)
	{
		ret = ConvertErrorCode(ret);
		return ret;
	}

	return inDataBlockLen;
}

SS_API
int ssa_get(const char* pDataName, char** ppOutDataBlock, const char* pGroupId, const char* pPassword)
{
	ssm_file_info_t info;
	size_t readLen = 0;
	int ret = 0;

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pDataName)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret  = ssm_getinfo(pDataName, &info, SSM_FLAG_SECRET_OPERATION, pGroupId);
	if(ret != 0)
	{
		ret = ConvertErrorCode(ret);
		return ret;
	}

	*ppOutDataBlock = (char*)malloc(sizeof(char)*(info.originSize+1));
	memset(*ppOutDataBlock, 0, info.originSize+1);

	ret = ssm_read(pDataName, *ppOutDataBlock, info.originSize, &readLen, SSM_FLAG_SECRET_OPERATION, pGroupId);
	if(ret != 0)
	{
		ret = ConvertErrorCode(ret);
		free(*ppOutDataBlock);
		return ret;
	}

	return (int)readLen;
}


SS_API
int ssa_delete(const char* pDataName, const char* pGroupId)
{
	int ret = 0;

	if(!pDataName)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = ssm_delete_file(pDataName, SSM_FLAG_SECRET_OPERATION, pGroupId);
	if(ret != 0)
	{
		ret = ConvertErrorCode(ret);
	}

	return ret;
}

SS_API
int ssa_encrypt(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword)
{
	int ret = 0;
	int outLen = 0;
	char* pKey = "0123456789abcdef0123456789abcdef";

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pInDataBlock || inDataBlockLen == 0 || inDataBlockLen > MAX_SEND_DATA_SIZE)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = DoCipher(pInDataBlock, inDataBlockLen, ppOutDataBlock, &outLen, pKey, 1);
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
	char* pKey = "0123456789abcdef0123456789abcdef";

	if(pPassword && (strlen(pPassword) > MAX_PASSWORD_SIZE))
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	if(!pInDataBlock || inDataBlockLen == 0)
	{
		SLOGE("Invalid input argument.");
		return  SSA_PARAM_ERROR;
	}

	ret = DoCipher(pInDataBlock, inDataBlockLen, ppOutDataBlock, &outLen, pKey, 0);
	if(ret != 1)
	{		
		return SSA_CIPHER_ERROR;
	}

	return outLen;
}

SS_API
int ssa_encrypt_web_application(const char* pAppId, int idLen, const char* pData, int dataLen, char** ppEncryptedData, int isPreloaded)
{
	int ret = 0;
	int outLen = 0;

	if(isPreloaded)
	{
		ret = ssm_encrypt_preloaded_application(pData, dataLen, ppEncryptedData, &outLen);
		if(ret != 0)
		{
			ret = ConvertErrorCode(ret);
			return ret;
		}

		return outLen;
	}

	else
	{
		ret = ssm_encrypt_application(pAppId, idLen, pData, dataLen, ppEncryptedData, &outLen);
		if(ret != 0)
		{
			ret = ConvertErrorCode(ret);
			return ret;
		}

		return outLen;
	}
}


SS_API
int ssa_decrypt_web_application(const char* pData, int dataLen, char** ppDecryptedData, int isPreloaded)
{
	int ret = 0;
	int outLen = 0;

	if(isPreloaded)
	{
		ret = ssm_decrypt_preloaded_application(pData, dataLen, ppDecryptedData, &outLen);
		if(ret != 0)
		{
			ret = ConvertErrorCode(ret);
			return ret;
		}

		return outLen;
	}

	else
	{
		ret = ssm_decrypt_application(pData, dataLen, ppDecryptedData, &outLen);
		if(ret != 0)
		{
			ret = ConvertErrorCode(ret);
			return ret;
		}

		return outLen;
	}
}
