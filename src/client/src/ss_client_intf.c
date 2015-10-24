/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "secure_storage.h"
#include "ss_client_intf.h"
#include "ss_client_ipc.h"
#include "ss_manager.h"

void printData(const char* pLogName, const char* pData, int dataLen)
{
#ifdef PRINT_DEBUG_DATA
	int i=0;
	int j=0;
	int count=0;

	SECURE_LOGD("========== %s, Lengh=%d ==========", pLogName, dataLen);
	if(dataLen % 4 == 0)
		count = dataLen/4;
	else
		count = dataLen/4+1;

	for(i=j=0; j<count; i=i+4, j++)
		SECURE_LOGD("[%d]= %02x [%d]=%02x [%d]=%02x [%d]=%02x", i, pData[i], i+1, pData[i+1], i+2, pData[i+2], i+3, pData[i+3]);
	SECURE_LOGD("========================", pLogName);
#else
    (void) pLogName;
    (void) pData;
    (void) dataLen;
#endif
}

void InitializeReqData(RequestData* pData)
{
	memset(pData->dataName, 0, MAX_FILENAME_SIZE+1);
	memset(pData->dataBlock, 0, MAX_SEND_DATA_SIZE);
	memset(pData->groupId, 0, MAX_GROUP_ID_SIZE+1);
	memset(pData->password, 0, MAX_PASSWORD_SIZE+1);
	pData->enablePassword = 0;
}

RequestData* SetRequestData(int reqType, const char* pDataName, const char* pData, int dataLen, const char* pGroupId, const char* pPassword, int encryptionMode)
{
	RequestData* pReqData = (RequestData*)malloc(sizeof(RequestData));
    if (!pReqData) {
        LOGE("Failed to allocate memory for RequestData");
        return NULL;
    }

	InitializeReqData(pReqData);

	pReqData->reqType = reqType;
	pReqData->dataBlockLen = dataLen;
	pReqData->encryptionMode = encryptionMode;

	if(pDataName)
	{
		if(strlen(pDataName) > MAX_FILENAME_SIZE)
		{
			LOGE("The data name is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->dataName, pDataName, MAX_FILENAME_SIZE);
		pReqData->dataName[strlen(pDataName)] = '\0';
	}

	if(dataLen != 0)
	{
		if(dataLen > MAX_SEND_DATA_SIZE)
		{
			LOGE("The data length is too long [%d]", dataLen);
			free(pReqData);
			return NULL;
		}
		memcpy(pReqData->dataBlock, pData, dataLen);
	}

	if(pGroupId != 0)
	{
		if(strlen(pGroupId) > MAX_GROUP_ID_SIZE)
		{
			LOGE("The group_id length is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->groupId, pGroupId, MAX_GROUP_ID_SIZE);
		pReqData->groupId[strlen(pGroupId)] = '\0';
	}
	else
	{
		strncpy(pReqData->groupId, "NOTUSED", MAX_GROUP_ID_SIZE);
	}

	if(pPassword != NULL)
	{
		if(strlen(pPassword) > MAX_PASSWORD_SIZE)
		{
			LOGE("The password is too long");
			free(pReqData);
			return NULL;
		}
		pReqData->enablePassword = 1;
		strncpy(pReqData->password, pPassword, MAX_PASSWORD_SIZE);
		pReqData->password[strlen(pPassword)] = '\0';
	}

	return pReqData;
}

//////////////////////////////
__attribute__((visibility("hidden")))
int DoCipher(const char* pInputBuf, int inputLen, char** ppOutBuf, int* pOutBufLen, char* pKey, char* iv, int encryption)
{
    struct evp_cipher_st* pCipherAlgorithm = NULL;
    EVP_CIPHER_CTX cipherCtx;
    int tempLen = 0;
    int result = 0;
    int finalLen = 0;

	printData("DoCipher key", pKey, 16);
	printData("DoCipher iv", iv, 16);
	printData("DoCipehr inData", pInputBuf, inputLen);

    pCipherAlgorithm = (struct evp_cipher_st*)EVP_aes_128_cbc();
    tempLen =  (int)((inputLen / pCipherAlgorithm->block_size + 1) * pCipherAlgorithm->block_size);

    *ppOutBuf = (char*)calloc(tempLen, 1);
    EVP_CIPHER_CTX_init(&cipherCtx);

    result = EVP_CipherInit(
            &cipherCtx,
            pCipherAlgorithm,
            (const unsigned char*)pKey,
            (const unsigned char *)iv,
            encryption);

    if(result != 1)
    {
        LOGE("[%d] EVP_CipherInit failed", result);
        goto Error;
    }

    result = EVP_CIPHER_CTX_set_padding(&cipherCtx, 1);
    if(result != 1)
    {
        LOGE("[%d] EVP_CIPHER_CTX_set_padding failed", result);
        goto Error;
    }

    //cipher update operation
    result = EVP_CipherUpdate(&cipherCtx, (unsigned char*)*ppOutBuf, pOutBufLen, (const unsigned char*)pInputBuf, inputLen);
    if(result != 1)
    {
        LOGE("[%d] EVP_CipherUpdate failed", result);
        goto Error;
    }

	//cipher final operation
    result = EVP_CipherFinal(&cipherCtx, (unsigned char*)*ppOutBuf + *pOutBufLen, &finalLen);
    if(result != 1)
    {
        LOGE("[%d] EVP_CipherFinal failed", result);
        goto Error;
    }
    *pOutBufLen = *pOutBufLen + finalLen;

	printData("DoCipehr outData", (*ppOutBuf), *pOutBufLen);

    goto Last;
Error:
    result = SSA_CIPHER_ERROR;
    free(*ppOutBuf);

Last:
    EVP_CIPHER_CTX_cleanup(&cipherCtx);
    if((result != 1) && (encryption != 1))
        result = SSA_CIPHER_ERROR;

    return result;
}

char* GetSalt(void)
{
    FILE* pFile = NULL;

    if((pFile = fopen(SALT_PATH, "r")))
    {   
        char* pSalt = NULL;
        int readLen = 0;
             
        pSalt = (char*)calloc(SALT_SIZE, 1); 
        if (!pSalt) {
            LOGE("Failed to allocate memory for salt");
            fclose(pFile);
            return NULL;
        }

        readLen = fread(pSalt, 1, SALT_SIZE, pFile);

        if(readLen != SALT_SIZE)
        {   
            LOGE("[real data size: %d] failed to read random code....", readLen);
            fclose(pFile);
            free(pSalt);
            return NULL;
        }   
        fclose(pFile);
        return pSalt;
    }   

    return NULL;
}

int GenerateRandomIndex(void)
{
    srandom(time(NULL));

    return random() % SALT_SIZE;
}

void SelectSalt(char* pSalt, int index, char* pSelectedSalt)
{
    if(index <= SALT_SIZE - KEY_SIZE)
        memcpy(pSelectedSalt, pSalt + index, KEY_SIZE);
    else
    {
        int first = 0;
        int last = 0;

        first = SALT_SIZE - index;
        last =  KEY_SIZE - first;
        memcpy(pSelectedSalt, pSalt + index, first);
        memcpy(pSelectedSalt + first, pSalt, last);
    }
}

int GetIv(char* pSrc, char* pIv, int srcLen)
{
	size_t outLen = 0;
	if (EVP_Digest(pSrc, srcLen, (unsigned char *)pIv, &outLen, EVP_sha1(), NULL) != 1) {
		LOGE("Failed to get iv");
		return 0;
	}

	return 1;
}

char* GenerateMasterKey(const char* pAppId, int idLen, const char* pSalt)
{
    char* pMasterKey = NULL;

    SECURE_LOGD("applicaton id[= %s] to generate master key", pAppId);
    
    pMasterKey = (char*)calloc(1, KEY_SIZE * 2);
    PKCS5_PBKDF2_HMAC_SHA1(pAppId, idLen, (const unsigned char*)pSalt, KEY_SIZE, 10, KEY_SIZE * 2, (unsigned char*)pMasterKey);

    return pMasterKey;
}

int SsClientEncryptPreloadedApplication(const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen)
{
	int result = 0;
	char duk[36] = {0,};
	char iv[SHA_DIGEST_LENGTH] = {0,};
	
	if(!pBuffer || bufLen ==0)
	{
		LOGE("Parameter error");
		result  = SSA_PARAM_ERROR;
		goto Final;
	}

	if(DoCipher(pBuffer, bufLen, ppEncryptedBuffer, pEncryptedBufLen, duk, iv, 1) != 1)
	{
		LOGE("failed to decrypt data");
		result  = SSA_CIPHER_ERROR;
		goto Final;
	}
	
	result = 1;

Final:
	return result;
}

int SsClientDecryptPreloadedApplication(const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pDecryptedBufLen)
{
	int result = 0;
	char duk[36] = {0,};
	char iv[SHA_DIGEST_LENGTH] = {0,};
	
	if(!pBuffer || bufLen ==0)
	{
		LOGE("Parameter error");
		result  = SSA_PARAM_ERROR;
		goto Final;
	}

	if(DoCipher(pBuffer, bufLen, ppDecryptedBuffer, pDecryptedBufLen, duk, iv, 0) != 1)
	{
		LOGE("failed to decrypt data");
		result  = SSA_CIPHER_ERROR;
		goto Final;
	}
	
	result = 1;

Final:
	return result;
}


int SsClientPutData(const char* pInDataName, const char* pInDataBlock, size_t inDataBlockLen, const char* pGroupId, const char* pPassword)
{
	LOGD("SsClientPutData");
	RequestData* pSendData = NULL;
	ResponseData recvData = {0, };

	pSendData = SetRequestData(PUT_DATA, pInDataName, pInDataBlock, inDataBlockLen, pGroupId, pPassword, 0);

	if(pSendData == NULL)
	{
		LOGE("Failed to set request data");
		return SSA_PARAM_ERROR;
	}

	recvData = SsClientComm(pSendData);
	if(recvData.result  < 0)
	{
		LOGE("An error occurred from server side err:[%d]", recvData.result);
		free(pSendData);
		return recvData.result;
	}

	free(pSendData);

	return recvData.result;
}

int SsClientGetData(const char* pOutDataName, char** ppOutDataBlock, const char* pGroupId, const char* pPassword)
{
	LOGD("SsClientGetData");
	RequestData* pSendData = NULL;
	ResponseData recvData;

	pSendData = SetRequestData(GET_DATA, pOutDataName, NULL, 0, pGroupId, pPassword, 0);
	if(pSendData == NULL)
	{
		LOGE("Failed to set request data");
		return SSA_PARAM_ERROR;
	}

	recvData = SsClientComm(pSendData);
	if(recvData.result < 0)
	{
		LOGE("An error occurred from server side err[%d]", recvData.result);
		free(pSendData);
		return recvData.result;
	}

	free(pSendData);

	if(recvData.dataBlockLen > 0 && recvData.dataBlockLen <= MAX_RECV_DATA_SIZE)
	{
		*ppOutDataBlock = (char*)malloc(recvData.dataBlockLen);
        if (!(*ppOutDataBlock)) {
            LOGE("Failed to allocate memory for OutDataBlock");
            return SSA_OUT_OF_MEMORY;
        }
		memcpy(*ppOutDataBlock, recvData.dataBlock, recvData.dataBlockLen);
	}
	else
	{
		LOGE("revcData length is wrong : %d", recvData.dataBlockLen);
		return SSA_PARAM_ERROR;
	}

	return recvData.result;
}

int SsClientDeleteData(const char* pDataName, const char* pGroupId)
{
	LOGD("SsClientDeleteData");
	RequestData* pSendData = NULL;
	ResponseData recvData;

	pSendData = SetRequestData(DELETE_DATA, pDataName, NULL, 0, pGroupId, NULL, 0);
	if(pSendData == NULL)
	{
		LOGE("Failed to set request data");
		return SSA_PARAM_ERROR;
	}

	recvData = SsClientComm(pSendData);

	free(pSendData);

	return recvData.result;
}

int SsClientEncryptData(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword)
{
	RequestData* pSendData = NULL;
	ResponseData recvData = {0,};

	pSendData = SetRequestData(ENCRYPT_DATA, NULL, pInDataBlock, inDataBlockLen, NULL, pPassword, 0);
	if(pSendData == NULL)
	{
		LOGE("Failed to set request data");
		return SSA_PARAM_ERROR;
	}

	recvData = SsClientComm(pSendData);
    free(pSendData);

	if(recvData.dataBlockLen < 0)
	{
		LOGE("An error occurred from server side : %d", recvData.dataBlockLen);
		return recvData.result;
	}
	else if(recvData.dataBlockLen > MAX_RECV_DATA_SIZE)
	{
		LOGE("dataBlockLength is wrong : %d", recvData.dataBlockLen);
		return SSA_PARAM_ERROR;
	}

	*ppOutDataBlock = (char*)malloc(recvData.dataBlockLen);
    if (!(*ppOutDataBlock)) {
        LOGE("Failed to allocate memory for OutDataBlock");
        return SSA_OUT_OF_MEMORY;
    }
	memcpy(*ppOutDataBlock, recvData.dataBlock, recvData.dataBlockLen);

	return recvData.result;
}

int SsClientDecryptData(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword)
{
	RequestData* pSendData = NULL;
	ResponseData recvData;

	pSendData = SetRequestData(DECRYPT_DATA, NULL, pInDataBlock, inDataBlockLen, NULL, pPassword, 0);
	if(pSendData == NULL)
	{
		LOGE("Failed to set request data");
		return SSA_PARAM_ERROR;
	}

	recvData = SsClientComm(pSendData);
    free(pSendData);

	if(recvData.dataBlockLen < 0)
	{
		LOGE("An error occurred from server side err[%d]", recvData.dataBlockLen);
		return recvData.result;
	}
	else if(recvData.dataBlockLen > MAX_RECV_DATA_SIZE)
	{
		LOGE("dataBlockLength is wrong : %d", recvData.dataBlockLen);
		return SSA_PARAM_ERROR;
	}

	*ppOutDataBlock = (char*)malloc(recvData.dataBlockLen);
    if (!(*ppOutDataBlock)) {
        LOGE("Failed to allocate memory for OutDataBlock");
        return SSA_OUT_OF_MEMORY;
    }
	memcpy(*ppOutDataBlock, recvData.dataBlock, recvData.dataBlockLen);

	return recvData.result;
}


int SsEncryptPreloadedWebApplication(const char*pAppId, int idLen, const char* pData, int dataLen, char**ppEncryptedData)
{
	RequestData* pSendData= NULL;
	ResponseData recvData;
	static char salt[SALT_SIZE] = {0,};
	static int saltExist = 0;
	char selectedSalt[KEY_SIZE] = {0,};
	char iv[SHA_DIGEST_LENGTH] = {0,};
	char* pSaltData = NULL;
	char* pKey = NULL;
	char* pTempBuffer = NULL;
	int index = 0;
	int tempBufLen = 0;

	pSaltData = GetSalt();

	if(pSaltData == NULL)
	{
		if(!saltExist)
		{
			pSendData = SetRequestData(GET_SALT, NULL, NULL, 0, NULL, NULL, 1);
			if(pSendData == NULL)
			{
				LOGE("Failed to set request data");
				return SSA_PARAM_ERROR;
			}

			recvData = SsClientComm(pSendData);
			if(recvData.result <= 0)
			{
				LOGE("An error occurred from server side err[%d]", recvData.result);
				free(pSendData);
				return recvData.result;
			}
			free(pSendData);
			memcpy(salt, recvData.dataBlock, SALT_SIZE);
			saltExist = 1;
		}
	}

	else
	{
		memcpy(salt, pSaltData, SALT_SIZE);
		free(pSaltData);
	}

	index = GenerateRandomIndex();
	SelectSalt(salt, index, selectedSalt);
	printData("EncryptPreloadedWebApp salt", selectedSalt, 16);

	SECURE_LOGD("appId= %s, len = %d", pAppId, idLen);

	pKey = GenerateMasterKey(pAppId, idLen, selectedSalt);
	if(pKey!=NULL)
	{
		int res = GetIv(pKey, iv, KEY_SIZE);
		if(res != 1)
		{
			free(pKey);
			return SSA_CIPHER_ERROR;
		}
	}
	else
	{
		LOGE("failed to get key");
		return SSA_CIPHER_ERROR;
	}

	if(DoCipher(pData, dataLen, &pTempBuffer, &tempBufLen, pKey, iv, 1) != 1)
   	{
   		LOGE("failed to encrypt data");
 		free(pKey);
		return SSA_CIPHER_ERROR;
  	}

   	*ppEncryptedData = (char*)calloc(tempBufLen + sizeof(int), 1);
    if (!(*ppEncryptedData)) {
        LOGE("failed to allocate memory for EncryptedData");
        free(pTempBuffer);
        return SSA_OUT_OF_MEMORY;
    }
   	memcpy(*ppEncryptedData, &index, sizeof(int));
   	memcpy(*ppEncryptedData + sizeof(int), pTempBuffer, tempBufLen);
   	free(pTempBuffer);
    free(pKey);

	return tempBufLen + sizeof(int);
}

int SsEncryptWebApplication(const char* pAppId, int idLen, const char* pData, int dataLen, char** ppEncryptedData, int isPreloaded)
{
	if(isPreloaded)
	{
		return SsEncryptPreloadedWebApplication(pAppId, idLen, pData, dataLen, ppEncryptedData);
	}

	else
	{
		RequestData* pSendData= NULL;
		ResponseData recvData;
		static char duk[KEY_SIZE] = {0,};
		static int dukExist = 0;
		int encryptedLen = 0;
		char iv[SHA_DIGEST_LENGTH] = {0,};

		LOGD("downloaded application, appId = %s", pAppId);
		if(!dukExist)
		{
			pSendData = SetRequestData(GET_DUK, NULL, pAppId, idLen, NULL, NULL, 1);
			if(pSendData == NULL)
			{
				LOGE("Failed to set request data");
				return SSA_PARAM_ERROR;
			}

			recvData = SsClientComm(pSendData);
			if(recvData.result <= 0)
			{
				LOGE("An error occurred from server side err:[%d]", recvData.result);
				free(pSendData);
				return recvData.result;
			}

			free(pSendData);
			memcpy(duk, recvData.dataBlock, KEY_SIZE);
			dukExist = 1;
		}

		int res = GetIv(duk, iv, KEY_SIZE);
		if(res != 1)
		{
			return SSA_CIPHER_ERROR;
		}

		if(DoCipher(pData, dataLen, ppEncryptedData, &encryptedLen, duk, iv, 1) != 1)
	   	{
   			LOGE("failed to encrypt data");
			return SSA_CIPHER_ERROR;
  		}
		return encryptedLen;
	}
}


int SsDecryptPreloadedWebApplication(const char* pData, int dataLen, char** ppDecryptedData)
{
	RequestData* pSendData= NULL;
	ResponseData recvData;
	int index = 0;
	int tempBufLen = 0;
	char selectedSalt[KEY_SIZE] = {0,};
	static char appId[MAX_APPID_SIZE] = {0,};
	static char salt[SALT_SIZE] = {0,};
	static int saltExist = 0;
	char* pKey = NULL;
	char iv[SHA_DIGEST_LENGTH] = {0,};

	if(!saltExist)
	{
		pSendData = SetRequestData(GET_SALT, NULL, NULL, 0, NULL, NULL, 0);
		if(pSendData == NULL)
		{
			LOGE("Failed to set request data");
			return SSA_PARAM_ERROR;
		}

		recvData = SsClientComm(pSendData);
		if(recvData.result <= 0)
		{
			LOGE("An error occurred from server side err[%d]", recvData.result);
			free(pSendData);
			return recvData.result;
		}
		free(pSendData);
		memcpy(appId, recvData.dataBlock, MAX_APPID_SIZE);
		memcpy(salt, recvData.dataBlock + MAX_APPID_SIZE, SALT_SIZE);
		LOGD("preloaded appId = %s", appId);

		saltExist = 1;
	}
	memcpy(&index, pData, sizeof(int));
	SECURE_LOGD("index = %d", index);

	if(index >= SALT_SIZE)
	{
		LOGE("Invalid input prameter");
		return SSA_PARAM_ERROR;
	}

	SelectSalt(salt, index, selectedSalt);
	printData("DecryptPreloadedWebApp salt", selectedSalt, 16);
	SECURE_LOGD("appId= %s, len = %d", appId, strlen(appId));
	pKey = GenerateMasterKey(appId, strlen(appId), selectedSalt);
	if(pKey!=NULL)
	{
		int res = GetIv(pKey, iv, KEY_SIZE);
		if(res != 1)
		{
			free(pKey);
			return SSA_CIPHER_ERROR;
		}
	}
	else
	{
		LOGE("failed to get key");
		return SSA_CIPHER_ERROR;
	}

	if(DoCipher(pData+sizeof(int), dataLen-sizeof(int), ppDecryptedData, &tempBufLen, pKey, iv, 0) != 1)
   	{
   		LOGE("failed to decrypt data");
 		free(pKey);
		return SSA_CIPHER_ERROR;
  	}
	return tempBufLen;
}


int SsDecryptWebApplication(const char* pData, int dataLen, char** ppDecryptedData, int isPreloaded)
{
	if(isPreloaded)
	{
		LOGD("preloaded application");
		return SsDecryptPreloadedWebApplication(pData, dataLen, ppDecryptedData);
	}

	else
	{
		RequestData* pSendData = NULL;
		ResponseData recvData;
		static char duk[KEY_SIZE] = {0,};
		static int dukExist = 0;
		int decryptedLen = 0 ;
		char iv[SHA_DIGEST_LENGTH] = {0,};

		LOGD("downloaded application");
		if(!dukExist)
		{
			pSendData = SetRequestData(GET_DUK, NULL, NULL, 0, NULL, NULL, 0);
			if(pSendData == NULL)
			{
				LOGE("Failed to set request data");
				return SSA_PARAM_ERROR;
			}

			recvData = SsClientComm(pSendData);
			SECURE_LOGD("read bytes : %d", recvData.result);
			if(recvData.result <= 0)
			{
				LOGE("An error occurred from server side err[%d]", recvData.result);
				free(pSendData);
				return recvData.result;
			}
			free(pSendData);
			memcpy(duk, recvData.dataBlock, recvData.result);
			dukExist = 1;
		}

		int res = GetIv(duk, iv, KEY_SIZE);
		if(res != 1)
		{
			return SSA_CIPHER_ERROR;
		}

		if(DoCipher(pData, dataLen, ppDecryptedData, &decryptedLen, duk, iv, 0) != 1)
		{
			LOGE("failed to decrypt data");
			return SSA_CIPHER_ERROR;
		}
		return decryptedLen;
	}
}
