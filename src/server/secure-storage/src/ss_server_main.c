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

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <security-server/security-server.h>

#include "secure_storage.h"

#include "ss_server_ipc.h"
#include "ss_server_main.h"

#define ENCRYPT_SIZE        1024
#define DUK_SIZE            16
#define DUK_SALT_SIZE       32
#define ITERATE_NUM         1
#define SECURE_STORAGE_NAME "secure-storage"
#define CONF_FILE_PATH      "/usr/share/secure-storage/config"

void printData(const char* pLogName, const char* pData, int dataLen)
{
#ifdef PRINT_DEBUG_DATA
	int i=0;
	int j=0;
	int count=0;

	SECURE_SLOGI("========== %s, Lengh=%d ==========", pLogName, dataLen);
	if(dataLen % 4 == 0)
		count = dataLen/4;
	else
		count = dataLen/4+1;

	for(i=j=0; j<count; i=i+4, j++)
		SECURE_SLOGI("[%d]= %02x [%d]=%02x [%d]=%02x [%d]=%02x", i, pData[i], i+1, pData[i+1], i+2, pData[i+2], i+3, pData[i+3]);
	SECURE_SLOGI("========================");
#else
	(void) pLogName;
	(void) pData;
	(void) dataLen;
#endif
}

/*
 *  salt is dummy in platform (0xFF * size) and iterates only once
 *
 *  [in] id : used as pwd
 *
 *  return DUK with size keyLen
 */
char *GetDummyDeviceUniqueKey(const char *id, size_t keyLen)
{
	unsigned char *duk = NULL;
	unsigned char salt[DUK_SALT_SIZE];

	memset(salt, 0xFF, DUK_SALT_SIZE);

	duk = (unsigned char *)malloc(sizeof(unsigned char) * (keyLen + 1));
	if (duk == NULL) {
		SECURE_SLOGE("Failed to alloc memory");
		return NULL;
	}

	PKCS5_PBKDF2_HMAC_SHA1(
		id,
		strlen(id),
		salt,
		DUK_SALT_SIZE,
		ITERATE_NUM,
		keyLen,
		duk);

	duk[keyLen] = 0;

	return (char *)duk;
}

static const char Base64EncodingTable[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

int IsSmackEnabled()
{
	FILE *file = fopen("/smack/load2", "r");
	if (file == NULL)
		return 0;

	fclose(file);

	return 1;
}

int IsDirExist(const char* dirpath)
{
	DIR* dp = opendir(dirpath);

	if (dp == NULL) {
		SECURE_SLOGD("directory [%s] is not exist.", dirpath);
		return 0;
	}

	closedir(dp);
	return 1;
}

int CreateStorageDir(const char* path)
{
	if (IsDirExist(path))
		return 0;

	SECURE_SLOGD("Make directory [%s]", path);

	if (mkdir(path, 0700) < 0) {
		SLOGE("[%s] cannot be made", SS_STORAGE_DEFAULT_PATH);
		return SSA_IO_ERROR;
	}

	return 0;
}

int check_privilege_by_sockfd(int sockfd, const char* object, const char* access_rights)
{
	int ret = -1;	// if success, return 0
	const char* private_group_id = PRIVATE_GROUP_ID;
	char* default_smack_label = NULL;
	const char* group_id = object;

	if(!IsSmackEnabled())
	{
		return 0;
	}

	if(!strncmp(group_id, private_group_id, strlen(private_group_id)))
	{
		SECURE_SLOGD("requested default group_id. get smack label");
		default_smack_label = security_server_get_smacklabel_sockfd(sockfd);
		if(default_smack_label)
		{
			SECURE_SLOGD("defined smack label : %s", default_smack_label);
			group_id = default_smack_label;
		}
		else
		{
			SLOGD("failed to get smack label");
			return -1;
		}
	}

	SECURE_SLOGD("object : %s, access_rights : %s", group_id, access_rights);
	ret = security_server_check_privilege_by_sockfd(sockfd, group_id, access_rights);

	if(default_smack_label)
	{
		free(default_smack_label);
	}

	return ret;
}

int GetProcessSmackLabel(int sockfd, char* proc_smack_label)
{
	char* smack_label = security_server_get_smacklabel_sockfd(sockfd);
	if(smack_label && strlen(smack_label) < MAX_GROUP_ID_SIZE)
	{
		strncpy(proc_smack_label, smack_label, MAX_GROUP_ID_SIZE);
		free(smack_label);
	}
	else
	{
		SLOGE("failed to get smack label");
		if(smack_label)
			free(smack_label);
		return -1; // SS_SECURITY_SERVER_ERROR?
	}
	SECURE_SLOGD("defined smack label : %s", proc_smack_label);
	return 0;
}

/* aes crypto function wrapper - p_text : plain text, c_text : cipher text, aes_key : from GetKey, mode : ENCRYPT/DECRYPT, size : data size */
unsigned char* AES_Crypto(unsigned char* p_text, unsigned char* c_text, char* aes_key, unsigned char* iv, int mode,  unsigned long size)
{
	AES_KEY e_key, d_key;
	
	AES_set_encrypt_key((unsigned char*)aes_key, 128, &e_key);
	AES_set_decrypt_key((unsigned char*)aes_key, 128, &d_key);
	
	if(mode == 1)
	{
		AES_cbc_encrypt(p_text, c_text, size, &e_key, iv, AES_ENCRYPT);
		return c_text;
	}
	else
	{
		AES_cbc_encrypt(c_text, p_text, size, &d_key, iv, AES_DECRYPT);
		return p_text;
	}
}

int SsServerGetDuk(int client_sockfd, char* pBuffer, int* pBufferLen, char* pAppId, unsigned int flag)
{
	char* pDuk = NULL;
	char* pSmackLabel = NULL;

	if(!IsSmackEnabled())
	{
		pSmackLabel = (char*)calloc(8, 1);
		if (!pSmackLabel) {
			SLOGE("Failed to allocate memory");
			return SSA_OUT_OF_MEMORY;
		}
		memcpy(pSmackLabel, "NOSMACK", 7);
	}

	else
	{
		if(flag == 0)
		{
			pSmackLabel = security_server_get_smacklabel_sockfd(client_sockfd);
			if(!pSmackLabel) 
			{
				SLOGE("failed to get smack label");
				return SSA_SECURITY_SERVER_ERROR;
			}
		}

		else
		{
			pSmackLabel = (char*)calloc(strlen(pAppId)+1,1);
			if (!pSmackLabel) {
				SLOGE("Failed to allocate memory");
				return SSA_OUT_OF_MEMORY;
			}
			memcpy(pSmackLabel, pAppId, strlen(pAppId));
		}
	}

	SECURE_SLOGD("smack label = %s, smack label length = %d", pSmackLabel, strlen(pSmackLabel));

	pDuk = GetDummyDeviceUniqueKey(pSmackLabel, DUK_SIZE * 2);
	if (pDuk == NULL) {
		SLOGE("failed to get duk");
		free(pSmackLabel);
		*pBufferLen = 0;
		return SSA_CIPHER_ERROR;
	}

	printData("Duk", pDuk, DUK_SIZE);

	memcpy(pBuffer, pDuk, DUK_SIZE);
	*pBufferLen = DUK_SIZE;
	free(pSmackLabel);
	free(pDuk);

	return *pBufferLen;
}

int SsServerGetSalt(int sockfd, char* pBuffer, int* pBufferLen, int encryptionMode)
{
	char* pSmackLabel = NULL;
	char salt[SALT_SIZE + 16] = {0,};
	int result = 0;

	result = SsServerGetData(-1, SALT_NAME, PRIVATE_GROUP_ID, NULL, 0, salt);
	if(result < 0)
	{   
		SLOGE("Faild to get salt from secure storage [result = %d]", result);
		return result;
	}   
	if(encryptionMode)
	{   
		memcpy(pBuffer, salt, SALT_SIZE);
		*pBufferLen = SALT_SIZE;
	}   
	else
	{   
		pSmackLabel = security_server_get_smacklabel_sockfd(sockfd);
		if(!pSmackLabel)
		{   
			SLOGE("Failed to get smack label");
			return SSA_SECURITY_SERVER_ERROR;
		}   
		SECURE_SLOGD("smack lebel = %s, smack label length = %d", pSmackLabel, strlen(pSmackLabel));

		memcpy(pBuffer, pSmackLabel, strlen(pSmackLabel));
		memset(pBuffer + strlen(pSmackLabel), 0, MAX_APPID_SIZE - strlen(pSmackLabel));
		memcpy(pBuffer + MAX_APPID_SIZE, salt, SALT_SIZE);
		*pBufferLen = MAX_APPID_SIZE + SALT_SIZE;
		free(pSmackLabel);
	}

	return 1;
}


int CheckGroupId(const char* pGroupId)
{
	const char* pPreGroupId = "secure-storage::";

	if(!strncmp(pGroupId, pPreGroupId, strlen(pPreGroupId)))
	{
		SLOGD("Valid group id");
		return 1;
	}

	SLOGD("Invalid group Id [%s]", pGroupId);
	return 0;
}

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

	result = EVP_CipherInit(&cipherCtx, pCipherAlgorithm, (const unsigned char*)pKey, (const unsigned char *)iv, encryption);
	if(result != 1)
	{
		SLOGE("[%d] EVP_CipherInit failed", result);
		goto Error;
	}

	result = EVP_CIPHER_CTX_set_padding(&cipherCtx, 1);
	if(result != 1)
	{
		SLOGE("[%d] EVP_CIPHER_CTX_set_padding failed", result);
		goto Error;
	}

	//cipher update operation
	result = EVP_CipherUpdate(&cipherCtx, (unsigned char*)*ppOutBuf, pOutBufLen, (const unsigned char*)pInputBuf, inputLen);
	if(result != 1)
	{
		SLOGE("[%d] EVP_CipherUpdate failed", result);
		goto Error;
	}

	//cipher final operation
	result = EVP_CipherFinal(&cipherCtx, (unsigned char*)*ppOutBuf + *pOutBufLen, &finalLen);
	if(result != 1)
	{
		SLOGE("[%d] EVP_CipherFinal failed", result);
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
	if((result != 1))
		result = SSA_CIPHER_ERROR;

	return result;
}

// not use
char* GenerateDataName(int sockfd, const char* pDataName, const char* pGroupId)
{
	SLOGD("GenerateDataName sockfd : %d, pDataName : %s, pGroupId : %s", sockfd, pDataName, pGroupId);

	char* pConvertedDataName = NULL;
	const char* pNotUsed = PRIVATE_GROUP_ID;
	const char* pSalt = "salt";
	const char* pDuk = "duk";

	if(sockfd == -1)
	{
		pConvertedDataName = (char*)calloc(1, strlen(pDataName)+1);
		if (!pConvertedDataName) {
			SLOGE("Failed to allocate memory");
			return NULL;
		}
		memcpy(pConvertedDataName, pDataName, strlen(pDataName));
	}
	else
	{
		//for test
		if(!(strncmp(pDataName, pSalt, strlen(pSalt))))
		{
			char* pSmackLabel = NULL;
			char* pTestApp = "ssa-test-util";

			pSmackLabel = security_server_get_smacklabel_sockfd(sockfd);
			if(!pSmackLabel)
			{
				SLOGE("Failed to get smack label");
				return NULL;
			}

			if(!(strncmp(pSmackLabel, pTestApp, strlen(pTestApp))))
			{
				free(pSmackLabel);
				pSmackLabel = NULL;

				pConvertedDataName = (char*)calloc(1, strlen(pSalt)+1);
				if (!pConvertedDataName) {
					SLOGE("Failed to allocate memory");
					return NULL;
				}

				memcpy(pConvertedDataName, pSalt, strlen(pSalt));
				return pConvertedDataName;
			}
			free(pSmackLabel);
		}

		if(!(strncmp(pDataName, pDuk, strlen(pDuk))))
		{
			char* pSmackLabel = NULL;
			char* pTestApp = "ssa-test-util";

			pSmackLabel = security_server_get_smacklabel_sockfd(sockfd);
			if(!pSmackLabel)
			{
				SLOGE("Failed to get smack label");
				return NULL;
			}

			if(!(strncmp(pSmackLabel, pTestApp, strlen(pTestApp))))
			{
				free(pSmackLabel);
                pSmackLabel = NULL;

				pConvertedDataName = (char*)calloc(1, strlen(pDuk)+1);
				if (!pConvertedDataName) {
					SLOGE("Failed to allocate memory");
					return NULL;
				}

				memcpy(pConvertedDataName, pDuk, strlen(pDuk));
				return pConvertedDataName;
			}
			free(pSmackLabel);
		}
		//end test

		if(strncmp(pGroupId, pNotUsed, strlen(pNotUsed)))
		{
			if(!CheckGroupId(pGroupId))
			{
				SLOGD("Invalid Group ID [%s]", pGroupId);
				return NULL;
			}

			pConvertedDataName = (char*)calloc(1, strlen(pDataName)+strlen(pGroupId)+DELIMITER_SIZE+1);
			if (!pConvertedDataName) {
				SLOGE("Failed to allocate memory");
				return NULL;
			}
			memcpy(pConvertedDataName, pGroupId, strlen(pGroupId));
			memcpy(pConvertedDataName + strlen(pGroupId), DELIMITER, DELIMITER_SIZE);
			memcpy(pConvertedDataName + strlen(pGroupId) + DELIMITER_SIZE, pDataName, strlen(pDataName));
		}
		else
		{
			char* pSmackLabel = NULL;

			pSmackLabel = security_server_get_smacklabel_sockfd(sockfd);
			if (!pSmackLabel) {
				SLOGE("Failed to get smack label");
				return NULL;
			}

			SECURE_SLOGD("defined smack label : %s", pSmackLabel);
			pConvertedDataName = (char*)calloc(1, strlen(pDataName)+strlen(pSmackLabel)+DELIMITER_SIZE+1);
			if (!pConvertedDataName) {
				free(pSmackLabel);
				SLOGE("Failed to allocate memory");
				return NULL;
			}

			memcpy(pConvertedDataName, pSmackLabel, strlen(pSmackLabel));
			memcpy(pConvertedDataName + strlen(pSmackLabel), DELIMITER, DELIMITER_SIZE);
			memcpy(pConvertedDataName + strlen(pSmackLabel) + DELIMITER_SIZE, pDataName, strlen(pDataName));
			free(pSmackLabel);
		}
	}
	
	return pConvertedDataName;
}

// use group_id if it is given else, use default label
char* GenerateStorageName(int sockfd, const char* pGroupId)
{
	SECURE_SLOGD("GenerateDataName sockfd : %d, pGroupId : %s", sockfd, pGroupId);

	char* pConvertedDataName = NULL;
	const char* pNotUsed= PRIVATE_GROUP_ID;

	if(sockfd == -1) // return default storage(or make secure-storage?)
	{
		pConvertedDataName = (char*)calloc(1, strlen(SECURE_STORAGE_NAME)+1);
		if (!pConvertedDataName) {
			SLOGE("Failed to allocate memory");
			return NULL;
		}
		memcpy(pConvertedDataName, SECURE_STORAGE_NAME, strlen(SECURE_STORAGE_NAME));
	}
	else
	{
		if(strncmp(pGroupId, pNotUsed, strlen(pNotUsed)))
		{
			if(!CheckGroupId(pGroupId))
			{
				SLOGD("Invalid Group ID [%s]", pGroupId);
				return NULL;
			}

			pConvertedDataName = (char*)calloc(1, strlen(pGroupId) + 1);
			if (!pConvertedDataName) {
				SLOGE("Failed to allocate memory");
				return NULL;
			}
			memcpy(pConvertedDataName, pGroupId, strlen(pGroupId));
		}
		else
		{
			char* pSmackLabel = NULL;

			pSmackLabel = security_server_get_smacklabel_sockfd(sockfd);
			if (!pSmackLabel) {
				SLOGD("failed to get smack label");
				return NULL;
			}

			SECURE_SLOGD("defined smack label : %s", pSmackLabel);
			pConvertedDataName = (char*)calloc(1, strlen(pSmackLabel) + 1);
			if (!pConvertedDataName) {
				free(pSmackLabel);
				SLOGE("Failed to allocate memory");
				return NULL;
			}

			memcpy(pConvertedDataName, pSmackLabel, strlen(pSmackLabel));
			free(pSmackLabel);
		}
	}
	
	SECURE_SLOGD("StorageName : %s", pConvertedDataName);

	return pConvertedDataName;
}

char* Base64Encoding(char* pData, size_t size)
{
	char* pEncodedBuf = NULL;
	char* pPointer = NULL;
	char* pLength = NULL;
	unsigned char pInput[3] = {0,0,0};
	unsigned char poutput[4] = {0,0,0,0};
	int index = 0;
	int loopCnt = 0;
	int stringCnt = 0;
	int sizeEncodedString = 0;

	pLength = pData + size - 1;
	sizeEncodedString = (4 * (size / 3)) + (size % 3 ? 4 : 0) + 1;
	pEncodedBuf = (char*)calloc(sizeEncodedString, sizeof(char));
	if (!pEncodedBuf) {
		SLOGE("Failed to allocate memory");
		return NULL;
	}

	for	(loopCnt = 0, pPointer = pData; pPointer <= pLength; loopCnt++, pPointer++) {
		index = loopCnt % 3;
		pInput[index] = *pPointer;

		if (index == 2 || pPointer == pLength) {
			poutput[0] = ((pInput[0] & 0xFC) >> 2);
			poutput[1] = ((pInput[0] & 0x3) << 4) | ((pInput[1] & 0xF0) >> 4);
			poutput[2] = ((pInput[1] & 0xF) << 2) | ((pInput[2] & 0xC0) >> 6);
			poutput[3] = (pInput[2] & 0x3F);

			pEncodedBuf[stringCnt++] = Base64EncodingTable[poutput[0]];
			pEncodedBuf[stringCnt++] = Base64EncodingTable[poutput[1]];
			pEncodedBuf[stringCnt++] = index == 0? '=' : Base64EncodingTable[poutput[2]];
			pEncodedBuf[stringCnt++] = index < 2? '=' : Base64EncodingTable[poutput[3]];

			pInput[0] = pInput[1] = pInput[2] = 0;
		}
	}

	pEncodedBuf[stringCnt] = '\0';

	return pEncodedBuf;
}

char* HashAndBase64Encoding(char* pData)
{
	size_t outLen = 0;
	char hashOut[HASH_SIZE] = {0,};

	EVP_Digest(pData, strlen(pData), (unsigned char *)hashOut, &outLen, EVP_sha1(), NULL);

	return Base64Encoding(hashOut, outLen);
}

// Replace whole delim char to dest from pName
char* ReplaceDelim(const char* pName, char pDelim, char pDestChar)
{
	int len = strlen(pName);
	int i = 0;

	char* pOutStr = strdup(pName);
	if (!pOutStr) {
		SLOGE("Failed to strdup. out of memory.");
		return NULL;
	}
	for(i=0; i<len; i++)
	{
		if(pOutStr[i] == pDelim)
		{
			pOutStr[i] = pDestChar;
		}
	}

	return pOutStr;
}

int CreateDataFile(const char* pPath, const char *pMode)
{
	FILE *fd = fopen(pPath, pMode);
	int ret = 0;

	if (fd == NULL) {
		SECURE_SLOGE("File open error:(path) %s", pPath);
		return SSA_IO_ERROR;
	}

	ret = chmod(pPath, 0600);

	fclose(fd);

	if (ret < 0) {
		SLOGE("chmod error");
		return SSA_IO_ERROR;
	}

	return 0;
}

int GetIv(char* pSrc, char* pIv, int srcLen)
{
	size_t outLen = 0;
	if (EVP_Digest(pSrc, srcLen, (unsigned char *)pIv, &outLen, EVP_sha1(), NULL) != 1) {
		SLOGE("Failed to get iv");
		return 0;
	}

	return 1;
}

int GenerateCipherKey(const char* pSeed, const char* pPassword, char** key, char** iv)
{
	char* pDuk = NULL;
	char *passwordedSeed = NULL;
	size_t seedLen = 0;
	size_t pwLen = 0;

	if(!pSeed)
	{
		SLOGE("Invalid pramters");
		return SSA_CIPHER_ERROR;
	}

	if(pPassword && strlen(pPassword) > 0)
	{
		// pSeed + pPassword
		seedLen = strlen(pSeed);
		pwLen = strlen(pPassword);
		passwordedSeed = (char*)malloc(seedLen + pwLen + 1);
		if(!passwordedSeed)
		{
			SLOGE("Failed to get memory allocation");
			return SSA_OUT_OF_MEMORY;
		}

		memcpy(passwordedSeed, pSeed, seedLen);
		memcpy(passwordedSeed+seedLen, pPassword, pwLen);
		passwordedSeed[seedLen + pwLen] = 0;

		pDuk = GetDummyDeviceUniqueKey(passwordedSeed, DUK_SIZE);
		free(passwordedSeed);
	}
	else
	{
		pDuk = GetDummyDeviceUniqueKey(pSeed, DUK_SIZE);
	}

	if (pDuk == NULL)
	{
		SLOGE("failed to get duk");
		return SSA_CIPHER_ERROR;
	}

	*key = pDuk;
	*iv = (char*)malloc(DUK_SIZE);

	GetIv(*key, *iv, DUK_SIZE);

	return 0;
}

int CipherData(const char* pData, int dataLen, const char* pPassword, const char* pSeed, char** ppOutData, int* outLen, int encrypt)
{
	if(!pData || !dataLen || !pSeed || !outLen)
	{
		SLOGE("Invalid Paramters");
		return SSA_PARAM_ERROR;
	}

	char* key = NULL;
	char* iv = NULL;

	if(GenerateCipherKey(pSeed, pPassword, &key, &iv) < 0)
	{
		SLOGE("Failed to get key");
		return SSA_CIPHER_ERROR;
	}

	if(DoCipher(pData, dataLen, ppOutData, outLen, key, iv, encrypt) != 1)
	{
		SLOGE("Failed to encrypt data");
		free(key);
		free(iv);
		return SSA_CIPHER_ERROR;
	}

	free(key);
	free(iv);

	return 1;
}

int WriteData(const char* pStoragePath, char* pData, int dataLen)
{
	FILE *fp = NULL;
	if(!pStoragePath || !pData || !dataLen)
	{
		SLOGE("Invalid Paramters");
		return SSA_PARAM_ERROR;
	}

	SECURE_SLOGD("Path : %s, dataLen : %d", pStoragePath, dataLen);

	if((fp = fopen(pStoragePath, "wb")) == NULL)
	{
		SLOGE("Failed to open file");
		return SSA_IO_ERROR;
	}

	if((fwrite(pData, sizeof(char), dataLen, fp)) == 0)
	{
		SLOGE("Failed to store data");
		fclose(fp);
		return SSA_IO_ERROR;
	}

	if(fflush(fp) != 0) {
		SLOGE("fail to execute fflush().\n");
		fclose(fp);
		return SSA_IO_ERROR;
	}
	else {
		if(fsync(fp->_fileno) == -1) {
			SLOGE("fail to execute fsync().\n");
			fclose(fp);
			return SSA_PARAM_ERROR;
		}
	}

	fclose(fp);
	return 0;
}

int ReadData(const char* pStoragePath, char** pData, int* dataLen)
{
	FILE *fp = NULL;
	unsigned int size = 0;
	int read_byte = 0;

	if(!pStoragePath || !pData || !dataLen)
	{
		SLOGE("Invalid Paramters");
		return SSA_PARAM_ERROR;
	}

	if(!(fp = fopen(pStoragePath, "rb")))
	{
		SECURE_SLOGE("File open error: %s", pStoragePath);
		return SSA_PARAM_ERROR;
	}
	
	if(fseek(fp, 0L, SEEK_END) < 0)
	{
		SECURE_SLOGE("Fseek error: in %s", pStoragePath);
		fclose(fp);
		return SSA_IO_ERROR;
	}
	
	size = ftell(fp);
	if((int)size < 1)
	{
		SECURE_SLOGE("Failed to get data size");
		fclose(fp);
		return SSA_IO_ERROR;
	}
	fseek(fp, 0L, SEEK_SET);

	*pData = (char*)malloc(size * sizeof(char));
	if(*pData == NULL)
	{
		SLOGE("Failed to allocated memory!");
		fclose(fp);
		return SSA_UNKNOWN_ERROR;
	}

	read_byte = fread(*pData, 1, size, fp);
	if(read_byte == 0)
	{
		SLOGE("Failed to read data");
		free(*pData);
		fclose(fp);
		return SSA_IO_ERROR;
	}

	*dataLen = read_byte;

	fclose(fp);
	return 0;
}

int DeleteData(const char* pPath)
{
	FILE *fp = NULL;
	int size = 0;

	if(!pPath)
	{
		SLOGE("Invalid Paramters");
		return SSA_PARAM_ERROR;
	}

	if( access( pPath, F_OK ) != 0 )
	{
		SLOGE("Can not find data");
		return SSA_PARAM_ERROR;
	}

	if(!(fp = fopen(pPath, "rb")))
	{
		SECURE_SLOGE("File open error: %s", pPath);
		return SSA_IO_ERROR;
	}
	
	if(fseek(fp, 0L, SEEK_END) < 0)
	{
		SECURE_SLOGE("Fseek error in %s", pPath);
		fclose(fp);
		return SSA_IO_ERROR;
	}
	
	size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	if(unlink(pPath) != 0)
	{
		SLOGE("Failed to delete data");
		fclose(fp);
		return SSA_IO_ERROR;
	}
	fclose(fp);

	return size;
}


int StoreDataToStorage(const char* pStorageName, const char* pDataName, const char* pData, int dataLen, const char *pPassword, const char* pSeed)
{
	char pDestPath[1024] = {0};
	char* pEncryptedData = NULL;
	int encryptedDataLen = 0;

	snprintf(pDestPath, 1024, "%s/%s/", SS_STORAGE_DEFAULT_PATH, pStorageName);
	if(CreateStorageDir(pDestPath) < 0)
	{
		return SSA_IO_ERROR;
	}

	if (sizeof(pDestPath) < (strlen(pDataName) + strlen(pDestPath) + 1)) {
		SLOGE("String is too long. pDestPath[%s], pDataName[%s]", pDestPath, pDataName);
		return SSA_PARAM_ERROR;
	}
	strncat(pDestPath, pDataName, strlen(pDataName));

	// encrypt data. if there is group_id, key seed will be group id else, it will be smack label
	if(CipherData(pData, dataLen, pPassword, pSeed, &pEncryptedData, &encryptedDataLen, 1) != 1)
	{
		SLOGE("Failed to Encrypt Data");
		return SSA_CIPHER_ERROR;
	}

	if(WriteData(pDestPath, pEncryptedData, encryptedDataLen) < 0)
	{
		SLOGE("Failed to Store Data");
		free(pEncryptedData);
		return SSA_IO_ERROR;
	}

	return encryptedDataLen;
}

int GetDataFromStroage(const char* pStorageName, const char* pDataName, const char* pPassword, const char* pSeed, char** ppOutData, int* outDataLen)
{
	char pDestPath[1024] = {0};
	char* pDecryptedData = NULL;
	char* pEncryptedData = NULL;
	int encryptedLen = NULL;
	int decryptedLen = 0;
	int ret = 0;

	snprintf(pDestPath, 1024, "%s/%s/%s", SS_STORAGE_DEFAULT_PATH, pStorageName, pDataName);

	// read encrypted data
	if((ret = ReadData(pDestPath, &pEncryptedData, &encryptedLen)) < 0)
	{
		SLOGE("Failed to get Data");
		return ret;
	}

	// encrypt data. if there is group_id, key seed will be group id else, it will be smack label
	if(CipherData(pEncryptedData, encryptedLen, pPassword, pSeed, &pDecryptedData, &decryptedLen, 0) != 1)
	{
		SLOGE("Failed to Encrypt Data");
		free(pEncryptedData);
		return SSA_CIPHER_ERROR;
	}

	*ppOutData = pDecryptedData;
	*outDataLen = decryptedLen;

	free(pEncryptedData);
	return decryptedLen;
}

int DeleteDataFromStorage(const char* pStorageName, const char* pDataName)
{
	char pDestPath[1024] = {0};

	snprintf(pDestPath, 1024, "%s/%s/%s", SS_STORAGE_DEFAULT_PATH, pStorageName, pDataName);

	int len = DeleteData(pDestPath);
	if(len < 0)
	{
		SLOGE("Failed to Delete Data");
		return SSA_IO_ERROR;
	}

	return len;
}

int GetStorageSeed(int sockfd, const char* pGroupId, char** ppSeed)
{
	char* pSeed = NULL;
	if(!strncmp(pGroupId, PRIVATE_GROUP_ID, strlen(PRIVATE_GROUP_ID)))
	{
		if(sockfd != -1)
		{
			pSeed = security_server_get_smacklabel_sockfd(sockfd);
			if(!pSeed)
			{
				SLOGE("Failed to get label");
				return SSA_SECURITY_SERVER_ERROR;
			}
		}
		else  // for salt. to be better..
		{
			pSeed = (char*)malloc(sizeof(char) * (strlen(SECURE_STORAGE_NAME) + 1));
			if (!pSeed) {
				SLOGE("Failed to allocate memory");
				return SSA_OUT_OF_MEMORY;
			}
			strncpy(pSeed, SECURE_STORAGE_NAME, strlen(SECURE_STORAGE_NAME));
			pSeed[strlen(SECURE_STORAGE_NAME)] = 0;
		}
	}
	else
	{
		pSeed = (char*)malloc(sizeof(char) * (strlen(pGroupId)+1));
		if (!pSeed) {
			SLOGE("Failed to allocate memory");
			return SSA_OUT_OF_MEMORY;
		}
		strncpy(pSeed, pGroupId, strlen(pGroupId));
		pSeed[strlen(pGroupId)] = 0;
	}

	*ppSeed = pSeed;

	return 0;
}

int SsServerPutData(int sockfd, const char* pDataName, const char* pData, int dataLen, const char* pGroupId, const char* pPassword, int enablePassword)
{
	char* pStorageName= NULL;
	char* pSeed = NULL;
	char* pReplaced = NULL;
//	char* pHashedDataName = NULL;
	int result = 0;

	if(sockfd != -1)
	{
		if(check_privilege_by_sockfd(sockfd, pGroupId, "w") != 0)
		{
			SECURE_SLOGE("[%s] permission denied\n", pGroupId);
			return SSA_PERMISSION_ERROR;
		}
	}

	// replace / string
	pReplaced = ReplaceDelim(pDataName, '/', '_');
	if (!pReplaced) {
		SLOGE("Failed to ReplaceDelim. pDataName[%s] is null or out of memory.", pDataName);
		return SSA_OUT_OF_MEMORY;
	}
	SECURE_SLOGD("data name : %s replaces : %s", pDataName, pReplaced);

	// generate storage name(smacklable + group id) as dataname
	pStorageName = GenerateStorageName(sockfd, pGroupId);
	if(!pStorageName)
	{
		SLOGE("Failed to generate data name");
		SECURE_SLOGE("[sockfd = %d, name = %s, groupId = %s]",sockfd, pDataName, pGroupId);
		free(pReplaced);
		return SSA_SECURITY_SERVER_ERROR;
	}
	
//	pHashedDataName = HashAndBase64Encoding(pDataName);
//	SECURE_SLOGD("pHashedDataName : %s", pHashedDataName);

	if(GetStorageSeed(sockfd, pGroupId, &pSeed) < 0)
	{
		SLOGE("Failed to get seed");
		free(pStorageName);
		free(pReplaced);
		return SSA_SECURITY_SERVER_ERROR;
	}

	result = StoreDataToStorage(pStorageName, pReplaced, pData, dataLen, pPassword, pSeed);
	if(result < 0)
	{
		SLOGE("Failed to put data from secure storage");
		SECURE_SLOGE("result : %d, dataName : %s", result, pDataName);
	}

	free(pStorageName);
	free(pSeed);
	free(pReplaced);
//	free(pHashedDataName);

	SECURE_SLOGI("result value = %d", result);

	return result;
}

int SsServerGetData(int sockfd, const char* pDataName, const char* pGroupId, const char* pPassword, int enablePassword, char* pOutData)
{
	char* pStorageName= NULL;
	char* pTempData = NULL;
	char* pSeed = NULL;
	char* pReplaced = NULL;
	int outDataLen = 0;
//	char* pHashedDataName = NULL;

	if(sockfd != -1)
	{
		if(check_privilege_by_sockfd(sockfd, pGroupId, "r") != 0)
		{
			SECURE_SLOGE("[%s] permission denied\n", pGroupId);
			return SSA_PERMISSION_ERROR;
		}
	}

	// replace / string
	pReplaced = ReplaceDelim(pDataName, '/', '_');
	if (!pReplaced) {
		SLOGE("Failed to ReplaceDelim. pDataName[%s] is null or out of memory.", pDataName);
		return SSA_OUT_OF_MEMORY;
	}
	SECURE_SLOGD("data name : %s replaced : %s", pDataName, pReplaced);

	pStorageName = GenerateStorageName(sockfd, pGroupId);
	if(!pStorageName)
	{
		SLOGE("Failed to generate data name");
		SECURE_SLOGE("[sockfd = %d, name = %s, groupId = %s]",sockfd, pDataName, pGroupId);
		free(pReplaced);
		return SSA_SECURITY_SERVER_ERROR;
	}

//	pHashedDataName = HashAndBase64Encoding(pDataName);
//	SECURE_SLOGD("pHashedDataName : %s", pHashedDataName);

	if(GetStorageSeed(sockfd, pGroupId, &pSeed) < 0)
	{
		SLOGE("Failed to get seed");
		free(pStorageName);
		free(pReplaced);
		return SSA_SECURITY_SERVER_ERROR;
	}

	int ret = GetDataFromStroage(pStorageName, pReplaced, pPassword, pSeed, &pTempData, &outDataLen);
	if(ret > 0)
	{
		printData("get", pTempData, outDataLen);

		memcpy(pOutData, pTempData, outDataLen);
	}
	else
	{
		SLOGE("Failed to get data from secure storage");
		SECURE_SLOGE("result : %d, dataName : %s", ret, pDataName);
	}

	free(pStorageName);
	free(pSeed);
	free(pTempData);
	free(pReplaced);
//	free(pHashedDataName);

	SECURE_SLOGI("result value = %d", ret);
	return ret;
}

int SsServerDeleteData(int sockfd, const char* pDataName, const char* pGroupId)
{
	char* pStorageName = NULL;
	char* pReplaced = NULL;
	int result = 0;

	if(check_privilege_by_sockfd(sockfd, pGroupId, "w") != 0)
	{
		SLOGE("[%s] permission denied\n", pGroupId);
		return SSA_PERMISSION_ERROR;
	}

	/* replace '/' with '_' in string */
	pReplaced = ReplaceDelim(pDataName, '/', '_');
	if (!pReplaced) {
		SLOGE("Failed to ReplaceDelim. pDataName[%s] is null or out of memory.", pDataName);
		return SSA_OUT_OF_MEMORY;
	}
	SECURE_SLOGD("data name : %s replaces : %s", pDataName, pReplaced);

	pStorageName = GenerateStorageName(sockfd, pGroupId);
	if(!pStorageName)
	{
		SLOGE("Failed to generate data name");
		SECURE_SLOGE("[sockfd = %d, name = %s, groupId = %s]",sockfd, pDataName, pGroupId);
		free(pReplaced);
		return SSA_SECURITY_SERVER_ERROR;
	}

	result = DeleteDataFromStorage(pStorageName, pReplaced);

	free(pStorageName);
	free(pReplaced);

	SECURE_SLOGI("result value = %d", result);
	return result;
}

int SsServerEncryptData(int sockfd, const char* pInData, int inDataLen, const char* pPassword, int enablePassword, char* pOutData)
{
	char* pTempData = NULL;
	int outDataLen = 0;
	char* pSeed = NULL;
	int result = SSA_UNKNOWN_ERROR;

	printData("before encryption", pInData, inDataLen);

	if (GetStorageSeed(sockfd, NULL, &pSeed) < 0) {
		SLOGE("Failed to get seed");
		return SSA_SECURITY_SERVER_ERROR;
	}

	result = CipherData(pInData, inDataLen, pPassword, pSeed, &pTempData, &outDataLen, 1);

	free(pSeed);

	if (result != 1) {
		SLOGE("Failed to encrypt by CipherData. errcode : %d", result);
		return SSA_CIPHER_ERROR;
	} else if (outDataLen > MAX_RECV_DATA_SIZE || outDataLen <= 0) {
		SLOGE("Invalid out data length : %d", outDataLen);
		free(pTempData);
		return SSA_PARAM_ERROR;
	}

	memcpy(pOutData, pTempData, outDataLen);
	free(pTempData);

	printData("after encryption", pOutData, outDataLen);

	return outDataLen;
}

int SsServerDecryptData(int sockfd, const char* pInData, int inDataLen, const char* pPassword, int enablePassword, char* pOutData)
{
	char* pTempData = NULL;
	int outDataLen = 0;
	char* pSeed = NULL;
	int result = SSA_UNKNOWN_ERROR;

	printData("before decryption", pInData, inDataLen);

	if (GetStorageSeed(sockfd, NULL, &pSeed) < 0) {
		SLOGE("Failed to get seed");
		return SSA_SECURITY_SERVER_ERROR;
	}

	result = CipherData(pInData, inDataLen, pPassword, pSeed, &pTempData, &outDataLen, 0);

	free(pSeed);

	if (result != 1) {
		SLOGE("Failed to decrypt by CipherData. errcode : %d", result);
		return SSA_CIPHER_ERROR;
	} else if (outDataLen <= 0) {
		SLOGE("Invalid out data length : %d", outDataLen);
		free(pTempData);
		return SSA_PARAM_ERROR;
	}


	memcpy(pOutData, pTempData, outDataLen);
	free(pTempData);

	printData("after  decryption", pOutData, outDataLen);

	return outDataLen;
}
