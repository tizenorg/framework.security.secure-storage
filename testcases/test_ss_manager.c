/*
 * secure storage
 *
 * Copyright (c) 2000 - 2010 Samsung Electronics Co., Ltd.
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ss_manager.h"

#define MAX_FILENAME_SIZE 256

// ssa_get, ssa_put
// ssa_put
// ssa_delete
// ssa_encrypt, ssa_decrypt
// ssa_encrypt_web_application, ssa_decrypt_web_application

void test_get_put_delete () {
	const char* pDataName = "test_data";
	const char* pInDataBlock = "testtesttest";
	size_t inDataBlockLen = strlen(pInDataBlock);
	const char* pGroupId = "NOTUSED";
	const char* pPassword = "test_password";

	char* pOutDataBlock = NULL;

	int outLen = -1;
	int ret = -1;

	printf("\n");
	printf("[TEST : test_get_put_delete ]\n");
	ret = ssa_delete(pDataName, pGroupId);

	outLen = ssa_put(pDataName, pInDataBlock, inDataBlockLen, pGroupId, pPassword);
	if(outLen < 0) {
		printf("..fail : ssa_put result = %d\n", outLen);
		return;
	}
	printf("..success : ssa_put - [%s,%s]=%s\n", pDataName, pGroupId, pInDataBlock);

	outLen = ssa_get(pDataName, &pOutDataBlock, pGroupId, pPassword);
	if(outLen < 0 || outLen > 4096) {
		printf("..fail : ssa_get result = %d\n", outLen);
        free(pOutDataBlock);
		return;
	}
	if(strncmp(pInDataBlock, pOutDataBlock, outLen) == 0) {
		printf("..success : ssa_get - [%s,%s]=%s\n", pDataName, pGroupId, pOutDataBlock);
	}else {
		printf("..fail: ssa_get - [%s,%s] : input[%s]=output[%s]\n", pDataName, pGroupId, pInDataBlock,  pOutDataBlock);
	}

    free(pOutDataBlock);

	ret = ssa_delete(pDataName, pGroupId);
	if(ret < 0) {
		printf("..fail : ssa_delete = %d\n", ret);
		return;
	}
	printf("..success : ssa_delete - [%s,%s]\n", pDataName, pGroupId);
	
}

void test_enc_dec () {
	const char* pInDataBlock = "test_data";
	size_t inDataBlockLen = strlen(pInDataBlock);
	char* pEncDataBlock = NULL;
	char* pDecDataBlock = NULL;
	const char* pPassword = "test_password";

	int len = -1;

	printf("\n");
	printf("[TEST : test_enc_dec]\n");

	len = ssa_encrypt(pInDataBlock, inDataBlockLen, &pEncDataBlock, pPassword);
	if(len < 0) {
		printf("..fail : ssa_encrypt. len = %d\n", len);
		return;
	}
	printf("..success : ssa_encrypt- input data = %s\n", pInDataBlock);

	len = ssa_decrypt(pEncDataBlock, len, &pDecDataBlock, pPassword);
	if(len < 0) {
		printf("..fail : ssa_decrypt. len = %d\n", len);
		return;
	}
	if(strncmp(pInDataBlock, pDecDataBlock, len) == 0) {
		printf("..success : ssa_decrypt- decrypted data = %s\n", pDecDataBlock);
	}else {
		printf("..fail: ssa_decrypt- decrypted data = %s\n", pDecDataBlock);
	}
}

void test_webapp_enc_dec() {
	const char* pAppId = "ss-client-tests";
	int idLen = strlen(pAppId);
	const char* pData = "test_app_data";
	int dataLen = strlen(pData);
	char* pEncAppData = NULL;
	char* pDecAppData = NULL;
	int isPreloaded = 0;

	printf("\n");
	printf("[TEST : test_webapp_enc_dec]\n");

	int len = -1;
	len = ssa_encrypt_web_application(pAppId, idLen, pData, dataLen, &pEncAppData, isPreloaded);
	if(len < 0) {
		printf("..fail : downloaded: ssa_ssa_encrypt_web_application. len = %d\n", len);
		return;
	}
	printf("..success : downloaded: ssa_ssa_encrypt_web_application. input app data - %s\n", pData);

	len = ssa_decrypt_web_application(pEncAppData, len, &pDecAppData, isPreloaded);
	if(len < 0) {
		printf("..fail : downloaded: ssa_decrypt_web_application. len = %d\n", len);
		return;
	}
	if(strncmp(pData, pDecAppData, len) == 0) {
		printf("..success : downloaded: ssa_decrypt_web_application. decrypted app data - %s\n", pDecAppData);
	}else {
		printf("..fail: downloaded: ssa_decrypt_web_application. decrypted app data - %s\n", pDecAppData);
	}


	isPreloaded = 1;
	len = ssa_encrypt_web_application(pAppId, idLen, pData, dataLen, &pEncAppData, isPreloaded);
	if(len < 0) {
		printf("..fail : preloaded : ssa_ssa_encrypt_web_application. len = %d\n", len);
		return;
	}
	printf("..success : preloaded : ssa_ssa_encrypt_web_application. input app data - %s\n", pData);

	len = ssa_decrypt_web_application(pEncAppData, len, &pDecAppData, isPreloaded);
	if(len < 0) {
		printf("..fail : preloaded : ssa_decrypt_web_application. len = %d\n", len);
		return;
	}
	if(strncmp(pData, pDecAppData, len) == 0) {
		printf("..success : preloaded : ssa_decrypt_web_application. decrypted app data - %s\n", pDecAppData);
	}else {
		printf("..fail: preloaded : ssa_decrypt_web_application. decrypted app data - %s\n", pDecAppData);
	}
}

void main(void)
{
	test_get_put_delete();
	test_enc_dec();
	test_webapp_enc_dec();
}

