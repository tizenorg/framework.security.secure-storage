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

#ifndef __SS_MANAGER__
#include "ss_manager.h"
#endif

int SsClientPutData(const char* pInDataName, const char* pInDataBlock, size_t inDataBlockLen, const char* pGroupId, const char* pPassword);
int SsClientGetData(const char* pOutDataName, char** ppOutDataBlock, const char* pGroupId, const char* pPassword);
int SsClientDeleteData(const char* pDataName, const char* pGroupId);
int SsClientEncryptData(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword);
int SsClientDecryptData(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword);
int SsEncryptWebApplication(const char* pAppId, int idLen, const char* pData, int dataLen, char** ppEncryptedData, int isPreloaded);
int SsDecryptWebApplication(const char* pData, int dataLen, char** ppDecryptedData, int isPreloaded);
int DoCipher(const char* pInputBuf, int inputLen, char** ppOutBuf, int* pOutBufLen, char* pKey, char* iv, int encryption);
