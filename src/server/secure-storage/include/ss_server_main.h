/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#include "ss_manager.h"

int SsServerPutData(int sockfd, const char* pDataName, const char* pData, int dataLen, const char* pGroupId, const char* pPassword,int enablePassword);
int SsServerGetData(int sockfd, const char* pDataName, const char* pGroupId, const char* pPassword, int enablePassword, char*pOutData);
int SsServerDeleteData(int sockfd, const char* pDataName, const char* pGroupId);
int SsServerEncryptData(int sockfd, const char* pInData, int inDataLen, const char* pPassword, int enablePassword, char* pOutData);
int SsServerDecryptData(int sockfd, const char* pInData, int inDataLen, const char* pPassword, int enablePassword, char* pOutData);

int SsServerGetDuk(int client_sockfd, char* pBuffer, int* pBufferLen, char* pAppId, unsigned int flag);
int SsServerGetSalt(int client_sockfd, char* pBuffer, int* pBufferLen, int encryptionMode);
