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
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "ss_client_ipc.h"
#include "secure_storage.h"

ResponseData SsClientComm(RequestData* pClientData)
{
	int sockfd = 0;
	int clientLen = 0;
	struct sockaddr_un clientaddr;
	RequestData sendData = {0, };
	ResponseData recvData = {0, };
	int tempLen = 0;
	int tempSockLen = 0;
	int read_len = 0;

	sendData.reqType = pClientData->reqType;
	sendData.dataBlockLen = pClientData->dataBlockLen;
	sendData.enablePassword = pClientData->enablePassword;
	sendData.encryptionMode = pClientData->encryptionMode;

	tempLen = strlen(pClientData->dataName);

	strncpy(sendData.dataName, pClientData->dataName, MAX_FILENAME_SIZE);
	sendData.dataName[tempLen] = '\0';

	strncpy(sendData.groupId, pClientData->groupId, MAX_GROUP_ID_SIZE);
	strncpy(sendData.password, pClientData->password, MAX_PASSWORD_SIZE);

	memcpy(sendData.dataBlock, pClientData->dataBlock, MAX_SEND_DATA_SIZE);

	if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		LOGE("Error in function socket()..\n");
		recvData.result = SSA_SOCKET_ERROR;	// ipc error
		goto Error_exit;
	}

	tempSockLen = strlen(SS_SOCK_PATH);

	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_UNIX;
	strncpy(clientaddr.sun_path, SS_SOCK_PATH, tempSockLen);
	clientaddr.sun_path[tempSockLen] = '\0';
	clientLen = sizeof(clientaddr);

	if(connect(sockfd, (struct sockaddr*)&clientaddr, clientLen) < 0)
	{
		LOGE("Error in function connect()..\n");
		recvData.result = SSA_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}

	if(write(sockfd, (char*)&sendData, sizeof(sendData)) < 0)
	{
		LOGE("Error in function write()..\n");
		recvData.result = SSA_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}

	read_len = read(sockfd, (char*)&recvData, sizeof(recvData));
	if(read_len < 0)
	{
		LOGE("Error in function read()..\n");
		recvData.result = SSA_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}

Error_close_exit:
	close(sockfd);

Error_exit:
	return recvData;
}
