/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <signal.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <systemd/sd-daemon.h>

#include "secure_storage.h"
#include "ss_server_ipc.h"
#include "ss_server_main.h"

#define CONF_FILE_PATH	"/usr/share/secure-storage/config"
#define KEY_SIZE 16
#define TIMEOUT_SEC 60
#define TIMEOUT_USEC 0

/* for executing coverage tool (2009-04-03) */
void SigHandler(int signo)
{
	SLOGI("Got Signal %d", signo);
	exit(1);
}
/* end */

int GetSocketFromSystemd(int* pSockfd)
{
    int n = sd_listen_fds(0);
    int fd;

	for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; ++fd) {
		if (sd_is_socket_unix(fd, SOCK_STREAM, 1, SS_SOCK_PATH, 0) > 0) {
			SLOGD("Get socket from systemd. fd[%d]", fd);
			*pSockfd = fd;
			return 1;
		}
	}
	return 0;
}

void SsServerComm(void)
{
	int server_sockfd = 0, client_sockfd = 0;
	int read_len = 0;
	int client_len = 0;
	struct sockaddr_un clientaddr;
	int ret = 0;

	RequestData recv_data = {0, };
	ResponseData send_data = {0, };

	if (!GetSocketFromSystemd(&server_sockfd)) {
		SLOGE("Failed to get sockfd from systemd.");
		return;
	}

	client_len = sizeof(clientaddr);

	signal(SIGINT, (void*)SigHandler);

	fd_set fd;
	struct timeval tv;
	while (1) {
		errno = 0;

		FD_ZERO(&fd);
		FD_SET(server_sockfd, &fd);

		tv.tv_sec = TIMEOUT_SEC;
		tv.tv_usec = TIMEOUT_USEC;

		ret = select(server_sockfd + 1, &fd, NULL, NULL, &tv);
		if (ret == 0) { // timeout
			SLOGD("ss-server timeout. exit.");
			break;
		}

		if (ret == -1) {
			SLOGE("select() error.");
			break;
		}

		if((client_sockfd = accept(server_sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&client_len)) < 0) {
			SLOGE("Error in function accept()..[%d, %d]", client_sockfd, errno);
			send_data.result = SSA_SOCKET_ERROR;	// ipc error
			goto Error_close_exit;
		}

		SLOGD("ss-server Accept! client sock[%d]", client_sockfd);

		read_len = read(client_sockfd, (char*)&recv_data, sizeof(recv_data));
		if (read_len < 0) {
			SLOGE("Error in function read()..");
			send_data.result = SSA_SOCKET_ERROR;	// ipc error
			goto Error_close_exit;
		}

		switch (recv_data.reqType) {
		case PUT_DATA:
		{
			SLOGD("ssa_put() called");
			send_data.result = SsServerPutData(client_sockfd, recv_data.dataName, recv_data.dataBlock, recv_data.dataBlockLen, recv_data.groupId, recv_data.password, recv_data.enablePassword);
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case GET_DATA:
		{
			SLOGD("ssa_get() called");
			send_data.result = SsServerGetData(client_sockfd, recv_data.dataName, recv_data.groupId, recv_data.password, recv_data.enablePassword, send_data.dataBlock);
			send_data.dataBlockLen = send_data.result;
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case DELETE_DATA:
		{
			SLOGD("ssa_delete() called");
			send_data.result = SsServerDeleteData(client_sockfd, recv_data.dataName, recv_data.groupId);
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case ENCRYPT_DATA:
		{
			SLOGD("ssa_encrypt() called");
			send_data.result = SsServerEncryptData(client_sockfd, recv_data.dataBlock, recv_data.dataBlockLen, recv_data.password, recv_data.enablePassword, send_data.dataBlock);
			send_data.dataBlockLen = send_data.result;
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case DECRYPT_DATA:
		{
			SLOGD("ssa_decrypt() called");
			send_data.result = SsServerDecryptData(client_sockfd, recv_data.dataBlock, recv_data.dataBlockLen, recv_data.password, recv_data.enablePassword, send_data.dataBlock);
			send_data.dataBlockLen = send_data.result;
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case GET_DUK:
		{
			SLOGD("ssa_get_duk() called, recv.DataBlock : %s, encrypted mode : %d", recv_data.dataBlock, recv_data.encryptionMode);
			//send_data.result = SsServerGetDuk(send_data.dataBlock, &send_data.dataBlockLen);
			send_data.result = SsServerGetDuk(client_sockfd, send_data.dataBlock, &(send_data.dataBlockLen), recv_data.dataBlock, recv_data.encryptionMode); // from old code
			SLOGD("GET_DUK result : %d", send_data.result);
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		case GET_SALT:
		{
			SLOGD("ssa_get_salt() called");
			send_data.result = SsServerGetSalt(client_sockfd, send_data.dataBlock, &send_data.dataBlockLen, recv_data.encryptionMode);
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			break;
		}

		default:
			SLOGE("Input error..Please check request type");
			break;
		}

		if (ret <= 0) {
			SLOGE("write failed :%d, errno %d try once", ret, errno);
			ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
			SLOGE("retry result :%d, errno %d", ret, errno);
		}

		close(client_sockfd);
	}

Error_close_exit:
	close(server_sockfd);

	if(client_sockfd >= 0)
	{
		ret = write(client_sockfd, (char*)&send_data, sizeof(send_data));
		close(client_sockfd);
	}
	else
		SLOGE("cannot connect to client socket.");

	SLOGI("SsServerComm Done.");
}

void PutSalt()
{
	FILE* pSalt = NULL;

	if (access(SALT_PATH, F_OK) == -1) {
		SLOGD("salt doesn't exist. It should be in secure-storage already.");
		return 0;
	}

	if (!(pSalt = fopen(SALT_PATH, "rb"))) {
		SLOGD("No salt file. Maybe it's already saved and removed.");
		return;
	}

	char saltData[SALT_SIZE] = {0,};
	int readLen = fread(saltData, 1, SALT_SIZE, pSalt);
	if (readLen != SALT_SIZE) {
		SLOGE("Failed to read salt [read length = %d]", readLen);
		fclose(pSalt);
		return;
	}

	fclose(pSalt);

	int result = 0;
	int retryCount = 3;
	while (1) {
		result = SsServerPutData(-1, SALT_NAME, saltData, SALT_SIZE, "NOTUSED", NULL, 0);
		if (result < 0) {
			SLOGE("Failed to put salt [error code = %d]", result);
			if (retryCount > 0) {
				SLOGE("Remaining retry count to put data [%d]", retryCount);
				retryCount--;
				sleep(1);
				continue;
			}
			return;
		}

		if (unlink(SALT_PATH) != 0) {
			SLOGE("unlink fail");
			return;
		}
		break;
	}
}

int main(void)
{
	SLOGI("Secure Storage Server Start..");

	SLOGI("PutSalt start");
	PutSalt();

	SLOGI("SsServerComm start");
	SsServerComm();

	SLOGI("Secure Storage Server End..");
	return 0;
}
