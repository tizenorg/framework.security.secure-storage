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
#include <signal.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <systemd/sd-daemon.h>
#include <pthread.h>
#include <vconf.h>
#include <glib.h>
#include <dlfcn.h>

#include "secure_storage.h"
#include "ss_server_ipc.h"
#include "ss_server_main.h"

#define CONF_FILE_PATH	"/usr/share/secure-storage/config"
#define KEY_SIZE 16
#define VCONF_SMACK_UPDATE_FILE_PATH_KEY_NODE "db/smack/spd_policy_filepath"
#define VCONF_UPDATE_RESULT_KEY_NODE "db/smack/spd_update_result"
#define VCONF_UPDATE_RESULT_KEY_NODE_FOR_APP "db/smack/spd_update_result2"

static GMainLoop *event_loop;

char* get_key_file_path()
{
	FILE* fp_conf = NULL;
	char buf[128];
	char* retbuf = NULL;
	char seps[] = " :\n\r\t";
	char* token = NULL;

	retbuf = (char*)malloc(sizeof(char) * 128);
	if(!retbuf)
	{
		SLOGE("fail to allocate memory.\n");
		return NULL;
	}
	memset(buf, 0x00, 128);
	memset(retbuf, 0x00, 128);

	if(!(fp_conf = fopen(CONF_FILE_PATH, "r")))
	{
		SLOGE("Configuration file is not exist\n");
		free(retbuf);
		return NULL;
	}
	
	while(fgets(buf, 128, fp_conf))
	{
		token = strtok(buf, seps);
		if(token != NULL)
		{
			if(!strncmp(token, "MASTER_KEY_PATH", 15))	// master key path
			{
				token = strtok(NULL, seps);	// real path
				break;
			}
		}
		token = NULL;
	}
	fclose(fp_conf);

	if(token)
		strncpy(retbuf, token, 127);
	else {
		if(retbuf != NULL)
			free(retbuf);
		return NULL;
	}

	return retbuf;
}

int check_key_file()
{
	FILE* fp_key = NULL;
	char* key_path = NULL;

	key_path = get_key_file_path();
	if(key_path == NULL)
	{
		SLOGE("Configuration file is not exist\n");
		return 0;
	}

	if(!(fp_key = fopen(key_path, "r")))
	{
		SLOGE("Secret key file is not exist, [%s]\n", key_path);
		free(key_path);
		return 0;
	}

	free(key_path);
	fclose(fp_key);
	return 1;
}

int make_key_file()
{
	FILE* fp_key = NULL;
	int random_dev = -1;
	int i = 0;
	char tmp_key[1];
	char key[33];
	char* key_path = NULL;
	int read_len = 0;

	memset(key, 0x00, 33);

	key_path = get_key_file_path();
	if(key_path == NULL)
	{
		SLOGE("Configuration file is not exist\n");
		return 0;
	}

	if((random_dev = open("/dev/urandom", O_RDONLY)) < 0)
	{
		SLOGE("Random device Open error\n");
		free(key_path);
		return 0;
	}

	while(i < 32)
	{
		read_len = read(random_dev, tmp_key, 1);
		if(read_len < 0)
		{
			SLOGE("read error from random file");
			break;
		}

		if((tmp_key[0] >= '!') && (tmp_key[0] <= '~')) {
			key[i] = tmp_key[0];
			i++;
		}
	}

	if(!(fp_key = fopen(key_path, "w")))
	{
		SECURE_SLOGE("Secret key file Open error, [%s]\n", key_path);
		free(key_path);
		close(random_dev);
		return 0;
	}

	fprintf(fp_key, "%s", key);

	if(chmod(key_path, 0600)!=0)
	{
		SLOGE("Secret key file chmod error, [%s]\n", strerror(errno));
		free(key_path);
		close(random_dev);
		fclose(fp_key);
		return 0;
	}
	
	free(key_path);
	fclose(fp_key);
	close(random_dev);
	return 1;
}

/* for executing coverage tool (2009-04-03) */
void SigHandler(int signo)
{
	SLOGI("Got Signal %d\n", signo);
	exit(1);
}
/* end */


int GetSocketFromSystemd(int* pSockfd)
{
    int n = sd_listen_fds(0);
    int fd;

	for(fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START+n; ++fd) {
		if (0 < sd_is_socket_unix(fd, SOCK_STREAM, 1,
								  SS_SOCK_PATH, 0))
		{
			*pSockfd = fd;
			return 1;
		}
	}
	return 0;
}

int CreateNewSocket(int* pSockfd)
{
	int server_sockfd = 0;
	int temp_len_sock = 0;
	struct sockaddr_un serveraddr;

	if((server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		SLOGE("Error in function socket()..\n");
		return 0;
	}

	temp_len_sock = strlen(SS_SOCK_PATH);
	
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, SS_SOCK_PATH, temp_len_sock);
	serveraddr.sun_path[temp_len_sock] = '\0';

	if((bind(server_sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
	{
		unlink("/tmp/SsSocket");
		if((bind(server_sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr))) < 0)
		{
			SLOGE("Error in function bind()..\n");
			close(server_sockfd);
			return 0;	// ipc error
		}
	}

	if(chmod(SS_SOCK_PATH, S_IRWXU | S_IRWXG | S_IRWXO) != 0)
	{
		close(server_sockfd);
		return 0;
	}

	*pSockfd = server_sockfd;
	return 1;
}


void SsServerComm(void)
{
	int server_sockfd, client_sockfd;
	int client_len;
	struct sockaddr_un clientaddr, serveraddr;

	struct ucred cr;	// for test client pid. 2009-03-24
	int cl = sizeof(cr);	//
	int temp_len_sock = 0;
	int temp_len_in = 0;

	ReqData_t recv_data = {0, };
	RspData_t send_data = {0, };


	server_sockfd = client_sockfd = -1;

	if(!GetSocketFromSystemd(&server_sockfd))
	{
		SLOGE("Failed to get sockfd from systemd");
		if(!CreateNewSocket(&server_sockfd))
		{
			SLOGE("Failed to create socket");
			send_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
			goto Error_exit;
		}
		if((listen(server_sockfd, 5)) < 0)
		{
			SLOGE("Error in function listen()..\n");
			send_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
			goto Error_close_exit;
		}
	}
	else
	{
		SLOGD("Get socket from systemd");
	}

	client_len = sizeof(clientaddr);

	signal(SIGINT, (void*)SigHandler);
	
	while(1) 
	{
		errno = 0;
		
		if((client_sockfd = accept(server_sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&client_len)) < 0)
		{
			SLOGE("Error in function accept()..[%d, %d]\n", client_sockfd, errno);
			send_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
			goto Error_close_exit;
		}
		
		// for test client pid. 2009-03-24
		if(getsockopt(client_sockfd, SOL_SOCKET, SO_PEERCRED, &cr, (socklen_t*)&cl) != 0)
		{
			SLOGE("getsockopt() fail\n");
		}
		// end
		
		if(read(client_sockfd, (char*)&recv_data, sizeof(recv_data)) < 0)
		{
			SLOGE("Error in function read()..\n");
			send_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
			goto Error_close_exit;
		}

		temp_len_in = strlen(recv_data.data_infilepath);

		switch(recv_data.req_type)
		{
			case 1:
				send_data.rsp_type = SsServerDataStoreFromFile(cr.pid, recv_data.data_infilepath, recv_data.flag, client_sockfd, recv_data.group_id);

				if(send_data.rsp_type == 1)
				{
					strncpy(send_data.data_filepath, recv_data.data_infilepath, MAX_FILENAME_SIZE);
					send_data.data_filepath[temp_len_in] = '\0';
				}
				else
				{
					strncpy(send_data.data_filepath, "Error Occured..", MAX_FILENAME_SIZE);
					send_data.data_filepath[15] = '\0';
				}

				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;
			case 2:
				send_data.rsp_type = SsServerDataStoreFromBuffer(cr.pid, recv_data.buffer, recv_data.count, recv_data.data_infilepath, recv_data.flag, client_sockfd, recv_data.group_id);

				if(send_data.rsp_type == 1)
				{
					strncpy(send_data.data_filepath, recv_data.data_infilepath, MAX_FILENAME_SIZE);
					send_data.data_filepath[temp_len_in] = '\0';
				}
				else
				{
					strncpy(send_data.data_filepath, "Error Occured..", MAX_FILENAME_SIZE);
					send_data.data_filepath[15] = '\0';
				}

				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;
			case 3:
				send_data.rsp_type = SsServerDataRead(cr.pid, recv_data.data_infilepath, send_data.buffer, recv_data.count, &(send_data.readLen), recv_data.flag, client_sockfd, recv_data.group_id);

				if(send_data.rsp_type == 1)
				{
					strncpy(send_data.data_filepath, recv_data.data_infilepath, MAX_FILENAME_SIZE);
					send_data.data_filepath[temp_len_in] = '\0';
				}
				else
				{
					strncpy(send_data.data_filepath, "Error Occured..", MAX_FILENAME_SIZE);
					send_data.data_filepath[15] = '\0';
				}

				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;
			case 4:
				send_data.rsp_type = SsServerGetInfo(cr.pid, recv_data.data_infilepath, send_data.buffer, recv_data.flag, client_sockfd /*recv_data.cookie*/, recv_data.group_id);

				if(send_data.rsp_type == 1)
				{
					strncpy(send_data.data_filepath, recv_data.data_infilepath, MAX_FILENAME_SIZE);
					send_data.data_filepath[temp_len_in] = '\0';
				}
				else
				{
					strncpy(send_data.data_filepath, "Error Occured..", MAX_FILENAME_SIZE);
					send_data.data_filepath[15] = '\0';
				}

				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;			
			case 5:
				send_data.rsp_type = SsServerGetDuk(client_sockfd, send_data.buffer, &(send_data.readLen), recv_data.group_id, recv_data.flag);
				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;
			case 10:
				send_data.rsp_type = SsServerDeleteFile(cr.pid, recv_data.data_infilepath, recv_data.flag, client_sockfd, recv_data.group_id);
				
				if(send_data.rsp_type == 1)
				{
					strncpy(send_data.data_filepath, recv_data.data_infilepath, MAX_FILENAME_SIZE);
					send_data.data_filepath[temp_len_in] = '\0';
				}
				else
				{
					strncpy(send_data.data_filepath, "Error Occured..", MAX_FILENAME_SIZE);
					send_data.data_filepath[15] = '\0';
				}

				write(client_sockfd, (char*)&send_data, sizeof(send_data));
				break;

			default:
				SLOGE("Input error..Please check request type\n");
				break;
		}
		close(client_sockfd);
	}
	
Error_close_exit:
	close(server_sockfd);
	
Error_exit:
	strncpy(send_data.data_filepath, "error", MAX_FILENAME_SIZE);
	send_data.data_filepath[5] = '\0';

	if(client_sockfd >= 0)
	{
		write(client_sockfd, (char*)&send_data, sizeof(send_data));
		close(client_sockfd);
	}
	else
		SLOGE("cannot connect to client socket.\n");
}

int SsServerUpdateSmackPolicy()
{
	typedef int (*SmackPolicyUpdateFuncPointer)();
	SmackPolicyUpdateFuncPointer pSmackPolicyUpdateFuncPointer = NULL;
	int errCode = -1;

	void* dlHandle = dlopen("/usr/lib/libsmack-update-service.so", RTLD_LAZY);

	if (!dlHandle)
	{
		SLOGE("Failed to open so with reason : %s",  dlerror());
		return errCode;
	}

	pSmackPolicyUpdateFuncPointer = (SmackPolicyUpdateFuncPointer)dlsym(dlHandle, "spd_smack_policy_update");
	if (dlerror() != NULL)
	{
		SLOGE("Failed to find spd_smack_policy_update symbol : %s",  dlerror());
		goto free_data;
	}

	errCode = pSmackPolicyUpdateFuncPointer();

	free_data:

	if(dlHandle){
		dlclose(dlHandle);
	}

	return errCode;
}

void vconf_smack_update_cb(keynode_t *key, void* data)
{
	SLOGD("Callback received");
	int errorCode;

	switch(vconf_keynode_get_type(key))
	{
	case VCONF_TYPE_INT:
		printf("key = %s, value = %d(int)\n",
				vconf_keynode_get_name(key), vconf_keynode_get_int(key));
		break;
	case VCONF_TYPE_STRING:
	{
		printf("key = %s, value = %s(string)\n",
				vconf_keynode_get_name(key), vconf_keynode_get_str(key));
		if (vconf_keynode_get_str(key))
		{
			errorCode = SsServerUpdateSmackPolicy();
			LOGD("set the updation status with value %d", errorCode);
			// set the update result for fota team
			int ret = vconf_set_int(VCONF_UPDATE_RESULT_KEY_NODE, errorCode);
			if (ret != VCONF_OK)
			{
				LOGD("failed to set the updation status for fota");
			}

			// set the update result for the app control
			ret = vconf_set_int(VCONF_UPDATE_RESULT_KEY_NODE_FOR_APP, errorCode);
			if (ret != VCONF_OK)
			{
				LOGD("failed to set the updation status for app control");
			}
		}

		else
		{
			LOGD("file path is invalid");
		}
	}
	break;
	fprintf(stderr, "Unknown Type(%d)\n", vconf_keynode_get_type(key));
	break;
	}

	printf("%s Notification OK", (char *)data);
	return;
}

int vconf_smack_update(void* pData)
{
	vconf_notify_key_changed(VCONF_SMACK_UPDATE_FILE_PATH_KEY_NODE, vconf_smack_update_cb, NULL);

	event_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(event_loop);
	return 0;
}


int main(void)
{
	SLOGI("Secure Storage Server Start..\n");

	int exist_ret = -1;
	int make_ret = -1;
	DIR* dp = NULL;	// make default directory(if not exist)
	pthread_t main_thread;

	pthread_create(&main_thread, NULL, vconf_smack_update, NULL);
	if((dp = opendir(SS_STORAGE_DEFAULT_PATH)) == NULL)
	{
		SLOGI("directory [%s] is not exist, making now.\n", SS_STORAGE_DEFAULT_PATH);
		if(mkdir(SS_STORAGE_DEFAULT_PATH, 0700) < 0)
		{
		    int err_tmp = errno;
		    SLOGE("Failed while making [%s] directory. Errno: %s\n", SS_STORAGE_DEFAULT_PATH, strerror(err_tmp));
		    return 0;
		}
	}
	else
		closedir(dp);

	exist_ret = check_key_file(); // if 0, there is not key file. Or 1, exist.
	
	if(exist_ret == 0)
	{
		make_ret = make_key_file();

		if(make_ret == 0)
		{
			SLOGE("Making key file fail. ss-server will be terminated..\n");
			return 0;
		}
	}

	SsServerComm();

	return 0;
}
