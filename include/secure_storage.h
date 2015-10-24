/*
 * secure storage
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
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

#ifndef __SECURE_STORAGE__
#define __SECURE_STORAGE__

#include "ss_manager.h"

#define	SS_SOCK_PATH			"/tmp/SsSocket"

#define		MAX_FILENAME_SIZE	SSA_MAX_DATA_NAME_SIZE
#define 	MAX_RECV_DATA_SIZE	4096	// internal buffer = 4KB
#define 	MAX_SEND_DATA_SIZE	4096	// internal buffer = 4KB
#define		MAX_GROUP_ID_SIZE	SSA_MAX_GROUP_ID_SIZE
#define 	SS_STORAGE_DEFAULT_PATH "/opt/share/secure-storage"

#define MAX_APPID_SIZE	32
#define	MAX_PASSWORD_SIZE SSA_MAX_PASSWORD_SIZE
#define KEY_SIZE		16
#define SALT_SIZE		400
#define SALT_NAME	"salt"
#define HASH_SIZE	20
#define DUK_NAME	"duk"
#define SALT_PATH "/opt/share/secure-storage/salt"
#define DELIMITER	"::"
#define DELIMITER_SIZE	2
#define PRE_GROUP_ID 	"secure-storage::"
#define PRIVATE_GROUP_ID "NOTUSED"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG	"SECURE_STORAGE"
#include <dlog.h>

#define	SS_FILE_POSTFIX			".e"

typedef enum {
	PUT_DATA,
	GET_DATA,
	DELETE_DATA,
	ENCRYPT_DATA,
	DECRYPT_DATA,
	GET_SALT,
	GET_DUK,
} RequestType;


typedef struct {
	RequestType	reqType;
	char		dataName[MAX_FILENAME_SIZE * 2 + 1]; // for absolute path
	char		dataBlock[MAX_SEND_DATA_SIZE];
	int			dataBlockLen;
	char		groupId[MAX_GROUP_ID_SIZE+1]; // string
	char		password[MAX_PASSWORD_SIZE+1]; // string
	int			enablePassword;
	int			encryptionMode;
} RequestData;

typedef struct {
	int		result;
	char	dataBlock[MAX_RECV_DATA_SIZE];
	int		dataBlockLen;
} ResponseData;

#endif // __SECURE_STORAGE__
