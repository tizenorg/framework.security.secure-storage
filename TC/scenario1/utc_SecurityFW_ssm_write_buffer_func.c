/*
 * secure storage
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
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

#include <ss_manager.h>
#include <tet_api.h>

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_SecurityFW_ssm_write_buffer_func_01(void);
static void utc_SecurityFW_ssm_write_buffer_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_SecurityFW_ssm_write_buffer_func_01, POSITIVE_TC_IDX },
	{ utc_SecurityFW_ssm_write_buffer_func_02, NEGATIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
	printf("Make temporary directory - /opt/secure-storage/test/\n");
	system("mkdir -p /opt/secure-storage/test");
	printf("Make temporary file\n");
	system("touch /opt/secure-storage/test/input.txt");
	system("echo \"abcdefghij\" > /opt/secure-storage/test/input.txt");
}

static void cleanup(void)
{
	printf("Remove tamporary file and directory\n");
	system("rm -rf /opt/secure-storage/test");
}

/**
 * @brief Positive test case of ssm_write_buffer()
 */
static void utc_SecurityFW_ssm_write_buffer_func_01(void)
{
	int tetResult = TET_FAIL;
	/* variables for ssm_write_buffer */
	int ret = -1;
	char oribuf[20];
	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
	char* group_id = NULL;
	char* filename = "write_buffer.txt";
	int buflen = 0;

	/* variables for ssm_read */
	char buf[20];
	char* retbuf = NULL;
	int readlen = 0;
	ssm_file_info_t sfi;

	/* set contents in buffers */
	memset(oribuf, 0x00, 20);
	memset(buf, 0x00, 20);
	strncpy(oribuf, "abcdefghij", 10);	// original buffer
	strncpy(buf, "abcdefghij", 10);		// encrypting

	buflen = strlen(buf);

	/* write file to secure-storage */
	ret = ssm_write_buffer(buf, buflen, filename, flag, group_id);
	if(ret != 0) 	// if fail,
	{
		tetResult = TET_UNINITIATED;
		goto error;
	}

	/* read and compare */
	ssm_getinfo(filename, &sfi, flag, group_id);
	retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
	memset(retbuf, 0x00, (sfi.originSize + 1));
	
	ret = ssm_read(filename, retbuf, sfi.originSize, &readlen, flag, group_id);
	if(ret != 0) 	// if fail,
	{
		tetResult = TET_UNINITIATED;
		goto free_error;
	}

	if(tetResult != TET_UNINITIATED)
	{
		if(!memcmp(oribuf, retbuf, strlen(retbuf)))	// if same
			tetResult = TET_PASS;
		else
			tetResult = TET_FAIL;
	}

	/* delete encrypted file */
	ret = ssm_delete_file(filename, flag, group_id);
	if(ret != 0)
		tetResult = TET_UNINITIATED;

free_error:
	free(retbuf);
error:
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}

/**
 * @brief Negative test case of ssm_write_buffer()
 */
static void utc_SecurityFW_ssm_write_buffer_func_02(void)
{
	int tetResult = TET_FAIL;
	/* variables for ssm_write_buffer */
	int ret = -1;
	char* filename = "write_buffer.txt";
	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
	char buf[20];
	int buflen = 0;
	char* group_id = NULL;

	/* write file to secure-storage */
	ret = ssm_write_buffer(NULL, buflen, filename, flag, group_id);
	if(ret != 0)	// if fail,
		tetResult = TET_PASS;
	else
		tetResult = TET_FAIL;

	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}
