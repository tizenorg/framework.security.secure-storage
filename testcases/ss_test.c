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

void usage(void)
{
	printf("\n == Secure Storage Test Usage ==\n\n");
	printf(" ./ss_test\n");
}

void prepare_test(void)
{
	// 1. make some directories
	// 2. make test file
	printf("Make directory - /opt/secure-storage/test\n");
	mkdir("/opt/secure-storage", 0777);
	mkdir("/opt/secure-storage/test", 0777);

	printf("Make test file\n");
	system("touch /opt/secure-storage/test/input.txt");
	system("echo \"abcdefghijklnmopqrstuvwxyz\" > /opt/secure-storage/test/input.txt");
}

int test_ssm_write_file()
{
	/*
	 * input  : const char*	pFilePath
	 *          ssm_flag	flag
	 * return : if 0, success
	 *          if < 0, fail
	 */
	printf("the file '/opt/secure-storage/test/input.txt' will be stored in secure-storage\n");

	int ret = -1;
	char *infilepath = "/opt/secure-storage/test/input.txt";
	ssm_flag flag = SSM_FLAG_DATA;

	ret = ssm_write_file(infilepath, flag, NULL);
	printf("test function end\n");

	return ret;
}

int test_ssm_write_buffer()
{
	/*
	 * input  : char*		pWriteBuffer
	 *          size_t		bufLen
	 *          const char*	pFileName
	 *          ssm_flag	flag
	 * return : if 0, success
	 *          if < 0, fail
	 */
	printf("the buffer will be stored in secure-storage\n");

	int ret = -1;
	char buf[27] = "abcdefghijklmnopqrstuvwxyz\0";
	int buflen = strlen(buf);
	char *filename = "res_write_buf.txt";
	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;

	printf(" ** buffer content : [%s]\n", buf);
	printf(" ** buffer length  : [%d]\n", buflen);

	ret = ssm_write_buffer(buf, buflen, filename, flag, NULL);
	printf("test function end\n");

	return ret;
}

int test_ssm_getinfo()
{
	/*
	 * input  : const char*			pFilePath
	 *          ssm_flag			flag
	 *          ssm_file_info_t*	sfi
	 * return : if 0, success
	 *          if < 0, fail
	 */
	printf("get information of encrypted file. your input in plaintext\n");

	int ret = -1;
	char *filepath = "/opt/secure-storage/test/input.txt";
	ssm_flag flag = SSM_FLAG_DATA;
	ssm_file_info_t sfi;

	ret = ssm_getinfo(filepath, &sfi, flag, NULL);
	printf(" ** original size: [%d]\n", sfi.originSize);
	printf(" ** stored size:   [%d]\n", sfi.storedSize);
	printf(" ** reserved:      [%s]\n", sfi.reserved);
	printf("test function end\n");

	return ret;
}

int test_ssm_read()
{
	/*
	 * input  : const char*	pFilePath
	 *          size_t		bufLen
	 *          ssm_flag	flag
	 * output : char*		pRetBuf
	 *          size_t		readLen
	 * return : if 0, success
	 *          if < 0, fail
	 */
	printf("decrypt content from encrypted file\n");

	int ret = -1;
	char *filepath = "/opt/secure-storage/test/input.txt";
//	char *filepath = "res_write_buf.txt";
	int buflen = 128;
	ssm_flag flag = SSM_FLAG_DATA;
//	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
	char* retbuf = NULL;
	int readlen = 0;
	ssm_file_info_t sfi;

//	ssm_getinfo(filepath, &sfi, SSM_FLAG_DATA);
	ssm_getinfo(filepath, &sfi, flag, NULL);
	retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
	memset(retbuf, 0x00, (sfi.originSize + 1));

//	ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, SSM_FLAG_DATA);
	ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, flag, NULL);

	printf(" ** decrypted data: [%s][%d]\n", retbuf, strlen(retbuf));
	free(retbuf);
	printf("test function end\n");

	return ret;
}

int test_ssm_delete_file()
{
	/*
	 * input  : const char*	pFilePath
	 *          ssm_flag	flag
	 * return : if 0, success
	 *          if < 0, fail
	 */
	printf("the file '/opt/secure-storage/test/input.txt' will be stored in secure-storage\n");
	printf(" and encrypted one of this file will be deleted\n");

	int ret = -1;
	char *infilepath = "/opt/secure-storage/test/input.txt";
	ssm_flag flag = SSM_FLAG_DATA;
//	char *infilepath = "res_write_buf.txt";
//	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;

	ret = ssm_delete_file(infilepath, flag, NULL);
	printf("test function end\n");

	return ret;
}

int main(int argc, char* argv[])
{
	int ret = -1;
	int choice;

	char in_filepath[MAX_FILENAME_SIZE] = {0, };
	char out_filepath[MAX_FILENAME_SIZE] = {0, };

	if(argc != 1)
	{
		printf("Error...input argument error\n");
		usage();
	}

	printf("\n= This is Secure Storage test program. =\n");
	printf("  0. Prepare Secure Storage test\n");
	printf("  1. Data Store\n");
	printf("     11. ssm_write_file()\n");
	printf("     12. ssm_write_buffer()\n");
	printf("  2. Data Information\n");
	printf("     21. ssm_getinfo()\n");
	printf("  3. Data Read\n");
	printf("     31. ssm_read()\n");
	printf("  4. Delete encrypted file\n");
	printf("     41. ssm_delete_file()\n");
	printf("  5. Exit\n");

	printf("\nselect num: ");
	scanf("%d", &choice);
	
	switch( choice )
	{
		case 0:
			printf("\nYou select \"Prepare test\"\n");
			prepare_test();
			break;
		case 11:
			printf("\nYou select \"ssm_write_file()\"\n");
			ret = test_ssm_write_file();
			printf( "return: %d\n", ret );
			break;
		case 12:
			printf("\nYou select \"ssm_write_buffer()\"\n");
			ret = test_ssm_write_buffer();
			printf( "return: %d\n", ret );
			break;
		case 21:
			printf("\nYou select \"ssm_getinfo()\"\n");
			ret = test_ssm_getinfo();
			printf( "return: %d\n", ret );
			break;
		case 31:
			printf("\nYou select \"ssm_read()\"\n");
			ret = test_ssm_read();
			printf( "return: %d\n", ret );
			break;
		case 41:
			printf("\nYou select \"ssm_delete_file()\"\n");
			ret = test_ssm_delete_file();
			printf("return: %d\n", ret);
			break;
		case 5:
			printf("\nYou select \"Exit\"\n");
			printf( "Bye~\n");
			break;
		default:
			printf( "\nError...select wrong number\n" );
			usage();
			break;
	}

	return 0;
}
