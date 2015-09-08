/*
 * secure storage
 *
 * Copyright (c) 2000 - 2010 Samsung Electronics Co., Ltd.
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 * 
 */

/* unit test for secure storage manager */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ss_manager.h"


#define LOG_FILE		"/opt/var/drm/unit_test_log.txt"
#define TEST_PATH		"/tmp/csa/"
#define OMA_DRM_CERT		"/tmp/csa/cert.cp"
#define TEST_FILE_NORMAL	"/opt/var/drm/normal"

#define TEST_SUCCESS		"test success!"
#define TEST_FAIL 		"test fail!"

const char* testcases[] = {
	"unit_test_write_file",
	"unit_test_write_buffer",
	"unit_test_read",
	"unit_test_all",
	"unit_test_pid",
	NULL
};

void mount_csa(void)
{
	system("mkdir /tmp/csa");
//	system("insmod /lib/modules/yaffs2.ko");
	system("mount -t rfs /dev/bml2 /tmp/csa");
	
	printf("mount_csa\n");
}

void umount_csa(void)
{
	system("umount /tmp/csa");
//	system("rmmod /lib/modules/yaffs2.ko");
	printf("umount_csa\n");
}

int write_log(FILE *fp, char *data, unsigned int len)
{
	size_t writelen;
	
	if(!fp)
	{
		printf("Error... log file open fail...\n");
		exit(0);
	}

	writelen = fwrite(data, 1, (size_t)len, fp); 

	fputc('\n', fp);
	
	if(writelen == len)
	{
		printf("log write %u bytes...\n", writelen);
		return 0;
	}
	else
	{
		printf("Error... log write fail...\n");
		return -1;
	}
}

void unit_test_write_file(FILE *fp)
{
	char* store_cases[] = {
		"1. invalid filepath = NULL",
		"2. invalid flag = -1",
		"3. invalid flag = 10",
		"4. filepath = cert.cp",
		"5. filepath = otherfile",
		NULL
	};
	char text[1024];
	int ret;
	
	sprintf(text, "----- %s Start -----", testcases[0]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);

	// # store case 1. invalid filepath = NULL
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[0], strlen(store_cases[0]));
	ret = SSM_WriteFile(NULL, SSM_FLAG_DATA);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 2. invalid flag = -1
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[1], strlen(store_cases[1]));
	ret = SSM_WriteFile(TEST_FILE_NORMAL, -1);
	if(ret != SSM_FALSE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 3. invalid flag = 10
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[2], strlen(store_cases[2]));
	ret = SSM_WriteFile(TEST_FILE_NORMAL, 10);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}

	// # store case 4. filepath = cert.cp
	// expected result ==> SSM_TRUE
	write_log(fp, store_cases[3], strlen(store_cases[3]));
	ret = SSM_WriteFile(OMA_DRM_CERT, SSM_FLAG_SECRET_PRESERVE);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 5. filepath = otherfile
	// expected result ==> SSM_TRUE
	write_log(fp, store_cases[4], strlen(store_cases[4]));
	ret = SSM_WriteFile(TEST_FILE_NORMAL, SSM_FLAG_DATA);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
		
	sprintf(text, "----- %s End -----", testcases[0]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);
}

void unit_test_write_buffer(FILE *fp)
{
	char* store_cases[] = {
		"1. invalid pWriteBuffer = NULL",
		"2. invalid bufLen = 0",
		"3. invalid pFileName = NULL",
	        "4. invalid pFileName = /xxxxxxx",
		"5. invalud flag = -1",	
		"6. invalid flag = 10",
		"7. a buffer input",
		NULL
	};
	char text[1024] = "This is a test buffer. WoW. that's wonderful.";
	int ret;
	
	sprintf(text, "----- %s Start -----", testcases[1]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);

	// # store case 1. invalid pWriteBuffer = NULL
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[0], strlen(store_cases[0]));
	ret = SSM_WriteBuffer(NULL, strlen(text), "text.txt", SSM_FLAG_SECRET_OPERATION);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}

	// # store case 2. invalid bufLen = 0
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[1], strlen(store_cases[1]));
	ret = SSM_WriteBuffer(text, 0, "text.txt", SSM_FLAG_SECRET_OPERATION);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
		
	// # store case 3. invalid pFileName = NULL
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[2], strlen(store_cases[2]));
	ret = SSM_WriteBuffer(text, strlen(text), NULL, SSM_FLAG_SECRET_OPERATION);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 4. invalid pFileName = /xxxxxx
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[3], strlen(store_cases[3]));
	ret = SSM_WriteBuffer(text, strlen(text), "/opt/var/text.txt", SSM_FLAG_SECRET_OPERATION);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 5. invalid flag = -1
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[4], strlen(store_cases[4]));
	ret = SSM_WriteBuffer(text, strlen(text), "text.txt", -1);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 6. invalid flag = 10
	// expected result ==> SSM_FALSE
	write_log(fp, store_cases[5], strlen(store_cases[5]));
	ret = SSM_WriteBuffer(text, strlen(text), "text.txt", 10);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	// # store case 7. a buffer input 
	// expected result ==> SSM_TRUE
	write_log(fp, store_cases[6], strlen(store_cases[6]));
	ret = SSM_WriteBuffer(text, strlen(text), "text.txt", SSM_FLAG_SECRET_OPERATION);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
	
	sprintf(text, "----- %s End -----", testcases[1]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);
}

void unit_test_read(FILE *fp)
{
	char* read_cases[] = {
		"1. invalid filepath = NULL",
		"2. invalid readLen = NULL",
		"3. invalid flag = -1",
		"4. invalid flag = 10",
		"5. proper parameters = cert.cp",
		"6. proper parameters = otherfile",
		"7. proper parameters = text.txt",
		NULL
	};
	char text[1024];
	char *retBuf = NULL;
       	int ret;
	size_t readLen = 0, bufLen = 1024;	
	ssm_file_info_t sfi;
	
	sprintf(text, "----- %s Start -----", testcases[2]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);

	// # read case 1. invalid filepath = NULL
	// expected result ==> SSM_FALSE
	write_log(fp, read_cases[0], strlen(read_cases[0]));
	ret = SSM_Read(NULL, retBuf, bufLen, &readLen, SSM_FLAG_DATA);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		//if(retBuf)
		//	free(retBuf);
	}
	
	// # read case 2. invalid readLen = NULL
	// expected result ==> SSM_FALSE
	write_log(fp, read_cases[1], strlen(read_cases[1]));
	ret = SSM_Read(TEST_FILE_NORMAL, retBuf, bufLen, NULL, SSM_FLAG_DATA);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		//if(retBuf)
		//	free(retBuf);
	}
	
	// # read case 3. invalid flag = -1
	// expected result ==> SSM_FALSE
	write_log(fp, read_cases[2], strlen(read_cases[2]));
	ret = SSM_Read(TEST_FILE_NORMAL, retBuf, bufLen, &readLen, -1);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		//if(retBuf)
		//	free(retBuf);
	}
	
	// # read case 4. invalid flag = 10
	// expected result ==> SSM_FALSE
	write_log(fp, read_cases[3], strlen(read_cases[3]));
	ret = SSM_Read(TEST_FILE_NORMAL, retBuf, bufLen, &readLen, 10);
	if(ret != SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		//if(retBuf)
		//	free(retBuf);
	}

	// # read case 5. proper parameters = cert.cp
	// expected result ==> SSM_TRUE
	write_log(fp, read_cases[4], strlen(read_cases[4]));
	SSM_GetInfo(OMA_DRM_CERT, &sfi, SSM_FLAG_SECRET_PRESERVE);
	retBuf = (char*)malloc(sfi.originSize+1);
	ret = SSM_Read(OMA_DRM_CERT, retBuf, sfi.originSize, &readLen, SSM_FLAG_SECRET_PRESERVE);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
		if(retBuf)
			free(retBuf);
	
	// # read case 6. proper parameters = otherfile
	// expected result ==> SSM_TRUE
	write_log(fp, read_cases[5], strlen(read_cases[5]));
	SSM_GetInfo(TEST_FILE_NORMAL, &sfi, SSM_FLAG_DATA);
	retBuf = (char*)malloc(sfi.originSize+1);
	ret = SSM_Read(TEST_FILE_NORMAL, retBuf, sfi.originSize, &readLen, SSM_FLAG_DATA);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
		if(retBuf)
			free(retBuf);
	
	// # read case 7. proper parameters = text.txt
	// expected result ==> SSM_TRUE
	write_log(fp, read_cases[6], strlen(read_cases[6]));
	SSM_GetInfo("text.txt", &sfi, SSM_FLAG_SECRET_OPERATION);
	retBuf = (char*)malloc(sfi.originSize+1);
	ret = SSM_Read("text.txt", retBuf, sfi.originSize, &readLen, SSM_FLAG_SECRET_OPERATION);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
	}
		if(retBuf)
			free(retBuf);

		
	sprintf(text, "----- %s End -----", testcases[2]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);
}


void unit_test_pid(FILE *fp)
{
#define ENCRYPT_PID 1
#define DECRYPT_PID 0
	
	int ret = 0;
	int i;
	char* pid_cases[] = {
		"1. encrypt pid",
		"2. decrypt pid",
		NULL	
	};
	char text[256];
	int encSize = 0;
	unsigned long pid = 1111, newPid;
	unsigned char testPid[16] = {0,};
	
	write_log(fp, pid_cases[0], strlen(pid_cases[0]));
	ret = SSM_EncryptPid(&pid, testPid, &encSize, ENCRYPT_PID);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		
		printf("%s result : pid - %u, size - %u\nencrypted pid -", pid_cases[0], pid, encSize);
		for(i = 0; i < 16; i++)
			printf("%.2x ", testPid[i]);
		printf("\n");
	}

	write_log(fp, pid_cases[1], strlen(pid_cases[1]));
	ret = SSM_EncryptPid(&newPid, testPid, &encSize, DECRYPT_PID);
	if(ret == SSM_TRUE)
	{
		sprintf(text, "    result = %s", TEST_SUCCESS);
		write_log(fp, text, strlen(text));
		
		printf("%s result : pid - %u, size - %u\n", pid_cases[1], newPid, encSize);
		
	}

}

void unit_test_all(FILE *fp)
{
	char text[1024];
	
	sprintf(text, "----- %s Start -----", testcases[3]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);
	
	unit_test_write_file(fp);
	unit_test_write_buffer(fp);
	unit_test_read(fp);
	
	sprintf(text, "----- %s End -----", testcases[3]);
	write_log(fp, text, strlen(text));
	printf("%s\n", text);
}

int main( int argc, char* argv[] )
{
	int 	ret;
	int 	choice;

	char 	in_filepath[50];
	
	FILE 	*log = NULL;

system("mkdir -p /opt/share/secure-storage/");
	
	printf( "  1. " ); printf(testcases[0]); printf( " \n" );
	printf( "  2. " ); printf(testcases[1]); printf( " \n" );
	printf( "  3. " ); printf(testcases[2]); printf( " \n" );
	printf( "  4. " ); printf(testcases[3]); printf( " \n" );
	printf( "  5. " ); printf(testcases[4]); printf( " \n" );
	printf( "  6. Exit\n" );

	printf( "\nselect num: " );
	scanf( "%d", &choice );

mount_csa();
system("cp /opt/var/drm/cert.cp /tmp/csa/");		// cert.cp
system("cp /opt/var/drm/cert.cp /opt/var/drm/normal");	// normal
	
	log = fopen(LOG_FILE, "wb");
	
	if(!log)
	{
		printf("Error... log file open fail...\n");
		exit(0);
	}

	switch( choice )
	{
		case 1:
			unit_test_write_file(log);
			break;
		case 2: 
			unit_test_write_buffer(log);
			break;
		case 3:
			unit_test_read(log);
			break;
		case 4:
			unit_test_all(log);
			break;
		case 5:
			unit_test_pid(log);
			break;
		case 6:
			printf( "You select 'Exit'\n" );
			break;
		default:
			printf( "Error...select wrong number\n" );
			break;
	}

umount_csa();

	if(log)
		fclose(log);
	
	return 0;
}
