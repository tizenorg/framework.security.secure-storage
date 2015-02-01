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

#include "ss_manager.h"


void format_mount_csa(void)
{
	system("mkdir /tmp/csa");
//	system("insmod /lib/modules/yaffs2.ko yaffs_format=1");
	system("ffdisk -a /dev/bml2");
	system("fformat -s 1 -S 512 16 /dev/stl2");
	system("mount -t rfs /dev/bml2 /tmp/csa");
	
	printf("format_mount_csa...\n");	
}

void mount_csa(void)
{
	system("mkdir /tmp/csa");
//	system("insmod /lib/modules/yaffs2.ko");
	system("mount -t rfs /dev/bml2 /tmp/csa");

	printf("mount_csa...\n");
}

void umount_csa(void)
{
	system("umount /tmp/csa");
//	system("rmmod /lib/modules/yaffs2.ko");
	printf("umount_csa...\n");
}


int main( int argc, char* argv[] )
{
	int 	ret;
	int 	choice;

	FILE	*fp;
	
	char 	in_filepath[50];
	char	writebuffer[31] = "abcdefghijklmnopqrstuvwxyz1234";
	char	*retBuf = NULL;
	
	size_t	readSize = 0;
	
	ssm_file_info_t sfi;
	
	system("mkdir -p /opt/share/secure-storage/");

	do {
		printf( "= This is Secure Storage test program. =\n" );
		printf( "  1. Secure Storage WriteFile() API\n" );
		printf( "  2. Secure Storage WriteBuffer() API \n" );
		printf( "  3. Secure Storage Read() API\n");
		printf( "  4. view rfs partition\n" );
		printf( "  5. Exit\n" );
		printf( "\nselect num: " );
		scanf( "%d", &choice );
	
		switch( choice )
		{
		case 1:
			printf("Call SSM_Store with /tmp/csa/cert.cp...\n");
			mount_csa();
			system("cp /opt/var/drm/cert.cp /tmp/csa/");
			
			ret = SSM_WriteFile("/tmp/csa/cert.cp", SSM_FLAG_SECRET_PRESERVE);
			umount_csa();		
			printf( "You select 'WriteFile'\n" );
			printf( "\nreturn: %d\n", ret );
			break;
		case 2:
			ret = SSM_WriteBuffer(writebuffer, 30, "writebuf.txt", SSM_FLAG_SECRET_OPERATION);
			printf( "You select 'WriteBuffer'\n" );
			printf( "return: %d\n", ret );
			break;
		case 3:
			printf("Call SSM_Read for OMA_DRM_CERT in secure storage...\n");
			//retBuf = (char*) malloc (50);
			printf("- read cert.cp\n");
			mount_csa();
			SSM_GetInfo("/tmp/csa/cert.cp", &sfi, SSM_FLAG_SECRET_PRESERVE);
			retBuf = (char*)malloc(sfi.originSize + 1);
			ret = SSM_Read("/tmp/csa/cert.cp", retBuf, sfi.originSize, &readSize, SSM_FLAG_SECRET_PRESERVE);
			//free(retBuf);
			umount();
			printf( "You select 'read1' : read Size = %u \n", readSize);

			fp = fopen("/opt/var/ss_test_result","wb");
			fwrite(retBuf, 1, readSize, fp);
			fclose(fp);
			
			printf( "address of retBuf : %x\n", retBuf);
			printf( "\nreturn: %d\n", ret );

			free(retBuf);
			
			printf("- read writebuf.txt");
			SSM_GetInfo("writebuf.txt", &sfi, SSM_FLAG_SECRET_OPERATION);
			retBuf = (char*)malloc(sfi.originSize);
			ret = SSM_Read("writebuf.txt", retBuf, sfi.originSize, &readSize, SSM_FLAG_SECRET_OPERATION);
			
			printf("You select 'read2' : read size %u \n", readSize);
			printf("return : %d, original data : %s\n", ret, retBuf);

			free(retBuf);
			
			break;

		case 4:
			mount_csa();
			system("df -h");
			system("ls -alF /tmp/csa");
			break;				
		case 5:
			printf( "You select 'Exit'\n" );
			exit(1);
		default:
			printf( "Error...select wrong number\n" );
			break;
		}
	}
	while(choice > 0 && choice < 5);

	return 0;
}
