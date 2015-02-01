/**
 *
 * @ingroup SLP_PG
 * @defgroup SecureStorage_PG Secure Storage
@{

<h1 class="pg">Introduction</h1>

<h2 class="pg">Goal</h2>
The purpose of the document is to explain the method to use <i>Secure Storage</i> for developing SLP.

<h2 class="pg">Scope</h2>
This document can be referenced by SCM engineers and SLP developers.

<h2 class="pg">Introduction</h2>
Secure storage is a kind of technology to store data securely, implemented by using cryptographic techniques. Distributed Secure storage Manager provides APIs so that other applications can tighten up security by using Secure storage Engine.
When user wants to store data, he(or she) can store data securely by using APIs provided by Secure storage.

<h2 class="pg">Requirements</h2>
OpenSSL
- Cryptographic APIs of Secure storage refer to the OpenSSL libraries, the OpenSSL module MUST be prepared before building Secure storage module.
	- # apt-get install openssl
- OpenSSL module is included in the SDK basically. In general, you don't care about that.

<h2 class="pg">Abbreviations</h2>
<table>
	<tr>
		<td>SLP</td><td>Samsung Linux Platform</td>
	</tr>
	<tr>
		<td>&nbsp;</td><td>&nbsp;</td>
	</tr>
	<tr>
		<td>&nbsp;</td><td>&nbsp;</td>
	</tr>
</table>


<h1 class="pg">Architecture</h1>
The Secure storage module is implemented by C language.

<h2 class="pg">System Architecture</h2>
@image html SLP_secure-storage_PG_image001.png
The figure shown above is the architecture of Secure Storage which now implemented in SLP. The Secure Storage is implemented as a Server/Client model, using Unix Socket communication between the Server and Client. The user application utilizes Secure Storage operation by using APIs provided by the Manager.

<h2 class="pg">File Structure</h2>
@image html SLP_secure-storage_PG_image002.png
The figure shown above is the structure of a file stored in Secure Storage. The file's metadata is added in a header before the actual data and is extendable.

<h2 class="pg">Source code Architecture</h2>
- Server
	- ss_server_ipc.c : processing communication of server
	- ss_server_main.c : actual cryptographic function (encrypt / decrypt)
- Client
	- ss_client_ipc : processing communication of client
	- ss_client_intf : processing request and reply of server
	- ss_manager : the high-ranked APIs which are used by other applications

<h2 class="pg">Result of Build</h2>
If build of Secure storage module is success, results of build are as below:
- libss-client.so : shared library for providing manager APIs (/usr/lib)
- ss-server : executable for operating Secure storage Server (/usr/bin)
- ss_manager.h : header file for providing APIs and data structures (/usr/include


<h1 class="pg">APIs</h1>
The APIs are classified by three categories - Store, Read and get information.

<h2 class="pg">Data Store</h2>
- Data Store 1
<table>
	<tr>
		<td>API Name</td><td colspan="2">ssm_write_file()</td>
	</tr>
	<tr>
		<td rowspan="3">Input Param</td><td>char* pFilePath</td><td>path of file to be stored in Secure Storage</td>
	</tr>
	<tr>
		<td>ssm_flag flag</td><td>type of file to be stored</td>
	</tr>
	<tr>
		<td>const char* group_id</td><td>group name to be shared, if not, NULL</td>
	</tr>
	<tr>
		<td>Output Param</td><td colspan="2">None</td>
	</tr>
	<tr>
		<td>Include File</td><td colspan="2">ss_manager.h</td>
	</tr>
	<tr>
		<td>Return Value</td><td colspan="2">Return Type : INT<br>If 0, Success<br>If <0, Fail<br></td>
	</tr>
</table>
	- Store file in the Secure Storage. The original file will be deleted after storing. The 'pFilePath' is written in absolute path. To use data type, refer to 'Type Definition 1'.

- Data Store 2
<table>
	<tr>
		<td>API Name</td><td colspan="2">ssm_write_buffer()</td>
	</tr>
	<tr>
		<td rowspan="5">Input Param</td><td>char* pWriteBuffer</td><td>buffer pointer of data to be stored in Secure storage</td>
	</tr>
	<tr>
		<td>size_t bufLen</td><td>size of buffer</td>
	</tr>
	<tr>
		<td>char* pFileName</td><td>file name to be used in Secure Storage</td>
	</tr>
	<tr>
		<td>ssm_flag flag</td><td>type of file to be stored</td>
	</tr>
	<tr>
		<td>const char* group_id</td><td>group name to be shared, if not, NULL</td>
	</tr>
	<tr>
		<td>Output Param</td><td colspan="2">None</td>
	</tr>
	<tr>
		<td>Include File</td><td colspan="2">ss_manager.h</td>
	</tr>
	<tr>
		<td>Return Value</td><td colspan="2">Return Type : INT<br>If 0, Success<br>If <0, Fail</td>
	</tr>
</table>
	- Encrypt buffer content and store that in the Secure Storage in the file form. The 'pFileName' is real file name which be stored in the Secure Storage and is not absolute path but single file name. For example, that is not 'mydata/abc.txt', but 'abc.txt'. The 'bufLen' has length from 0 to 4KB(4096). To use data type, refer to chapter 'Type Definition 1'.

<h2 class="pg">Data Information</h2>
- Data Information
<table>
	<tr>
		<td>API Name</td><td colspan="2">ssm_getinfo()</td>
	</tr>
	<tr>
		<td rowspan="4">Input Param</td><td>char* pFilePath</td><td>file name or path to be stored in secure storage</td>
	</tr>
	<tr>
		<td>ssm_flag flag</td><td>type of file to be stored</td>
	</tr>
	<tr>
		<td>ssm_file_info_t* sfi</td><td>data structure or information of the file</td>
	</tr>
	<tr>
		<td>const char* group_id</td><td>group name to be shared, if not, NULL</td>
	</tr>
	<tr>
		<td>Output Param</td><td colspan="2">None</td>
	</tr>
	<tr>
		<td>Include File</td><td colspan="2">ss_manager.h</td>
	</tr>
	<tr>
		<td>Return Value</td><td colspan="2">Return Type : INT<br>If 0, Success<br>If <0, Fail</td>
	</tr>
</table>
	- Get information about file that you want to read. You can use 'originSize' of 'ssm_file_info_t' data structure to parameter 'bufLen' of SSM_Read() function. To use data type, refer to 'Type Definition 1'.

<h2 class="pg">Data Read</h2>
<table>
	<tr>
		<td>API Name</td><td colspan="2">ssm_read()</td>
	</tr>
	<tr>
		<td rowspan="4">Input Param</td><td>char* pFilePath</td><td>file name or path to be read in secure storage</td>
	</tr>
	<tr>
		<td> size_t bufLen</td><td>length of data to be read</td>
	</tr>
	<tr>
		<td>ssm_flag flag</td><td>data type to be read</td>
	</tr>
	<tr>
		<td>const char* group_id</td><td>group name to be shared, if not, NULL</td>
	</tr>
	<tr>
		<td rowspan="2">Output Param</td><td>char* pRetBuf</td><td>buffer for decrypted data</td>
	</tr>
	<tr>
		<td>size_t* readLen</td><td>length of data that this function read</td>
	</tr>
	<tr>
		<td>Include File</td><td colspan="2">ss_manager.h</td>
	</tr>
	<tr>
		<td>Return Value</td><td colspan="2">Return Type : INT<br>If 0, Success<br>If <0, Fail</td>
	</tr>
</table>
	- Read contents of file stored in Secure Storage to buffer. When coding, please note the following.
		-# The 'flag' of required data MUST be same as the 'flag' of stored data.
		-# The 'pFilePath' is absolute path or file name. In case of ssm_write_file(), use the absolute path, and in case of ssm_write_buffer(), use a file name.
		-# The 'pRetBuf' should be a pointer of already allocated memory. (Secure Storage does not allocate memory itself.)
		-# When using 'pRetBuf', do not use "string function" but "memory function". (It may include NULL bytes.)
		  string function : strcpy, strlen, strcat, fputs, fgets, ...
		  memory function : memcpy, memset, fwrite, fread, ...
@code
int ret;
size_t bufLen, readLen;
ssm_file_info_t sfi;
char* buffer = NULL;
...
ssm_getinfo("/abc/def/ghi", &sfi, SSM_FLAG_DATA);
...
buffer = (char*)malloc(sfi.originSize + 1);
bufLen = sfi.originSize;
...
ret = ssm_read("/abc/def/ghi", buffer, bufLen, &readLen, SSM_FLAG_DATA);
...
@endcode

<h2 class="pg">Delete File</h2>
- Delete encrypted file
<table>
	<tr>
		<td>API Name</td><td colspan="2">ssm_delete_file()</td>
	</tr>
	<tr>
		<td rowspan="3">Input Param</td><td>char* pFilePath</td><td>path of file to be deleted from Secure Storage</td>
	</tr>
	<tr>
		<td>ssm_flag flag</td><td>type of file to be deleted</td>
	</tr>
	<tr>
		<td>const char* group_id</td><td>group name to be shared, if not, NULL</td>
	</tr>
	<tr>
		<td>Output Param</td><td colspan="2">None</td>
	</tr>
	<tr>
		<td>Include File</td><td colspan="2">ss_manager.h</td>
	</tr>
	<tr>
		<td>Return Value</td><td colspan="2">Return Type : INT<br>If 0, Success<br>If <0, Fail</td>
	</tr>
</table>
	- Use when user want to delete file in Secure-storage. If you use the function ssm_write_file( ) or ssm_write_buffer( ) when storing in Secure-storage, you should use this function in order to delete those files. The flag MUST be identical with one which was used when storing.

<h2 class="pg">Type Definition</h2>
- Type Definition 1
<table>
	<tr>
		<td>Type Name</td><td>ssm_flag</td>
	</tr>
	<tr>
		<td>Members</td>
		<td>
		typedef enum {<br>
		&nbsp;&nbsp;&nbsp;&nbsp;SSM_FLAG_NONE = 0x00,<br>
		&nbsp;&nbsp;&nbsp;&nbsp;SSM_FLAG_DATA,<br>
		&nbsp;&nbsp;&nbsp;&nbsp;SSM_FLAG_SECRET_PRESERVE,<br>
		&nbsp;&nbsp;&nbsp;&nbsp;SSM_FLAG_SECRET_OPERATION,<br>
		&nbsp;&nbsp;&nbsp;&nbsp;SSM_FLAG_MAX<br>
		} SSM_FLAG
		</td>
	</tr>
	<tr>
		<td>Include File</td><td>ss_manager.h</td>
	</tr>
</table>
	- The flag for separating contents of file to be stored in Secure Storage. Secure storage API requires the flag information.
		-# <b>SSM_FLAG_DATA</b> : general data for user. (picture, movie, memo, etc.)
		-# <b>SSM_FLAG_SECRET_PRESERVE</b> : the secret data for preservation.
		-# <b>SSM_FLAG_SECRET_OPERATION</b> : the secret data to be renewed.

- Type Definition 2
<table>
	<tr>
		<td>Type Name</td><td>ssm_file_info_t</td>
	</tr>
	<tr>
		<td>Members</td>
		<td>
		typedef struct {<br>
		&nbsp;&nbsp;&nbsp;&nbsp;unsigned int originSize;<br>
		&nbsp;&nbsp;&nbsp;&nbsp;insigned int storedSize;<br>
		&nbsp;&nbsp;&nbsp;&nbsp;char reserved[8];<br>
		} ssm_file_info_t<br>
		</td>
	</tr>
	<tr>
		<td>Include File</td><td>ss_manager.h</td>
	</tr>
</table>
	- The data structure for storing metadata of file to be stored in Secure Storage. After encrypting, file size will be increased because of cryptographic block size. Therefore store before and after file size. 1bytes of reserved 8bytes is used for storing flag information.

<h2 class="pg">Error Definition</h2>
- Error Definition
<table>
	<tr>
		<td rowspan="2">Error Name</td><td colspan="2">Value</td>
	</tr>
	<tr>
		<td>Hex</td><td>Decimal</td>
	</tr>
	<tr>
		<td>SS_PARAM_ERROR</td><td>0x00000002</td><td>2</td>
	</tr>
	<tr>
		<td>SS_FILE_TYPE_ERROR</td><td>0x00000003</td><td>3</td>
	</tr>
	<tr>
		<td>SS_FILE_OPEN_ERROR</td><td>0x00000004</td><td>4</td>
	</tr>
	<tr>
		<td>SS_FILE_READ_ERROR</td><td>0x00000005</td><td>5</td>
	</tr>
	<tr>
		<td>SS_FILE_WRITE_ERROR</td><td>0x00000006</td><td>6</td>
	</tr>
	<tr>
		<td>SS_MEMORY_ERROR</td><td>0x00000007</td><td>7</td>
	</tr>
	<tr>
		<td>SS_SOCKET_ERROR</td><td>0x00000008</td><td>8</td>
	</tr>
	<tr>
		<td>SS_ENCRYPTION_ERROR</td><td>0x00000009</td><td>9</td>
	</tr>
	<tr>
		<td>SS_DECRYPTION_ERROR</td><td>0x0000000a</td><td>10</td>
	</tr>
	<tr>
		<td>SS_SIZE_ERROR</td><td>0x0000000b</td><td>11</td>
	</tr>
	<tr>
		<td>SS_SECURE_STORAGE_ERROR</td><td>0x0000000c</td><td>12</td>
	</tr>
	<tr>
		<td>SS_PERMISSION_ERROR</td><td>0x0000000d</td><td>13</td>
	</tr>
</table>
	- The error codes are defined in ss_manager.h. The actual return value of Secure Storage API is the negative form of the defined value.

<h2 class="pg">File System Synchronization (Recommended)</h2>
- When writing a file to Secure Storage using ssm_write_file() or ssm_write_buffer(), if it powers down unexpectedly, the data will not be recorded properly in the filesystem. To prevent this from happening, your application should call the <b>sync()</b> function.
<table>
	<tr>
		<td>
		<b>POSIX Programmer's manual</b><br>
		<br>
		<b>NAME</b></br>
		&nbsp;&nbsp;&nbsp;&nbsp;sync - schedule file system updates<br>
		<br>
		<b>SYNOPSIS</b>
		&nbsp;&nbsp;&nbsp;&nbsp;#include <unistd.h><br>
		<br>
		&nbsp;&nbsp;&nbsp;&nbsp;void sync(void);<br>
		<br>
		<b>DESCRIPTION</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;The sync() function shall cause all information in memory that updates file systems to be scheduled for writing out to all file systems.<br>
		<br>
		&nbsp;&nbsp;&nbsp;&nbsp;The writing, although scheduled, is not necessarily complete upon return from sync().<br>
		<br>
		<b>RETURN VALUE</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;The sync() function shall not return a value.<br>
		<br>
		<b>ERRORS</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;No errors are defined.<br>
		<br>
		&nbsp;&nbsp;&nbsp;&nbsp;The following sections are informative.<br>
		<br>
		<b>EXAMPLES</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;None<br>
		<br>
		<b>APPLICATION USAGE</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;None<br>
		<br>
		<b>RATIONALE</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;None<br>
		<br>
		<b>FUTURE DIRECTIONS</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;None<br>
		<br>
		<b>SEE ALSO</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;fsync() , the Base Definitions volume of IEEE Std 1003.1-2001, <unistd.h><br>
		<br>
		<b>COPYRIGHT</b><br>
		&nbsp;&nbsp;&nbsp;&nbsp;Portions of this text are reprinted and reproduced in electronic form from IEEE Std 1003.1, 2003 Edition, Standard for Information Technology -- Portable Operating System Interface (POSIX), The Open Group Base Specifications Issue 6, Copyright (C) 2001-2003 by the Institute of Electrical and Electronics Engineers, Inc and The Open Group. In the event of any discrepancy between this version and the original IEEE and The Open Group Standard, the original IEEE and The Open Group Standard is the referee document. The original Standard can be obtained online at http://www.open-group.org/unix/online.html.<br>
		</td>
	</tr>
</table>


<h1 class="pg">Implementation Guide</h1>
<h2 class="pg">A note of caution when implementing</h2>
- General particular
	- The 'group_id' parameter is very important portion in Secure Storage module.
		- In general cases, when an application stores some file in Secure Storage, he(or she) NEVER want to expose that file to other applications.
		- Therefore, all applications should have their independent storage in Secure Storage.
		- But in some cases, two or more applications should share same encrypted file. (e.g. DRM master secret key)
	- The 'group_id' works in two diffrent ways - <b>'designated group name'</b> or <b>'NULL'</b>
		- Use designated group name
			- Use when two or more applications want to share same encrypted file.
			- You should ask the security part to make the proper group_id.
			- The storage is made in /opt/share/secure-storage/, and the directory name is group_id. (/opt/share/secure-storage/[GROUP_ID])
			- If an application wants to read the encrypted file in some specific storage, that application MUST have privilege to access the file in the storage.
		- Use NULL
			- In the most cases, an application writes file into it's own storage, and the privilege is given to ifself.
			- The storage is made in /opt/share/secure-storage/, and the directory name is the hash value of execution path of that application.
				- Each applications have it's own storage.
			- Each applications CANNOT access to other's storage. (the hash value of execution path is unique.)
- Usage of tags. In Secure Storage, we have some tags, which is used to determine the kind of encrypted data.
	- SSM_FLAG_DATA
		- The general data. The most files are included, BUT you cannot use this flag in case of buffer encryption.
		- The encrypted content will be stored in /opt/share/secure-storage/~~/.
	- SSM_FLAG_SECRET_OPERATION
		- If you want to encrypt buffer content, you can use this flag. The file can be encrypted, too.
		- The encrypted content will be stored in /opt/share/secure-storage/~~/.
	- SSM_FLAG_SECRET_PRESERVE
		- This flag is reserved for special contents. The encrypted file by this flag will not be deleted regardless of any changes of binary.
		- The encrypted content will be stored in directory which be specified in configuration file.
		- The configuration file is /usr/share/secure-storage/config.
		
<h2 class="pg">Encrypt file content and store into secure-storage</h2>
@code
#include <stdio.h>
#include <ss_manager.h>

int main(void)
{
	int ret = -1;	// if return is 0, success
	char* filepath = "/opt/secure-storage/test/input.txt";	// this file will be encrypted. MUST use absolute path.
	ssm_flag flag = SSM_FLAG_DATA;	// in case of file encryption, SSM_FLAG_DATA is recommended.
	char* group_id = NULL;	// if some applications want to share encrypted file, 'group_id' will have a value, otherwise, NULL.

	ret = ssm_write_file(filepath, flag, group_id);
	// - if success, return 0. otherwise, return negative value. each value has specific meaning. see Error Definition.
	// - encrypted file will be stored in /opt/share/secure-storage/[HASH_VALUE_OF_CALLER]/{ORIGINAL_FILE_NAME}_{HASH_OF_NAME}.{EXTENSION}.e
	//   if you use specific 'group_id', directory name is that instead of {HASH_VALUE_OF_CALLER}.
	// - the original file is deleted after encrypting.

	printf("ret: [%d]\n", ret);
	return 0;
}
@endcode

<h2 class="pg">Encrypt buffer content and store into secure-storage</h2>
@code
#include <stdio.h>
#include <ss_manager.h>

int main(void)
{
	int ret = -1;	// if return is 0, success
	char buf[32];	// this buffer content will be encrypted.
	ssm_flag flag = SSM_FLAG_SECRET_OPERATION;	// in case of buffer encryption, SSM_FLAG_SECRET_OPERATION is recommended.
	char* group_id = NULL;	// if some applications want to share encrypted file, 'group_id' will have a value, otherwise, NULL.
	char* filename = "write_buf_res.txt";	// file name of encrypted buffer content. this file will be stored in secure-storage.
	int buflen = 0;	// length of the original buffer content

	memset(buf, 0x00, 32);
	strncpy(buf, "abcdefghij", 10);

	buflen = strlen(buf);

	ret = ssm_write_buf(buf, buflen, filename, flag, group_id);
	// - if success, return 0. otherwise, return negative value. each value has specific meaning. see Error Definition.
	// - encrypted file will be stored in /opt/share/secure-storage/[HASH_VALUE_OF_CALLER]/write_buf_res.txt
	//   file name is what you use as parameter.
	//   same as above, if you use specific 'group_id', directory name will be changed.

	printf("ret: [%d]\n", ret);
	return 0;
}

@endcode

<h2 class="pg">Read encrypted content</h2>
@code
#include <stdio.h>
#include <ss_manager.h>

int main(void)
{
	int ret = -1;	// if return is 0, success
	char* filepath = "/opt/secure-storage/test/input.txt";
	// this 'filepath' MUST be same with the one which be used when encrypting.
	// in case of buffer encryption, type JUST file name.
	char* retbuf = NULL;	// decrypted content is stored in this buffer.
	ssm_file_info_t sfi;	// information of encrypted file. this information is used in order to know original file size.
	int readlen = 0;	// length of reading content
	ssm_flag flag = SSM_FLAG_DATA;	// this 'flag' MUST be same with the one which be used when encrypting.
	char* group_id = NULL;	// if some applications want to share encrypted file, 'group_id' will have a value, otherwise, NULL.

	ssm_get_info(filepath, &sfi, flag, group_id);	// get information of encrypted file, that information will be stored in 'sfi'.
	retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));	// memory allocation for decrypted data
	memset(retbuf, 0x00, (sfi.originSize + 1));

	ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, flag, group_id);
	// - if success, return 0. otherwise, return negative value. each value has specific meaning. see Error Definition.
	// - if no error occured, decrypted data is stored in 'refbuf' buffer.
	
	printf("ret: [%d]\n", ret);
	printf("decrypted data: [%s]\n", retbuf);
	return 0;
}
@endcode


<h1 class="pg">Test &amp; Etc.</h1>
- Test
	- Unit test - not supported yet.
	- Integration test - not supported yet.
	
- Server Action
	- When testing, server program and test executable are running at the same time. Therefore two terminals are executed simultaneously. To doing this, execute server when booting.
	- In /etc/rc.d/rc.sysinit script, there is code which starts secure storage (Already reflected)

- Physical Secure storage
	- The location of certificate file which be used OMA DRM is '/csa/'. But other files are stored in '/opt/share/secure-storage/'. If you want to check the file storing path, refer to 'ss_manager.h'.
	- #define SSM_STORAGE_DEFAULT_PATH

- Source code Download
	- If you want to get source codes, there are two ways,
		- # apt-get source libss-client-0

*/

/**
 * @}
 */
