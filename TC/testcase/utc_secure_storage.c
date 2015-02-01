/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <tet_api.h>
#include <ss_manager.h>
#include <stdlib.h>

#define MAX_DATA_NAME 256 
#define MAX_BUFFER_LEN 4096
#define MAX_GROUP_ID_LEN 32
#define MAX_PASSWORD_LEN 32

#define SSA_TEST_RESULT_SUCCESS 0
enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

// positive
static void utc_secure_stroage_ssa_put_p01(void);
static void utc_secure_stroage_ssa_put_p02(void);
static void utc_secure_stroage_ssa_put_p03(void);
static void utc_secure_stroage_ssa_put_p04(void);
static void utc_secure_stroage_ssa_put_p05(void);
static void utc_secure_stroage_ssa_get_p01(void);
static void utc_secure_stroage_ssa_delete_p01(void);
static void utc_secure_stroage_ssa_encrypt_p01(void);
static void utc_secure_stroage_ssa_encrypt_p02(void);
static void utc_secure_stroage_ssa_decrypt_p01(void);
// negative                       
static void utc_secure_stroage_ssa_put_n01(void);
static void utc_secure_stroage_ssa_get_n01(void);
static void utc_secure_stroage_ssa_encrypt_n01(void);
static void utc_secure_stroage_ssa_decrypt_n01(void);
static void utc_secure_stroage_ssa_delete_n01(void);

struct tet_testlist tet_testlist[] = {
	{ utc_secure_stroage_ssa_put_p01, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_put_p02, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_put_p03, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_put_p04, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_put_p05, POSITIVE_TC_IDX },
//	{ utc_secure_stroage_ssa_get_p01, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_delete_p01, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_encrypt_p01, POSITIVE_TC_IDX },
	{ utc_secure_stroage_ssa_encrypt_p02, POSITIVE_TC_IDX },
//	{ utc_secure_stroage_ssa_decrypt_p01, POSITIVE_TC_IDX },

	{ utc_secure_stroage_ssa_put_n01, NEGATIVE_TC_IDX },
//	{ utc_secure_stroage_ssa_get_n01, NEGATIVE_TC_IDX },
	{ utc_secure_stroage_ssa_encrypt_n01, NEGATIVE_TC_IDX },
	{ utc_secure_stroage_ssa_decrypt_n01, NEGATIVE_TC_IDX },
	{ utc_secure_stroage_ssa_delete_n01, NEGATIVE_TC_IDX },
	{ NULL, 0 },
};

static void startup(void)
{
	/* start of TC */
	tet_printf("\n Secure Storage Agnet TC start");
}


static void cleanup(void)
{
	/* end of TC */
	tet_printf("\n Secure Storage Agent TC end");
}


static void MakeLongBuffer(char* buffer, int length)
{
	int i = 0;
	for(i=0; i<length; i++)
	{
		(buffer[i]) = (char)('a' + i % 26);
	}
}

int SsaCheckPut(const char* data_name, const char* group_id, const char *password, const char* orig_buffer)
{
	char* read_buffer = NULL;

	int len = ssa_get(data_name, &read_buffer, group_id, password);
	dts_check_gt("ssa_get", len, 0, "Failed to get data_name : %s , err : %d", data_name, len);
	dts_check_ne("ssa_get", read_buffer, NULL, "Failed to get data");

	if(orig_buffer)
	{
		int res = strncmp(orig_buffer, read_buffer, len);
		dts_check_eq("ssa_get", res, 0, "Failed to get data");
	}

	free(read_buffer);
	
	return len;
}

int SsaCheckEncrypt(const char* data, int data_len, const char *password, const char* orig_buffer)
{
	char* decrypted_buffer = NULL;

	int len = ssa_decrypt(data, data_len, &decrypted_buffer, password);
	dts_check_gt("ssa_decrypt", len, 0, "Failed to decrypt data");
	dts_check_ne("ssa_decrypt", decrypted_buffer, NULL, "Failed to decrypt data");

	if(orig_buffer)
	{
		int res = strncmp(orig_buffer, decrypted_buffer, len);
		dts_check_eq("ssa_decrypt", res, 0, "Failed to decrypt data");
	}

	free(decrypted_buffer);
	
	return len;
}

// Positive
static void utc_secure_stroage_ssa_put_p01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* data_name = "test";
	const char* group_id = NULL;
	const char* password = "1234";

	int len = ssa_put(data_name, test_buffer, strlen(test_buffer), group_id, password);
	dts_check_gt("ssa_put", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_put", res, 0, "Failed to get data after put :%d", res);
}


static void utc_secure_stroage_ssa_put_p02(void)
{
	const char* test_buffer = "this is test buffer for ssa_put with group_id.\n group_id is secure-storage::test";
	const char* data_name = "group_id_test";
	const char* group_id = NULL;
	const char* password = "qwer";

	int len = ssa_put(data_name, test_buffer, strlen(test_buffer), group_id, password);
	dts_check_gt("ssa_put", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_put", res, 0, "Failed to get data after put :%d", res);
}


static void utc_secure_stroage_ssa_put_p03(void)
{
	const char* test_buffer = "this is test buffer for ssa_put with max data name.";
	char data_name[MAX_DATA_NAME+1] = {0,};
	const char* group_id = NULL;
	const char* password = "qwer1234";

	MakeLongBuffer(data_name, MAX_DATA_NAME);
	int len = ssa_put(data_name, test_buffer, strlen(test_buffer), group_id, password);
	dts_check_gt("ssa_put", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_put", res, 0, "Failed to get data after put :%d", res);
}


/**
 * @brief Positive test case of sim_get_mcc()
 */
static void utc_secure_stroage_ssa_put_p04(void)
{
	char test_buffer[MAX_BUFFER_LEN] = {0,};
	const char* data_name = "max_buffer_test";
	const char* group_id = NULL;
	const char* password = "qwer";

	MakeLongBuffer(test_buffer, MAX_BUFFER_LEN);

	int len = ssa_put(data_name, test_buffer, MAX_BUFFER_LEN, group_id, password);
	dts_check_gt("ssa_put", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_put", res, 0, "Failed to get data after put :%d", res);
}


static void utc_secure_stroage_ssa_put_p05(void)
{
	const char* test_buffer = "this is test buffer for ssa_put with max password";
	const char* data_name = "max_buffer_test";
	const char* group_id = NULL;
	char password[MAX_PASSWORD_LEN+1] = {0,};

	MakeLongBuffer(password, MAX_PASSWORD_LEN);

	int len = ssa_put(data_name, test_buffer, strlen(test_buffer), group_id, password);
	dts_check_gt("ssa_put", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_put", res, 0, "Failed to get data after put :%d", res);
}


static void utc_secure_stroage_ssa_get_p01(void)
{
}


static void utc_secure_stroage_ssa_delete_p01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* data_name = "delete_test";
	const char* group_id = NULL;
	const char* password = "1234";

	// NULL group_id
	int len = ssa_put(data_name, test_buffer, strlen(test_buffer), NULL, password);
	dts_check_gt("ssa_delete", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	int res = SsaCheckPut(data_name, NULL, password, test_buffer);
	dts_check_gt("ssa_delete", res, 0, "Failed to get data after put :%d", res);

	int check = ssa_delete(data_name, NULL);
	dts_check_gt("ssa_delete", check, 0, "Failed to ssa_delete :%d", check);


	// with group_id
	len = ssa_put(data_name, test_buffer, strlen(test_buffer), group_id, password);
	dts_check_gt("ssa_delete", len, 0, "Failed to put data_name : %s , err : %d", data_name, len);

	res = SsaCheckPut(data_name, group_id, password, test_buffer);
	dts_check_gt("ssa_delete", res, 0, "Failed to get data after put :%d", res);

	check = ssa_delete(data_name, group_id);
	dts_check_gt("ssa_delete", check, 0, "Failed to ssa_delete :%d", check);
}


static void utc_secure_stroage_ssa_encrypt_p01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* password = "1234";
	char* encrypted_buffer = NULL;

	int len = ssa_encrypt(test_buffer, strlen(test_buffer), &encrypted_buffer, password);
	dts_check_gt("ssa_encrypt", len, 0, "Failed to encrypt err : %d", len);

	if(len > 0 && encrypted_buffer != NULL)
	{
		int res = SsaCheckEncrypt(encrypted_buffer, len, password, test_buffer);
		dts_check_gt("ssa_encrypt", res, 0, "Failed to verifying ssa_encrypt err : %d", res);
		free(encrypted_buffer);
	}
}


static void utc_secure_stroage_ssa_encrypt_p02(void)
{
	char test_buffer[MAX_BUFFER_LEN] = {0,};
	const char* password = "1234";
	char* encrypted_buffer = NULL;

	MakeLongBuffer(test_buffer, MAX_BUFFER_LEN-60);
	int len = ssa_encrypt(test_buffer, strlen(test_buffer), &encrypted_buffer, password);
	dts_check_gt("ssa_encrypt", len, 0, "Failed to encrypt err : %d", len);

	if(len > 0 && encrypted_buffer != NULL)
	{
		int res = SsaCheckEncrypt(encrypted_buffer, len, password, test_buffer);
		dts_check_gt("ssa_encrypt", res, 0, "Failed to verifying ssa_encrypt err : %d", res);
		free(encrypted_buffer);
	}
}


static void utc_secure_stroage_ssa_decrypt_p01(void)
{
}

// Negative

static void utc_secure_stroage_ssa_put_n01(void)
{
	const char* test_buffer = "this is nagative ssa_put test buffer.\n";
	const char* data_name = "nagative_test_data_name";
	const char* group_id = "test";
	const char* password = "qwer";

	// NULL data name
	int len = ssa_put(NULL, test_buffer, strlen(test_buffer), NULL, NULL);
	dts_check_lt("ssa_put Negative", len, 0, "Failed to test NULL data name data_name : %s , err : %d", data_name, len);

	// NULL data buffer
	len = ssa_put(data_name, NULL, strlen(test_buffer), NULL, NULL);
	dts_check_lt("ssa_put Negative", len, 0, "Failed to test NULL data buffer data_name : %s , err : %d", data_name, len);

	// zero data length
	len = ssa_put(data_name, test_buffer, 0, NULL, NULL);
	dts_check_lt("ssa_put Negative", len, 0, "Failed to test 0 data length put data_name : %s , err : %d", data_name, len);

	// ununiformed group_id
	len = ssa_put(data_name, test_buffer, strlen(test_buffer), "ununiformaed group_id", NULL);
	dts_check_lt("ssa_put Negative", len, 0, "Failed to test group_id data_name : %s , err : %d", data_name, len);

	// invalid password. ss password : 32, sss MAX_PW_LEN : 64
	char invalidPassword[128] = {0,};
	MakeLongBuffer(invalidPassword, 128);
	len = ssa_put(data_name, test_buffer, strlen(test_buffer), NULL, invalidPassword);
	dts_check_lt("ssa_put Negative", len, 0, "Failed to test invalid password data_name : %s , err : %d", data_name, len);
}

static void utc_secure_stroage_ssa_get_n01(void)
{
}

static void utc_secure_stroage_ssa_encrypt_n01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* password = "1234";
	char* encrypted_buffer = NULL;

	// null input buffer
	int len = ssa_encrypt(NULL, strlen(test_buffer), &encrypted_buffer, password);
	dts_check_lt("ssa_encrypt Negative", len, 0, "Failed to test null buffer err : %d",len);
	dts_check_gt("ssa_encrypt Negative", encrypted_buffer, NULL, "Failed to encrypt err : %d", len);

	// zero buffer length
	len = ssa_encrypt(test_buffer, 0, &encrypted_buffer, password);
	dts_check_lt("ssa_encrypt Negative", len, 0, "Failed to test zero length err : %d",len);

	// over size of input buffer
	char max_buffer[5500] = {0,};
	MakeLongBuffer(max_buffer, 5500);
	len = ssa_encrypt(max_buffer, strlen(max_buffer), &encrypted_buffer, password);
	dts_check_lt("ssa_encrypt Negative", len, 0, "Failed to test over size buffer err : %d", len);

	// over size of password
	char max_passwd[80] = {0,};
	MakeLongBuffer(max_passwd, 80);
	len = ssa_encrypt(test_buffer, strlen(test_buffer), &encrypted_buffer, max_passwd);
	dts_check_lt("ssa_encrypt Negative", len, 0, "Failed to test invalid password err : %d", len);
}


static void utc_secure_stroage_ssa_decrypt_n01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* password = "1234";
	char* encrypted_buffer = NULL;

	int len = ssa_encrypt(test_buffer, strlen(test_buffer), &encrypted_buffer, password);
	dts_check_gt("ssa_decrypt Negative", len, 0, "Failed to encrypt err : %d", len);
	dts_check_gt("ssa_decrypt Negative", encrypted_buffer, NULL, "Failed to encrypt err : %d", len);

	char* decrypted_buffer = NULL;
	// NULL input buffer
	len = ssa_decrypt(NULL, len, &decrypted_buffer, NULL);
	dts_check_lt("ssa_decrypt Negative", len, 0, "Failed to test NULL input buffer err : %d", len);
	free(decrypted_buffer);

	// zero length
	len = ssa_decrypt(encrypted_buffer, 0, &decrypted_buffer, NULL);
	dts_check_lt("ssa_decrypt Negative", len, 0, "Failed to test NULL zero length err : %d", len);
	free(encrypted_buffer);
}

static void utc_secure_stroage_ssa_delete_n01(void)
{
	const char* test_buffer = "this is test buffer for ssa_put.\n 1234567890 \n abcdefghijklmni \n !@#$%^&*()_+|";
	const char* data_name = "nagative_delete_test";
	const char* group_id = NULL;
	const char* password = "1234";

	// no data_name
	int check = ssa_delete(data_name, NULL);
	dts_check_lt("ssa_delete Negative", check, 0, "Failed to test invalid data name data_name : %s , err : %d", data_name, check);

	// NULL data name
	check = ssa_delete(NULL, group_id);
	dts_check_lt("ssa_delete Negative", check, 0, "Failed to test NULL data name data_name : %s , err : %d", data_name, check);
}
