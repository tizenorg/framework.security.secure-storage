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

#ifndef __SS_MANAGER__
#define __SS_MANAGER__

#include <tizen.h>

/**
 * @addtogroup CAPI_SECURE_STORAGE_MODULE
 * @{
 */

/**
 * @brief Maximum length if data name
 */
#define SSA_MAX_DATA_NAME_SIZE 256 
/**
 * @brief Maximum length of group id
 */
#define SSA_MAX_GROUP_ID_SIZE 32
/**
 * @brief Maximum length of password
 */
#define SSA_MAX_PASSWORD_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	SSA_PARAM_ERROR = TIZEN_ERROR_SYSTEM_CLASS | 0x01, 			/** < Invalid parameters */
	SSA_AUTHENTICATION_ERROR = TIZEN_ERROR_SYSTEM_CLASS | 0x02, /** < Authentication error */
	SSA_TZ_ERROR = TIZEN_ERROR_SYSTEM_CLASS | 0x03,				/** < Trust zone error */
	SSA_SOCKET_ERROR = TIZEN_ERROR_CONNECTION, 		 			/** < Connection error */
	SSA_PERMISSION_ERROR = TIZEN_ERROR_PERMISSION_DENIED, 		/** < Permission denied */
	SSA_SECURITY_SERVER_ERROR = TIZEN_ERROR_SYSTEM_CLASS | 0x04,/** < Security server error */
	SSA_CIPHER_ERROR = TIZEN_ERROR_SYSTEM_CLASS | 0x05, 		/** < Encryption / Decryption error */
	SSA_IO_ERROR = TIZEN_ERROR_IO_ERROR, 			 			/** < I/O error */
	SSA_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, 	 			/** < Out of memory */
	SSA_UNKNOWN_ERROR = TIZEN_ERROR_UNKNOWN, 					/** < Unknown error */
} ssa_error_e;

/**
 * @internal
 * @brief Puts application data to Secure Storage by given name.
 * @remark Input parameters pInDataName, pInDataBlock, pGroupId, pPassword must be static / allocated by user. Maximum lengths of user password and group id are 32.
 *
 * @since_tizen 2.3
 * @param[in] pDataName       The data name to be identify.
 * @param[in] pInDataBlock    The data block to be stored.
 * @param[in] pInDataBlockLen The length of the data to be put.
 * @param[in] pGroupId        Sharing group id. (NULL if not used)
 * @param[in] pPassword       The user password to use for encryption. (NULL if not used)
 *
 * @return  The length of stored data block on success or an error code otherwise.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter 
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 * @retval #SSA_CIPHER_ERROR 			Encryption failed
 * @retval #SSA_IO_ERROR 				I/O failed
 *
 *
 *
 * @see ssa_get()
 *
 * @code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int outLen = -1;
 * unsigned char dataName[32];
 * unsigned char* pDataBlock;
 * unsigned int dataLen;
 * unsigned char password[32];
 * unsigned char* pGroupId;
 *
 * // Put the data name to the dataName array
 * // Put the data block to pDataBlock and put its length to dataLen
 * // Put the user password to the password array
 * // Put the group id to pGroupId if want share the data
 *
 * outLen = ssa_put(dataName, pDataBlock, dataLen, pGroupId, password);
 * if(outLen < 0)
 * {
 *    // Error handling
 * }
 * // Use dataName to read data block afterwards
 *
 * ...
 * @endcode
 *
 */
int ssa_put(const char* pDataName, const char* pInDataBlock, size_t inDataBlockLen, const char* pGroupId, const char* pPassword);


/**
 * @internal
 * @brief Gets application data from Secure Storage by given name.
 * @remark Input parameters pOutataName, pGroupId, pPassword must be static / allocated by user. Maximum length of user password and group id are 32.
 *
 * @since_tizen 2.3
 * @param[in] pDataName        The data name to read.
 * @param[out] ppOutDataBlock  Containing data get from the secure storage. Memory allocated for ppOutDataBlock. So must be freed by the user of this function.
 * @param[in] pGroupId         Sharing group id. (NULL if not used)
 * @param[in] pPassword        The user password to use for encryption. (NULL if not used)
 *
 * @return The length of read data block on success or an error code otherwise.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter or no such data by given data name
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 * @retval #SSA_CIPHER_ERROR 			Decryption failed
 * @retval #SSA_IO_ERROR 				I/O failed
 *
 * @see ssa_put()
 *
 * @code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int outLen = -1;
 * unsigned char dataName[32];
 * unsigned char* pOutDataBlock;
 * unsigned char password[32];
 * unsigned char* pGroupId;
 *
 * // Put the data name to the dataName array
 * // Put the user password to the password array
 * // Put the group id to pGroupId if want share the data
 *
 * outLen = ssa_get(dataName, &pOutDataBlock, pGroupId, password);
 * if(outLen < 0)
 * {
 *    // Error handling
 * }
 *
 * free(pOutDataName);
 * return;
 * ...
 * @endcode
 *
 */
int ssa_get(const char* pDataName, char** ppOutDataBlock, const char* pGroupId, const char* pPassword);


/**
 * @internal
 * @brief Deletes application data from Secure Storage by given name.
 * @remark Input parameters pDataName, pGroupId must be static / allocated by caller. Maximum length of group id is 32.
 *
 * @since_tizen 2.3
 * @param[in] pDataName    The data name to delete
 * @param[in] pGroupId     Sharing group id. (NULL if not used)
 *
 * @return The length of data block on success or an error code otherwise.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter or no such data by given data name
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 * @retval #SSA_IO_ERROR 				I/O failed
 *
 * @pre The application data have to put before using this API by ssa_put()
 * @see ssa_put()
 *
 * @code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * unsigned char dataName[32];
 * unsigned char* pGroupId;
 *
 * // Put the data name to the dataName array
 * // Put the group id to pGroupId if want share the data
 *
 * ret = ssa_delete(dataName, pGroupId);
 * if(ret < 0)
 * {
 *    // Error handling
 * }
 *
 * return;
 * ...
 * @endcode
 *
 */
int ssa_delete(const char* pDataName, const char* pGroupId);


/**
 * @internal
 * @brief Encrypts application data using Secure Storage.
 * @remark Input parameters pInDataBlock, pPassword must be static / allocated by caller. Maximum length of password is 32.
 *
 * @since_tizen 2.3
 * @param[in] pInDataBlock   The data block to be encrypted.
 * @param[in] inDataBlockLen The length of the data block to be encrypted.
 * @param[out] ppOutDataBlock The data block contaning encrypted data block. Memory allocated for ppOutDataBlock. Has to be freed by free() function.
 * @param[in] pPassword      The user password to use for encryption. (NULL if not used)
 *
 * @return The length of encrypted data block on success or an error code otherwise.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 *
 * @see ssa_decrypt()
 *
 * @code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int len = -1;
 * unsigned char* pDataBlock;
 * unsigned int dataBlockLen;
 * unsigned char* pOutDataBlock;
 * unsigned char pPassword[32];
 *
 * // Put the data block to pDataBlock and put its length to dataBlockLen
 * // Put the user password to the pPassword array
 *
 * len = ssa_encrypt(pDataBlock, dataBlockLen, &pOutDataBlock, pPassword);
 * if(len < 0)
 * {
 *    // Error handling
 * }
 *
 * ...
 * free(pOutDataBlock);
 * @endcode
 *
 */
int ssa_encrypt(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword);


/**
 * @internal
 * @brief Decrypts application data using Secure Storage.
 * @remark Input parameters pInDataBlock, pPassword must be static / allocated by caller. Maximum length of password is 32.
 *
 * @since_tizen 2.3
 * @param[in] pInDataBlock   The data block contained encrypted data from ssa_encrypt.
 * @param[in] inDataBlockLen The length of the data block to be decrypted.
 * @param[out] ppOutDataBlock The data block contaning decrypted data block. Memory allocated for ppOutDataBlock. Has to be freed  by free() function.
 * @param[in] pPassword      The user password to use for decryption. (NULL if not used)
 *
 * @return Length of decrypted data block on success, otherwise an error code.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 *
 * @see ssa_encrypt()
 *
 * @code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int len = -1;
 * unsigned char* pDataBlock;
 * unsigned int dataBlockLen;
 * unsigned char* pOutDataBlock;
 * unsigned char pPassword[32];
 *
 * // Put the data block to pDataBlock and put its length to dataBlockLen
 * // Put the user password to the pPassword array
 *
 * len = ssa_decrypt(pDataBlock, dataBlockLen, &pOutDataBlock, pPassword);
 * if(len < 0)
 * {
 *    // Error handling
 * }
 *
 * ...
 * free(pOutDataBlock);
 * @endcode
 *
 */
int ssa_decrypt(const char* pInDataBlock, size_t inDataBlockLen, char** ppOutDataBlock, const char* pPassword);


/**
 * @internal
 * @brief Encrypts web application data using Secure Storage.
 *
 * @since_tizen 2.3
 * @param[in] pAppId   The application id.
 * @param[in] idLen    The length of the application id.
 * @param[in] pData    The data block to be encrypted.
 * @param[in] dataLen  The length of the data block.
 * @param[out] ppEncryptedData The data block contaning encrypted data block. Memory allocated for ppEncryptedData. Has to be freed by free() function.
 * @param[in] isPreloaded True if the application is preloaded, otherwise false.
 *
 * @return The length of encrypted data block on success, otherwise an error code.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 *
 * @see ssa_decrypt_web_application()
 */
int ssa_encrypt_web_application(const char* pAppId, int idLen, const char* pData, int dataLen, char** ppEncryptedData, int isPreloaded);


/**
 * @internal
 * @brief Encrypts web application data using Secure Storage.
 *
 * @since_tizen 2.3
 * @param[in] pAppId   The application id.
 * @param[in] idLen    The length of the application id.
 * @param[in] pData    The data block to be encrypted.
 * @param[in] dataLen  The length of the data block.
 * @param[out] ppEncryptedData Data block contaning encrypted data block. Memory allocated for ppEncryptedData. Has to be freed by free() function.
 * @param[in] isPreloaded True if the application is preloaded, otherwise false.
 *
 * @return Length of encrypted data block on success, otherwise an error code.
 * @retval #SSA_PARAM_ERROR 			Invalid input parameter
 * @retval #SSA_AUTHENTICATION_ERROR 	Non-authenticated application request
 * @retval #SSA_TZ_ERROR 				Trust zone error
 * @retval #SSA_SOCKET_ERROR 			Socket connection failed
 * @retval #SSA_PERMISSION_ERROR 		Permission error
 * @retval #SSA_SECURITY_SERVER_ERROR 	Getting smack information failed
 *
 * @see ssa_decrypt_web_application()
 */
int ssa_decrypt_web_application(const char* pData, int dataLen, char** ppDecryptedData, int isPreloaded);

#ifdef __cplusplus
}
#endif

#endif
