/*****************************************
** SUPPORTED ALGORITHMS ******************
** AES CRYPTO ****************************
*** TEE_ALG_AES_ECB_NOPAD ****************
*** TEE_ALG_AES_CBC_NOPAD ****************
*** TEE_ALG_AES_CTR **********************
******************************************
** RSA CRYPTO ****************************
*** TEE_ALG_RSA_NOPAD ********************
*** TEE_ALG_RSAES_PKCS1_V1_5 *************
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 *
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 *
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 ***
******************************************
** RSA SIGN ******************************
*** TEE_ALG_RSASSA_PKCS1_V1_5_MD5 ********
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 *******
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 *****
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 *****
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 ***
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 *
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 *
******************************************
** HASH **********************************
*** TEE_ALG_MD5 **************************
*** TEE_ALG_SHA1 *************************
*** TEE_ALG_SHA256 ***********************
*** TEE_ALG_SHA512 ***********************
*****************************************/
#include "tee_internal_api.h"
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
    {0x25081234, 0x4132, 0x5532, {'k', 'e', 'y', 's', 't', 'o', 'r', 'e'}}, 512,
    255, 1, 1, 1)

#endif

// Helper function.
#define BYTES2BITS(bytes) (bytes * 8)

// Max key sizes.
#define MAX_RSA_KEYSIZE 1024
#define MAX_AES_KEYSIZE 256

// Available command for the CA to call.
#define ENCRYPTION 0
#define DECRYPTION 1
#define SIGNATURE 2
#define VERIFICATION 3
#define HASH 4
#define KEYGENERATION 5

// Available modes for the TA to use.
typedef enum {
  DECRYPT = 0,
  ENCRYPT = 1,
  SIGN = 2,
  VERIFY = 3,
  DIGEST = 4
} Operation;

// Available cryptographic algorithm categories.
typedef enum { RSA = 0, AES = 1 } Algorithm_type;

/*                                                                             *
*                                                                              *
* Low level functions defining functions that will be used by other functions. *
*                                                                              *
*                                                                              *
*                                                                              */

/*!
* \brief RSA_Operation Wraps the RSA operations in one function.
* \param mode          Supported mode are TEE_MODE_ENCRYPT and TEE_MODE_DECRYPT.
* \param algorithm     Supported algorithms are defined above for RSA.
* \param key           The key that will be used for the operation.
* \param in_data       Pointer to the input data buffer.
* \param in_data_len   Size of the input data buffer.
* \param out_data      Pointer for the output data buffer. For the signature
* operation it is also used for input
* \param out_data_len  Size of the output data buffer.
*/
static TEE_Result RSA_Operation(TEE_OperationMode mode, uint32_t algorithm,
                                TEE_ObjectHandle key, void *in_data,
                                uint32_t in_data_len, void *out_data,
                                uint32_t out_data_len) {
  // Null initialized handle for the TEE operation.
  TEE_OperationHandle rsa_operation = NULL;
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;

  // Allocate the cryptographic operation.
  ret = TEE_AllocateOperation(&rsa_operation, algorithm, mode, MAX_RSA_KEYSIZE);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  // Bind operation and key.
  ret = TEE_SetOperationKey(rsa_operation, key);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  // Switch with all available RSA modes: encrypt, decrypt, sign and verify.
  switch (mode) {
  // Encryption
  case TEE_MODE_ENCRYPT:
    // Encrypt the in_data with given key and put the result on out_data buffer.
    ret = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, &out_data_len);
    // If operation fails, log error to the system log.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed: 0x%x", ret);
    }
    break;
  // Decryption
  case TEE_MODE_DECRYPT:
    // Decrypt the in_data with given key and put the result on out_data buffer.
    ret = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, &out_data_len);
    // If operation fails, log error to the system log.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt failed: 0x%x", ret);
    }
    break;
  // Signing
  case TEE_MODE_SIGN:
    // Sign the in_data digest with given key and put the result on out_data
    // buffer.
    ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, in_data, in_data_len,
                                   out_data, &out_data_len);
    // If operation fails, log error to the system log.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricSignDigest failed: 0x%x", ret);
    }
    break;
  // Verification
  case TEE_MODE_VERIFY:
    // Verify the in_data digest with given key and out_data signature. Put the
    // result on out_data buffer.
    ret = TEE_AsymmetricVerifyDigest(rsa_operation, NULL, 0, in_data,
                                     in_data_len, out_data, out_data_len);
    // If operation fails, log error to the system log.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricVerifyDigest failed: 0x%x", ret);
    }
    break;
  default:
    // If the mode does not much the available modes, log the error.
    OT_LOG(LOG_ERR, "Unkown RSA mode type");
  }
  // Always free the operation.
  TEE_FreeOperation(rsa_operation);
  // Return the result.
  return ret;
}

/*!
* \brief AES_operation Wraps the AES operations in one function.
* \param mode          Supported mode are TEE_MODE_ENCRYPT and TEE_MODE_DECRYPT.
* \param algorithm     Supported algorithms are defined above for AES.
* \param key           The key that will be used for the operation.
* \param in_data       Pointer to the input data buffer.
* \param in_data_len   Size of the input data buffer.
* \param out_data      Pointer for the output data buffer. For the signature
* operation it is also used for input
* \param out_data_len  Pointer to memory containing the size of the output data
* buffer.
*/
static TEE_Result AES_operation(TEE_OperationMode mode, uint32_t algorithm,
                                TEE_ObjectHandle key, void *IV, uint32_t IV_len,
                                void *in_data, uint32_t in_data_len,
                                void *out_data, uint32_t *out_data_len) {
  // Null initialized handle for the TEE operation.
  TEE_OperationHandle aes_operation = NULL;
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;

  // Allocate the cryptographic operation.
  ret = TEE_AllocateOperation(&aes_operation, algorithm, mode, MAX_AES_KEYSIZE);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  // Bind operation and key.
  ret = TEE_SetOperationKey(aes_operation, key);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  // Initialize cipher with given initialization vector.
  TEE_CipherInit(aes_operation, IV, IV_len);
  // Complete the cipher with one operation. If bigger data encryption is
  // required, will implement pipeline structure.
  ret = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data,
                          out_data_len);
  // If operation fails, log error to the system log.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", ret);
  }

  // Always free the operation.
  TEE_FreeOperation(aes_operation);
  // Return the result.
  return ret;
}

/*!
* \brief digest_operation Wraps the hash operations in one function.
* \param algorithm        Supported algorithms are defined above for hash
* functions.
* \param in_data          Pointer to the input data buffer.
* \param in_data_len      Size of the input data buffer.
* \param out_data         Pointer for the output data buffer.
* \param out_data_len     Pointer to memory containing the size of the output
* data
* buffer.
*/
static TEE_Result digest_operation(uint32_t algorithm, void *in_data,
                                   uint32_t in_data_len, void *out_data,
                                   uint32_t *out_data_len) {
  // Null initialized handle for the TEE operation.
  TEE_OperationHandle dig_operation = NULL;
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;

  // Allocate the cryptographic operation.
  ret = TEE_AllocateOperation(&dig_operation, algorithm, TEE_MODE_DIGEST, 0);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(dig_operation);
    return ret;
  }

  // Do the digest function with one call. If bigger data encryption is
  // required, will implement pipeline structure.
  ret = TEE_DigestDoFinal(dig_operation, in_data, in_data_len, out_data,
                          out_data_len);
  // If operation fails, log error to the system log.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
  }

  // Always free the operation.
  TEE_FreeOperation(dig_operation);
  // Return the result.
  return ret;
}

/*!
* \brief generate_key  Wraps the key generation operation.
* \param key_size      The size of the key to be generated.
* \param key_type      Type of the key.
* \param params        Parameters to be used with the key generation function.
* \param param_count   Parameter count
* \param outkey        Pointer to witch the generated key will be written.
*/
static TEE_Result generate_key(uint32_t key_size, uint32_t key_type,
                               TEE_ObjectHandle *outkey) {
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;

  // Allocate the cryptographic operation.
  ret = TEE_AllocateTransientObject(key_type, key_size, outkey);
  // If operation fails, log error to the system log, free the operation and
  // return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", ret);
    TEE_FreeTransientObject(*outkey);
    return ret;
  }

  // Generate key according to the parameters given and the type of the
  // transient object.
  ret = TEE_GenerateKey(*outkey, key_size, NULL, 0);
  // If operation fails, log error to the system log.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_GenerateKey failed: 0x%x", ret);
  }

  // Always free the operation.
  TEE_FreeTransientObject(*outkey);
  // Return the result.
  return ret;
}

/*!
* \brief find_available_objectID  Loops through the integer IDs until an empty
* slot is found. The objectID variable is given the resulting value.
*/
static uint32_t find_available_objectID() {
  // Starting at ID = 0
  uint32_t objectID = 0;
  // Null initialized object handle.
  TEE_ObjectHandle object = NULL;
  TEE_Result ret = TEE_SUCCESS;
  // Try to open the persistent object at given ID.
  ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                 sizeof(objectID), 0, &object);
  // Close the object to free it if slot not available. If the first id is
  // available, return.
  if (ret != TEE_SUCCESS) {
    return objectID;
  } else {
    TEE_CloseObject(object);
  }

  // Loop through the IDs one by one.
  while (ret == TEE_SUCCESS) {
    // For code correctness, added upper bound to the number of IDs to 100. This
    // value can be changed accordingly.
    if (objectID >= 100) {
      OT_LOG(
          LOG_ERR,
          "Error infinite loop while searching for ID. Why can this happen?");
    }
    // Increment id counter.
    objectID++;
    // Try to open the persistent object at given ID.
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                   sizeof(objectID), 0, &object);
    // Check for ID availability. If an object is openned, it is closed.
    if (ret != TEE_SUCCESS) {
      break;
    } else {
      TEE_CloseObject(object);
    }
  }
  return objectID;
}

/*!
* \brief store_key  Wraps the key storage operation.
* \param key        The key to be stored.
*/
static TEE_Result store_key(TEE_ObjectHandle key, uint32_t *id_found) {
  // Find available ID for the key to be stored.
  uint32_t id = find_available_objectID();
  // Write the ID of the key on CA returned value variable.
  *id_found = id;
  // Null initialized object handle.
  TEE_ObjectHandle temp = NULL;
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;
  // Create persistent storage object for the given ID in the private storage of
  // the TA.
  ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id), 0, key,
                                   NULL, 0, &temp);
  // If operation fails, log the error and return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", ret);
    *id_found = -1;
    return ret;
  }

  // Always close the object to free it.
  TEE_CloseObject(temp);
  // Return the result.
  return ret;
}

/*!
* \brief get_key  Wraps the operation of getting a key.
* \param key      Pointer to an object that the key will be stored in.
* \param id       The id of the object that the key is stored in.
*/
static TEE_Result get_key(TEE_ObjectHandle *key, uint32_t id) {
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;
  // Null initialized object handle.
  TEE_ObjectHandle temp_key = NULL;

  // Open the persistent object that corresponds to the id.
  ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
                                 TEE_DATA_FLAG_ACCESS_READ, &temp_key);
  // If operation fails, log the error and return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }

  // Null initialized variable that will hold an oject info.
  TEE_ObjectInfo info;
  // Get the object info of the temp_key to retain info about the object to be
  // returned.
  TEE_GetObjectInfo(temp_key, &info);
  // // If operation fails, log the error, close the object and return.
  // if (ret != TEE_SUCCESS) {
  //   OT_LOG(LOG_ERR, "TEE_GetObjectInfo failed: 0x%x", ret);
  //   TEE_CloseObject(temp_key);
  //   return ret;
  // }

  // Allocate a transient object with the info from the previous variable.
  ret = TEE_AllocateTransientObject(info.objectType, info.objectSize, key);
  // If operation fails, log the error, close both objects and return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", ret);
    TEE_CloseObject(temp_key);
    TEE_CloseObject(*key);
    return ret;
  }

  // Copy all the attributes from persistent to transient object. The object
  // type of both objects is the same, so they are compatible and both keys will
  // be copied if RSA.
  TEE_CopyObjectAttributes(*key, temp_key);
  // // If operation fails, log the error.
  // if (ret != TEE_SUCCESS) {
  //   OT_LOG(LOG_ERR, "TEE_CopyObjectAttributes failed: 0x%x", ret);
  // }

  // Always close both objects.
  TEE_CloseObject(*key);
  TEE_CloseObject(temp_key);
  // Return the result.
  return ret;
}

/*!
* \brief do_crypto  Wraps the generic cryptographic operation.
* \param op         Available options: ENCRYPT, DECRYPT.
* \param alg_type   Available options: RSA, AES.
* \param key        The key that will be used for the operation.
* \algorithm        The algorithm that will be used.
* \in_data          Pointer to the input buffer.
* \in_data_len      The length of the input buffer.
* \out_data         Pointer to the output buffer.
* \out_data_len     The length of the output buffer.
*/
static TEE_Result do_crypto(Operation op, Algorithm_type alg_type,
                            TEE_ObjectHandle key, uint32_t algorithm,
                            void *in_data, uint32_t in_data_len, void *out_data,
                            uint32_t *out_data_len) {
  // Null initialized mode.
  TEE_OperationMode mode;
  // Null initialized initialization vector.
  uint8_t *IV = NULL;
  // 0 initialized length.
  uint32_t IV_len = 0;

  // Check for the parameters of the operation.
  if (op != ENCRYPT || op != DECRYPT) {
    // Not recognized operation.
    OT_LOG(LOG_ERR, "Bad cryptographic operation");
    // Return bad parameters.
    return TEE_ERROR_BAD_PARAMETERS;
  } else if (op == ENCRYPT) {
    // Set mode to TEE_MODE_ENCRYPT.
    mode = TEE_MODE_ENCRYPT;
    // Null initialized variable that will hold an oject info.
    TEE_ObjectInfo info;
    // Get info from the key object.
    // TEE_GetObjectInfo(key, &info);
    // // If operation fails, log the error and return.
    // if (ret != TEE_SUCCESS) {
    //   OT_LOG(LOG_ERR, "TEE_GetObjectInfo failed: 0x%x", ret);
    //   return ret;
    // }
    // Set the length of the initialization vector the same size as the key.
    IV_len = (uint32_t)info.objectSize;
    // Generate random vector with given size.
    TEE_GenerateRandom(IV, IV_len);
  } else if (op == DECRYPT) {
    // Set the mode to decrypt.
    mode = TEE_MODE_DECRYPT;
  }

  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;
  // Switch the algorithm types RSA and AES.
  switch (alg_type) {
  case RSA:
    // Call the RSA wrapper.
    ret = RSA_Operation(mode, algorithm, key, in_data, in_data_len, out_data,
                        *out_data_len);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "RSA_Operation failed: 0x%x", ret);
    }
    return ret;
  case AES:
    // Call the AES wrapper.
    ret = AES_operation(mode, algorithm, key, IV, IV_len, in_data, in_data_len,
                        out_data, out_data_len);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "AES_operation failed: 0x%x", ret);
    }
    return ret;
  }
  // Bad algorithm type.
  OT_LOG(LOG_ERR, "Bad algorithm type.");
  return TEE_ERROR_BAD_PARAMETERS;
}

/*!
* \brief do_sign          Wraps the generic signature and verification
* operation.
* \param op               Available options: SIGN, VERIFY.
* \param hash_algorithm   Available algorithms are defined in the beginning of
* the document.
* \param sign_algorithm   Available algorithms are defined in the beginning of
* the document.
* \key                    The key that will be used for the operation.
* \in_data                Pointer to the input buffer.
* \in_data_len            The length of the input buffer.
* \out_data               Pointer to the output buffer.
* \out_data_len           Buffer to the length of the output buffer.
*/
static TEE_Result do_sign(Operation op, uint32_t hash_algorithm,
                          uint32_t sign_algorithm, TEE_ObjectHandle key,
                          void *in_data, uint32_t in_data_len, void *out_data,
                          uint32_t *out_data_len) {
  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;
  // Parameter check.
  if (op != SIGN || op != VERIFY) {
    // Not recognized operation.
    OT_LOG(LOG_ERR, "Bad sign/verify operation.");
    // Return bad parameters.
    return TEE_ERROR_BAD_PARAMETERS;
  } else if (op == SIGN) {
    // Call the digest operation wrapper to get the hash of the input data.
    ret = digest_operation(hash_algorithm, in_data, in_data_len, out_data,
                           out_data_len);
    // If operation fails, log the error and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at digest_operation: 0x%x", ret);
      return ret;
    }

    // Call the RSA signature operation with given hash and key.
    ret = RSA_Operation(TEE_MODE_SIGN, sign_algorithm, key, out_data,
                        *out_data_len, out_data, *out_data_len);
    // If operation fails, log the error and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at RSA_Operation: 0x%x", ret);
      return ret;
    }
  } else if (op == VERIFY) {
    // Call the digest operation wrapper to get the hash of the input data.
    ret = digest_operation(hash_algorithm, out_data, *out_data_len, out_data,
                           out_data_len);
    // If operation fails, log the error and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at digest_operation: 0x%x", ret);
      return ret;
    }

    // Call the RSA verification operation with given hash and key.
    ret = RSA_Operation(TEE_MODE_VERIFY, sign_algorithm, key, out_data,
                        *out_data_len, in_data, in_data_len);
    // If operation fails, log the error and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at RSA_Operation: 0x%x", ret);
      return ret;
    }
  }

  // Return the result.
  return ret;
}

/*                                 *
*                                  *
* Implement the TEE api functions. *
*                                  *
*                                 */

TEE_Result TA_EXPORT TA_CreateEntryPoint(void) {
  OT_LOG(LOG_ERR, "Calling the create entry point");

  return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void) {
  OT_LOG(LOG_ERR, "Calling the Destroy entry point");
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
                                              TEE_Param params[4],
                                              void **sessionContext) {
  OT_LOG(LOG_ERR, "Calling the Open session entry point");
  paramTypes = paramTypes;
  params = params;
  sessionContext = sessionContext;

  return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) {
  sessionContext = sessionContext;
  OT_LOG(LOG_DEBUG, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
                                                uint32_t commandID,
                                                uint32_t paramTypes,
                                                TEE_Param params[4]) {
  sessionContext = sessionContext;
  // Parameter Check.
  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT ||
      TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INOUT) {
    OT_LOG(LOG_ERR, "Error bad parameters, params[0] and params[1] must be: "
                    "TEE_PARAM_TYPE_VALUE_INOUT");
    return TEE_ERROR_BAD_PARAMETERS;
  }
  // Parameter Check.
  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT ||
      TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) {
    OT_LOG(LOG_ERR, "Error bad parameters, params[2] and params[3] must be: "
                    "TEE_PARAM_TYPE_MEMREF_INOUT");
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // TEE_Result initialized as a success. On failure the value is changed
  // accordingly.
  TEE_Result ret = TEE_SUCCESS;

  // Switch available commands.
  if (commandID == ENCRYPTION) {
    // Null initialized object handle to the key.
    TEE_ObjectHandle key = NULL;
    // Get the key from given id.
    ret = get_key(&key, params[0].value.a);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Get key operation failed");
      return ret;
    }
    // Output buffer size.
    uint32_t out_size;
    // Call cryptographic operation.
    ret = do_crypto(ENCRYPT, params[0].value.b, key, params[1].value.a,
                    params[2].memref.buffer, params[2].memref.size,
                    params[3].memref.buffer, &out_size);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS || out_size == 0) {
      OT_LOG(LOG_ERR, "Encryption operation failed");
    }
    // Free the transient object.
    TEE_FreeTransientObject(key);
    // Return the result.
    return ret;
  } else if (commandID == DECRYPTION) {
    // Null initialized object handle to the key.
    TEE_ObjectHandle key = NULL;
    // Get the key from given id.
    ret = get_key(&key, params[0].value.a);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Get key operation failed");
      return ret;
    }

    // Call cryptographic operation.
    ret =
        do_crypto(DECRYPT, params[0].value.b, key, params[1].value.a,
                  params[2].memref.buffer, params[2].memref.size,
                  params[3].memref.buffer, (uint32_t *)&params[3].memref.size);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS || params[3].memref.size == 0) {
      OT_LOG(LOG_ERR, "Decryption operation failed");
    }
    // Free the transient object.
    TEE_FreeTransientObject(key);
    // Return the result.
    return ret;
  } else if (commandID == SIGNATURE) {
    // Null initialized object handle to the key.
    TEE_ObjectHandle key = NULL;
    // Get the key from given id.
    ret = get_key(&key, params[0].value.a);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Get key operation failed");
      return ret;
    }
    // Output buffer size.
    uint32_t out_size;
    // Call signing operation.
    ret = do_sign(SIGN, params[0].value.b, params[1].value.a, key,
                  params[2].memref.buffer, params[2].memref.size,
                  params[3].memref.buffer, &out_size);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS || out_size == 0) {
      OT_LOG(LOG_ERR, "Signature operation failed");
    }

    // Free the transient object.
    TEE_FreeTransientObject(key);
    // Return the result.
    return ret;
  } else if (commandID == VERIFICATION) {
    // Null initialized object handle to the key.
    TEE_ObjectHandle key = NULL;
    // Get the key from given id.
    ret = get_key(&key, params[0].value.a);
    // If operation fails, log and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Get key operation failed");
      return ret;
    }
    // Output buffer size.
    uint32_t out_size = params[3].memref.size;
    // Call verification operation.
    ret = do_sign(SIGN, params[0].value.b, params[1].value.a, key,
                  params[2].memref.buffer, params[2].memref.size,
                  params[3].memref.buffer, &out_size);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS || out_size == 0) {
      OT_LOG(LOG_ERR, "Verification operation failed");
    }

    // Free the transient object.
    TEE_FreeTransientObject(key);
    // Return the result.
    return ret;
  } else if (commandID == HASH) {
    // Output buffer size.
    uint32_t out_size;
    // Call hash operation.
    digest_operation(params[0].value.a, params[2].memref.buffer,
                     params[2].memref.size, params[3].memref.buffer, &out_size);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS || out_size == 0) {
      OT_LOG(LOG_ERR, "Hash operation failed");
    }
    return ret;
  } else if (commandID == KEYGENERATION) {
    // Null initialized object handle to the key.
    TEE_ObjectHandle key = NULL;
    // Call key generation operation.
    ret = generate_key(params[0].value.a, params[0].value.b, &key);
    // If operation fails, log the error and return.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Key generation operation failed");
      return ret;
    }

    // Call key storage operation.
    ret = store_key(key, &params[0].value.a);
    // If operation fails, log the error.
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Key storage operation failed");
    }

    // Always free the object.
    TEE_FreeTransientObject(key);
    // Return the result.
    return ret;
  } else {
    OT_LOG(LOG_ERR, "Bad command.");
    return TEE_ERROR_BAD_PARAMETERS;
  }
}

/*
*
* Should the secret keys be encrypted?
*
*/
// static TEE_Result encrypt_private_key(TEE_ObjectHandle *encrypted_key,
//                                       uint32_t *encrypted_key_size,
//                                       TEE_ObjectHandle aes_encryption_key) {
//   TEE_OperationMode mode = TEE_MODE_ENCRYPT;
//   uint32_t algorithm = TEE_ALG_AES_ECB_NOPAD;
//   TEE_Result ret = TEE_SUCCESS;
//   uint8_t *key;
//   uint32_t *key_size;
//   ret = TEE_GetObjectBufferAttribute(*encrypted_key, TEE_ATTR_SECRET_VALUE,
//   key,
//                                      key_size);
//
//   if (ret != TEE_SUCCESS) {
//     OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed: 0x%x", ret);
//     return ret;
//   }
//
//   ret = AES_operation(mode, algorithm, aes_encryption_key, NULL, NULL, 0, 0,
//                       key, *key_size, key, key_size);
//   if (ret != TEE_SUCCESS) {
//     OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed: 0x%x", ret);
//   }
//
//   return ret;
// }
