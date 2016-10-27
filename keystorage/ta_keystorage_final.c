#include "ta_key_storage.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

#define BYTES2BITS(bytes) (bytes * 8)
#define MAX_RSA_KEYSIZE 1024
#define MAX_AES_KEYSIZE 256

typedef enum {
  ENCRYPTION = 0,
  DECRYPTION = 1,
  SIGNATURE = 2,
  VERIFICATION = 3,
  HASH = 4
}

typedef enum {
  DECRYPT = 0,
  ENCRYPT = 1,
  SIGN = 2,
  VERIFY = 3,
  DIGEST = 4
} Operation;

typedef enum { RSA = 0, AES = 1 } Algorithm_type;

#define ALG_CHECK

static TEE_Result RSA_Operation(TEE_OperationMode mode, uint32_t algorithm,
                                TEE_ObjectHandle key, void *in_data,
                                uint32_t in_data_len, void *out_data,
                                uint32_t out_data_len) {
  TEE_OperationHandle rsa_operation = NULL;
  ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&rsa_operation, algorithm, mode, MAX_RSA_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  ret = TEE_SetOperationKey(rsa_operation, key);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  switch (mode) {
  case TEE_MODE_ENCRYPT:
    ret = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed: 0x%x", ret);
    }
    break;
  case TEE_MODE_DECRYPT:
    ret = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt failed: 0x%x", ret);
    }
    break;
  case TEE_MODE_SIGN:
    ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, in_data, in_data_len,
                                   out_data, &out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricSignDigest failed: 0x%x", ret);
    }
    break;
  case TEE_MODE_VERIFY:
    ret = TEE_AsymmetricVerifyDigest(rsa_operation, NULL, 0, in_data,
                                     in_data_len, out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricVerifyDigest failed: 0x%x", ret);
    }
    break;
  default:
    OT_LOG(LOG_ERR, "Unkown RSA mode type");
  }

  TEE_FreeOperation(rsa_operation);
  return ret;
}

static TEE_Result AES_operation(TEE_OperationMode mode, uint32_t algorithm,
                                TEE_ObjectHandle key, void *IV, uint32_t IV_len,
                                void *in_data, uint32_t in_data_len,
                                void *out_data, uint32_t *out_data_len) {
  TEE_OperationHandle aes_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&aes_operation, algorithm, mode, MAX_AES_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  ret = TEE_SetOperationKey(aes_operation, key);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  TEE_CipherInit(aes_operation, IV, IV_len);
  ret = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data,
                          out_data_len);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", ret);
  }

  TEE_FreeOperation(aes_operation);
  return ret;
}

static TEE_Result digest_operation(uint32_t algorithm, void *in_data,
                                   uint32_t in_data_len, void *out_data,
                                   uint32_t *out_data_len) {
  TEE_OperationHandle dig_operation = NULL;
  TEE_Result = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&dig_operation, algorithm, TEE_MODE_DIGEST, 0);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(dig_operation);
    return ret;
  }

  ret = TEE_DigestDoFinal(dig_operation, in_data, in_data_len, out_data,
                          out_data_len);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
  }

  TEE_FreeOperation(dig_operation);
  return ret;
}

static TEE_Result generate_key(uint32_t key_size, uint32_t key_type,
                               TEE_Attribute *params, uint32_t param_count,
                               TEE_ObjectHandle *outkey) {
  TEE_Result = TEE_SUCCESS;

  ret = TEE_AllocateTransientObject(key_type, key_size, outkey);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", ret);
    TEE_FreeTransientObject(*outkey);
    return ret;
  }

  ret = TEE_GenerateKey(*outkey, key_size, params, param_count);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_GenerateKey failed: 0x%x", ret);
  }

  TEE_FreeTransientObject(*outkey);
  return ret;
}

// Loops through the integer IDs until an empty slot is found. The objectID
// variable is given the resulting value.
static uint32_t find_available_objectID() {
  uint32_t objectID = 0; // Starting at ID = 0
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                            sizeof(objectID), 0, &object);
  // Close the object to free it if not available. If the first id is available,
  // return.
  if (ret != TEE_SUCCESS) {
    return objectID;
  } else {
    TEE_CloseObject(object);
  }

  // Loop through the IDs one by one.
  while (ret == TEE_SUCCESS) {
    objectID++;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                   sizeof(objectID), 0, &object);
    // Check for ID availability. If an object is openned, it is closed.
    if (ret != TEE_SUCCESS) {
      return objectID;
    } else {
      TEE_CloseObject(object);
    }
  }
}

static TEE_Result store_key(TEE_ObjectHandle key) {
  uint32_t id = find_available_objectID();
  TEE_ObjectHandle temp = NULL;
  TEE_Result ret = TEE_SUCCESS;
  ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id), 0, key,
                                   NULL, 0, &temp);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", ret);
    return ret;
  }

  TEE_CloseObject(temp);
  return ret;
}

static TEE_Result get_key(TEE_ObjectHandle *key, uint32_t id) {
  TEE_Result = TEE_SUCCESS;
  TEE_ObjectHandle temp_key = NULL;

  ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
                                 TEE_DATA_FLAG_ACCESS_READ, &temp_key);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }

  TEE_ObjectInfo info = null;
  ret = TEE_GetObjectInfo(temp_key, &info);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_GetObjectInfo failed: 0x%x", ret);
    TEE_CloseObject(temp_key);
    return ret;
  }

  ret = TEE_AllocateTransientObject(info.objectType, info.objectSize, key);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", ret);
    TEE_CloseObject(temp_key);
    TEE_CloseObject(*key);
    return ret;
  }

  ret = TEE_CopyObjectAttributes(*key, temp_key);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CopyObjectAttributes failed: 0x%x", ret);
    TEE_CloseObject(*key);
  }
  TEE_CloseObject(temp_key);
  return ret;
}

static TEE_Result do_crypto(Operation op, Algorithm_type alg_type,
                            TEE_ObjectHandle key, uint32_t algorithm,
                            void *in_data, uint32_t in_data_len, void *out_data,
                            uint32_t *out_data_len) {
  TEE_OperationMode mode = NULL;
  uint8_t *IV = NULL;
  uint32_t IV_len = 0;
  if (op != ENCRYPT || op != DECRYPT) {
    OT_LOG(LOG_ERR, "Bad cryptographic operation");
    return TEE_ERROR_BAD_PARAMETERS;
  } else if (op == ENCRYPT) {
    mode = TEE_MODE_ENCRYPT;
    ret = TEE_GetObjectInfo(key, &info);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_GetObjectInfo failed: 0x%x", ret);
      return ret;
    }
    IV_len = (uint32_t)info.objectSize;
    TEE_GenerateRandom(IV, IV_len);
  } else if (op == DECRYPT) {
    mode = TEE_MODE_DECRYPT;
  }

  TEE_Result = TEE_SUCCESS;
  switch (alg_type) {
  case RSA:
    ret = RSA_Operation(mode, algorithm, key, in_data, in_data_len, out_data,
                        *out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "RSA_Operation failed: 0x%x", ret);
    }
    return ret;
  case AES:
    ret = AES_operation(mode, algorithm, key, IV, IV_len, in_data, in_data_len,
                        out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "AES_operation failed: 0x%x", ret);
    }
    return ret;
  }
}

static TEE_Result do_sign(Operation op, uint32_t hash_algorithm,
                          uint32_t sign_algorithm, TEE_ObjectHandle key,
                          void *in_data, uint32_t in_data_len, void *out_data,
                          uint32_t *out_data_len) {
  TEE_Result ret = TEE_SUCCESS;
  if (op != SIGN || op != VERIFY) {
    OT_LOG(LOG_ERR, "Bad sign/verify operation.");
    return TEE_ERROR_BAD_PARAMETERS;
  } else if (op == SIGN) {
    ret = digest_operation(hash_algorithm, in_data, in_data_len, out_data,
                           out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at digest_operation: 0x%x", ret);
      return ret;
    }

    ret = RSA_Operation(TEE_MODE_SIGN, algorithm, key, out_data, *out_data_len,
                        out_data, *out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at RSA_Operation: 0x%x", ret);
      return ret;
    }
  } else if (op == VERIFY) {
    ret = digest_operation(hash_algorithm, out_data, *out_data_len, out_data,
                           out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at digest_operation: 0x%x", ret);
      return ret;
    }

    ret = RSA_Operation(TEE_MODE_VERIFY, algorithm, key, out_data,
                        *out_data_len, in_data, in_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Error at RSA_Operation: 0x%x", ret);
      return ret;
    }
  }
  return ret;
}

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
  // paramTypes = paramTypes;
  // sessionContext = sessionContext;
  // params = params;
  OT_LOG(LOG_ERR, "Calling the Open session entry point");
  return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) {
  // sessionContext = sessionContext;
  OT_LOG(LOG_DEBUG, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
                                                uint32_t commandID,
                                                uint32_t paramTypes,
                                                TEE_Param params[4]) {
  // Parameter Check
  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT ||
      TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INOUT) {
    OT_LOG(LOG_ERR, "Error bad parameters, params[0] and params[1] must be: "
                    "TEE_PARAM_TYPE_VALUE_INOUT");
    return TEE_ERROR_BAD_PARAMETERS;
  }

  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT ||
      TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) {
    OT_LOG(LOG_ERR, "Error bad parameters, params[2] and params[3] must be: "
                    "TEE_PARAM_TYPE_MEMREF_INOUT");
    return TEE_ERROR_BAD_PARAMETERS;
  }

  TEE_Result ret = TEE_SUCCESS;

  switch (commandID) {
  case ENCRYPTION:
    ret = do_crypto(ENCRYPT, parms[0].value.a, ) break;
  case DECRYPTION:
    break;
  case SIGNATURE:
    break;
  case VERIFICATION:
    break;
  case HASH:
    break;
  }
}

/*
** SUPPORTED ALGORITHMS **
** AES CRYPTO **
*** TEE_ALG_AES_ECB_NOPAD
*** TEE_ALG_AES_CBC_NOPAD
*** TEE_ALG_AES_CTR
*
** RSA CRYPTO **
*** TEE_ALG_RSA_NOPAD
*** TEE_ALG_RSAES_PKCS1_V1_5
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256
*** TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1
*
** RSA SIGN **
*** TEE_ALG_RSASSA_PKCS1_V1_5_MD5
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA1
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
*** TEE_ALG_RSASSA_PKCS1_V1_5_SHA512
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256
*** TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512
*
** HASH **
*** TEE_ALG_MD5
*** TEE_ALG_SHA1
*** TEE_ALG_SHA256
*** TEE_ALG_SHA512
*/
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
