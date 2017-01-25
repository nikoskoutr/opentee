#include "ta_key_storage.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

struct keychain_data {
  uint32_t key_count;
  uint32_t key_length;
  uint8_t keys[];
}

struct session_ctx {
  uint8_t session_type;
};

/* VaLid session types */
#define CTX_TYPE_CREATE_ROOT_DIR 0x23
#define CTX_TYPE_DO_CRYPTO 0x24

static TEE_ObjectHandle rsa_keypair_object;
static TEE_ObjectHandle aes_key_object;

#define BYTES2BITS(bytes) (bytes * 8)

#define RSA_MODULO_SIZE 128
#define AES_SIZE 32
#define AES_IV_SIZE 16

static uint8_t aes_iv[OMS_AES_IV_SIZE];

// FLAGS: To be used with the peristent objects used.
static uint32_t FLAGS = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
                        TEE_DATA_FLAG_OVERWRITE |
                        TEE_DATA_FLAG_ACCESS_WRITE_META;

// ojbectID: The ID of the object that is handled with global scope to be used
// by more than one functions.
uint32_t objectID;

// *returnKeyBuffer: Pointer to the output buffer provided by the CA caller.
void *returnKeyBuffer;

/*
*
* Application specific functions
*
*/

static TEE_Result RSA_Operation(TEE_OperationMode mode, void *in_data,
                                uint32_t in_data_len, void *out_data,
                                uint32_t out_data_len) {
  TEE_OperationHandle rsa_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&rsa_operation, TEE_ALG_RSAES_PKCS1_V1_5, mode,
                              BYTES2BITS(RSA_MODULO_SIZE));
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", ret);
    goto err;
  }

  ret = TEE_SetOperationKey(rsa_operation, rsa_keypair_object);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    goto err;
  }

  if (mode == TEE_MODE_ENCRYPT) {
    ret = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed : 0x%x", ret);
      goto err;
    }

  } else if (mode == TEE_MODE_DECRYPT) {
    ret = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, in_data_len,
                                out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt failed : 0x%x", ret);
      goto err;
    }

  } else if (mode == TEE_MODE_SIGN) {

  } else if (mode == TEE_MODE_VERIFY) {
    OT_LOG(LOG_ERR, "Unkown RSA mode type");
    goto err;
  }
err:
  TEE_FreeOperation(rsa_operation);
  return tee_rv;
}

static TEE_Result aes_operation(TEE_ObjectHandle key, TEE_OperationMode mode,
                                uint32_t aes_algorithm, void *IV,
                                uint32_t IV_len, void *in_data,
                                uint32_t in_data_len, void *out_data,
                                uint32_t *out_data_len) {
  TEE_OperationHandle aes_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  tee_rv = TEE_AllocateOperation(&aes_operation, aes_algorithm, mode,
                                 BYTES2BITS(OMS_AES_SIZE));
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateOperation failed (TEE_ALG_AES_CTR) : 0x%x",
           ret);
    goto err;
  }

  ret = TEE_SetOperationKey(aes_operation, key);
  if (tee_rv != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", ret);
    goto err;
  }

  if (algorithm != TEE_ALG_AES_ECB_NOPAD) {
    TEE_CipherInit(aes_operation, IV, IV_len);
  } else {
    TEE_CipherInit(aes_operation, NULL, 0);
  }

  /* TA is supporting only small files and therefore there is no need for
   * "pipeline" style encrypting or decrypting. The do final can do it in one go
   */
  ret = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data,
                          out_data_len);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", ret);
  }

err:
  /* Freeing operation. TEE_FreeOperation: TEE Core API p-144 */
  TEE_FreeOperation(aes_operation);
  return tee_rv;
}

static TEE_Result create_aes_key(uint8_t *aes_key, uint32_t *aes_key_size,
                                 TEE_ObjectHandle *aes_key_object) {
  TEE_ObjectHandle new_aes_key_object = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateTransientObject(TEE_TYPE_AES, BYTES2BITS(OMS_AES_SIZE),
                                    &new_aes_key_object);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", ret);
    goto err;
  }

  ret = TEE_GenerateKey(new_aes_key_object, BYTES2BITS(OMS_AES_SIZE), NULL, 0);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_Gener ateKey failed : 0x%x", ret);
    goto err;
  }

  if (aes_key) {
    if (aes_key_size == NULL) {
      OT_LOG(LOG_ERR, "Aes key buffer is not NULL, but key size is NULL");
      ret = TEE_ERROR_BAD_PARAMETERS;
      goto err;
    }
    ret = TEE_GetObjectBufferAttribute(
        new_aes_key_object, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

    if (ret != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed: 0x%x", ret);
      goto err;
    }
  }

  if (aes_key_object)
    *aes_key_object = new_aes_key_object;
  else
    TEE_FreeTransientObject(new_aes_key_object); /* see below at err -label */

  return ret;

err:
  TEE_FreeTransientObject(new_aes_key_object);
  if (aes_key && aes_key_size) {
    TEE_MemFill(aes_key, 0, *aes_key_size);
    *aes_key_size = 0;
  }
  return tee_rv;
}

// Loops through the integer IDs until an empty slot is found. The objectID
// variable is given the resulting value.
static void find_available_objectID() {
  objectID = 0; // Starting at ID = 0
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                            sizeof(objectID), FLAGS, &object);
  // Close the object to free it if not available. If the first id is available,
  // return.
  if (ret != TEE_SUCCESS) {
    return;
  } else {
    TEE_CloseObject(object);
  }

  // Loop through the IDs one by one.
  while (ret == TEE_SUCCESS) {
    objectID++;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                   sizeof(objectID), FLAGS, &object);
    // Check for ID availability. If an object is openned, it is closed.
    if (ret != TEE_SUCCESS) {
      return;
    } else {
      TEE_CloseObject(object);
    }
  }
}

// Function for storing a key on any available storageID. The
// find_available_objectID() function is used.
static TEE_Result store_key(uint64_t *key) {
  find_available_objectID();
  TEE_ObjectHandle object;

  // Create persistent object with initial value *key.
  TEE_Result ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                              sizeof(objectID), FLAGS, NULL,
                                              key, sizeof(*key), &object);

  // If fail, log the error, close the object and return. Else, close the object
  // and return.
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", ret);
    // TEE_CloseObject(object);
    return ret;
  }

  TEE_CloseObject(object);
  return ret;
}

// Function to remove key at the id position.
static TEE_Result remove_key(uint32_t id) {
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id,
                                            sizeof(id), FLAGS, &object);
  if (ret != TEE_SUCCESS) {
    // TEE_CloseObject(object);
    // Object not found.
    OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }
  // Close and delete object.
  TEE_CloseAndDeletePersistentObject(object);
  return ret;
}

// Function to update existing key.
static TEE_Result update_key(uint64_t *key, uint32_t id) {
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id,
                                            sizeof(id), FLAGS, &object);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }

  // Set the buffer pointer to the beginning of the object.
  ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SeekObjectData failed: 0x%x", ret);
    return ret;
  }

  // Write data to the object.
  ret = TEE_WriteObjectData(object, key, sizeof(*key));
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_WriteObjectData failed: 0x%x\n", ret);
    return ret;
  }
  TEE_CloseObject(object);
  return ret;
}

// Get the value of a key.
static TEE_Result get_key(uint32_t id) {
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id,
                                            sizeof(id), FLAGS, &object);

  TEE_ObjectInfo objectInfo;
  TEE_GetObjectInfo(object, &objectInfo);

  OT_LOG_INT(objectInfo.objectType);

  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }

  // Set the buffer pointer to the beginning of the object.
  ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_SeekObjectData failed: 0x%x", ret);
    return ret;
  }

  uint32_t count;
  // Read data.
  ret = TEE_ReadObjectData(object, returnKeyBuffer, 80, &count);
  if (ret != TEE_SUCCESS) {
    OT_LOG(LOG_ERR, "TEE_ReadObjectData failed: 0x%x", ret);
    return ret;
  }
  TEE_CloseObject(object);
  return ret;
}

// No functionality.
TEE_Result TA_EXPORT TA_CreateEntryPoint(void) {
  OT_LOG(LOG_ERR, "Calling the create entry point");

  return TEE_SUCCESS;
}

// No functionality.
void TA_EXPORT TA_DestroyEntryPoint(void) {
  OT_LOG(LOG_ERR, "Calling the Destroy entry point");
}

// No functionality.
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
                                              TEE_Param params[4],
                                              void **sessionContext) {
  // paramTypes = paramTypes;
  // sessionContext = sessionContext;
  // params = params;
  OT_LOG(LOG_ERR, "Calling the Open session entry point");
  return TEE_SUCCESS;
}

// No functionality.
void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) {
  // sessionContext = sessionContext;
  OT_LOG(LOG_DEBUG, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
                                                uint32_t commandID,
                                                uint32_t paramTypes,
                                                TEE_Param params[4]) {
  TEE_Result ret = TEE_SUCCESS;
  // sessionContext = sessionContext;
  OT_LOG(LOG_ERR, "Calling the Invoke command entry point");
  // Check parameter type.
  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) {
    OT_LOG(LOG_ERR, "Expected buffer input type as index 0 parameter");
    ret = TEE_ERROR_BAD_PARAMETERS;
    return ret;
  }

  switch (commandID) {
  case STORE_KEY_COMMAND:
    OT_LOG(LOG_DEBUG, "Command: Store key");
    ret = store_key((uint64_t *)(params[0].memref.buffer));
    params[1].value.a = objectID;
    break;
  case GET_KEY_COMMAND:
    OT_LOG(LOG_DEBUG, "Command: Get key");
    returnKeyBuffer = params[0].memref.buffer;
    ret = get_key((uint32_t)(params[1].value.a));
    break;
  case UPDATE_KEY_COMMAND:
    OT_LOG(LOG_DEBUG, "Command: Update key");
    ret = update_key((uint64_t *)(params[0].memref.buffer),
                     (uint32_t)(params[1].value.a));
    break;
  case REMOVE_KEY_COMMAND:
    OT_LOG(LOG_DEBUG, "Command: Remove key");
    ret = remove_key((uint32_t)(params[1].value.a));
    break;
  case DUMMY_TEST:
    OT_LOG(LOG_DEBUG, "DUMMY TEST");
    params[1].value.a = 1254125411;
    uint32_t fill = 5;
    // uint64_t *test = params[0].memref.buffer;
    //*test = 5 * 5 * 5 * 5 * 5 * 5 * 5;
    // uint32_t *temp = params[0].memref.buffer;
    // int i = 0;
    // while (i <  params[0].memref.size{
    //   i++;
    //   *temp = 5;
    //   temp++;
    // }
    memset(params[0].memref.buffer, '5', params[0].memref.size);
    ret = TEE_SUCCESS;
    break;
  default:
    OT_LOG(LOG_ERR, "Unknown command");
    break;
  }

  return ret;
}
