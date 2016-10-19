#include "TA_key_storage.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

// FLAGS: To be used with the peristent objects used.
static uint32_t FLAGS = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
                        TEE_DATA_FLAG_OVERWRITE |
                        TEE_DATA_FLAG_ACCESS_WRITE_META;

// ojbectID: The ID of the object that is handled with global scope to be used
// by more than one functions.
uint32_t objectID;

// *returnKeyBuffer: Pointer to the output buffer provided by the CA caller.
void *returnKeyBuffer;

// Loops through the integer IDs until an empty slot is found. The objectID
// variable is given the resulting value.
static void find_available_objectID() {
  objectID = 0; // Starting at ID = 0
  TEE_ObjectHandle object;
  TEE_Result ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                            sizeof(objectID), FLAGS, &object);
  // Close the object to free it. If the first id is available, return.
  TEE_CloseObject(object);
  if (ret != TEE_SUCCESS) {
    return;
  }

  // Loop through the IDs one by one.
  while (ret == TEE_SUCCESS) {
    objectID++;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID,
                                   sizeof(objectID), FLAGS, &object);
    // Always close the object first, then check for ID availability. If so,
    // return.
    TEE_CloseObject(object);
    if (ret != TEE_SUCCESS) {
      return;
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
    TEE_CloseObject(object);
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
    TEE_CloseObject(object);
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
  ret = TEE_ReadObjectData(object, returnKeyBuffer, sizeof(*returnKeyBuffer),
                           &count);
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
  paramTypes = paramTypes;
  sessionContext = sessionContext;
  params = params;
  OT_LOG(LOG_ERR, "Calling the Open session entry point");
  return TEE_SUCCESS;
}

// No functionality.
void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) {
  sessionContext = sessionContext;
  OT_LOG(LOG_DEBUG, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
                                                uint32_t commandID,
                                                uint32_t paramTypes,
                                                TEE_Param params[4]) {
  TEE_Result ret = TEE_SUCCESS;
  sessionContext = sessionContext;
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
  default:
    OT_LOG(LOG_ERR, "Unknown command");
    break;
  }

  return ret;
}
