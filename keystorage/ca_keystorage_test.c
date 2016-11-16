#include "tee_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Available commands
#define ENCRYPTION 0
#define DECRYPTION 1
#define SIGNATURE 2
#define VERIFICATION 3
#define HASH 4
#define KEYGENERATION 5

#define TEE_TYPE_RSA_KEYPAIR 0xA1000030
#define TEE_ALG_RSA_NOPAD 0x60000030

typedef enum { RSA = 0, AES = 1 } Algorithm_type;

static const TEEC_UUID uuid = {
    0x3E93872E, 0xAAB0, 0x4C7E, {'K', 'E', 'Y', 'S', 'T', 'O', 'R', 'E'}};

int main() {
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation = {0};
  TEEC_SharedMemory in_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result ret;

  printf("-- Initializing context.\n");
  ret = TEEC_InitializeContext(NULL, &context);
  if (ret != TEEC_SUCCESS) {
    printf("!! TEEC_InitializeContext failed: 0x%x\n", ret);
    return 0;
  }

  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT,
                                          TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);
  operation.params[0].value.a = 256;
  operation.params[0].value.b = TEE_TYPE_RSA_KEYPAIR;
  operation.params[1].value.a = 0;
  operation.params[1].value.b = 0;

  printf("-- Opening session.\n");
  ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                         &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  char *p = malloc(32);
  char *result = malloc(100);

  memset((void *)&in_mem, 'z', sizeof(in_mem));
  memset((void *)&out_mem, 'z', sizeof(out_mem));
  memset(p, 'z', 32);
  memset(result, 'z', 100);

  printf("-- Registering shared memories.\n");

  in_mem.buffer = p;
  in_mem.size = 32;
  in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

  out_mem.buffer = result;
  out_mem.size = 100;
  out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

  ret = TEEC_RegisterSharedMemory(&context, &in_mem);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error registering input memory 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  ret = TEEC_RegisterSharedMemory(&context, &out_mem);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error registering output memory 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  operation.params[2].memref.parent = &in_mem;
  operation.params[3].memref.parent = &out_mem;

  printf("-- Invoking command: Key Generation:\n");
  ret = TEEC_InvokeCommand(&session, KEYGENERATION, &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error generating key 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  uint32_t key_id = operation.params[0].value.a;
  printf("-- Key generation successful, the key id is: %d\n-- And the rsa "
         "modulo is: %d\n",
         key_id, operation.params[1].value.b);

  printf("++ Enter key to encrypt:\n");

  fgets(p, 20, stdin);

  printf("-- Encrypting with generated RSA key.\n");
  operation.params[0].value.a = key_id;
  operation.params[0].value.b = RSA;
  operation.params[1].value.a = TEE_ALG_RSA_NOPAD;
  ret = TEEC_InvokeCommand(&session, ENCRYPTION, &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error encrypting 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  printf("-- Successful encryption\n");
  printf("-- The encrypted string is: %s\n-- And it's size is:%d\n",
         (char *)result, (uint32_t)operation.params[3].memref.size);

  operation.params[2].memref.parent = &in_mem;
  operation.params[3].memref.parent = &out_mem;

  printf("-- Decrypting with generated RSA key.\n");

  TEEC_ReleaseSharedMemory(&out_mem);
  TEEC_ReleaseSharedMemory(&in_mem);

  in_mem.buffer = result;
  out_mem.buffer = p;

  ret = TEEC_RegisterSharedMemory(&context, &out_mem);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error registering output memory 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  ret = TEEC_RegisterSharedMemory(&context, &in_mem);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error registering input memory 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  memset(p, 'z', 32);
  printf("-- Buffer before decryption %s\n", p);
  ret = TEEC_InvokeCommand(&session, DECRYPTION, &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error decrypting 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  printf("-- The decrypted string is: %s\n-- And it's size is:%d\n", (char *)p,
         (uint32_t)operation.params[2].memref.size);

  printf("-- Test operation ended successfuly");
  TEEC_CloseSession(&session);
  TEEC_FinalizeContext(&context);
  return 0;
}
