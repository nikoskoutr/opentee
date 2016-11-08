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
    0x25081234, 0x4132, 0x5532, {'k', 'e', 'y', 's', 't', 'o', 'r', 'e'}};

int main() {
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
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
  -

      printf("-- Invoking command: Key Generation:\n");
  ret = TEEC_InvokeCommand(&session, KEYGENERATION, &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error generating key 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  uint32_t key_id = operation.params[0].value.a;
  printf("-- Key generation successful, the key id is: %d\n", key_id);

  printf("-- Registering shared memories.\n");
  char *p = malloc(10);
  char *result = malloc(40);

  memset((void *)&in_mem, 'z', sizeof(in_mem));
  memset((void *)&out_mem, 'z', sizeof(out_mem));
  memset(p, 'z', 10);
  memset(result, 'z', 40);

  in_mem.buffer = p;
  in_mem.size = 10;
  in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

  out_mem.buffer = result;
  out_mem.size = 40;
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

  printf("++ Enter key to encrypt:\n");
  fflush(stdout);

  char line[10];
  p = fgets(line, 10, stdin);

  operation.params[2].memref.parent = &in_mem;
  operation.params[3].memref.parent = &out_mem;

  printf("-- Encrypting with generated RSA key.");
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
  printf("-- The encrypted string is: %s\n", result);

  printf("-- Decrypting with generated RSA key.");
  in_mem.buffer = result;
  in_mem.size = 40;

  out_mem.buffer = p;
  out_mem.size = 10;

  ret = TEEC_InvokeCommand(&session, DECRYPTION, &operation, NULL);
  if (ret != TEEC_SUCCESS) {
    printf("!! Error decrypting 0x%x\n", ret);
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }

  printf("-- Test operation ended successfuly");
  TEEC_CloseSession(&session);
  TEEC_FinalizeContext(&context);
  return 0;
}
