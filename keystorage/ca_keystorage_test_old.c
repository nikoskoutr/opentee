//#include "ca_keystorage_test.h"
#include "tee_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INVOKE_COMMAND_STOREKEY 0
#define INVOKE_COMMAND_GETKEY 1
#define INVOKE_COMMAND_REMOVEKEY 2
#define INVOKE_COMMAND_UPDATEKEY 3
#define DUMMY_TEST 4

#define PRI(str, ...) printf(str, ##__VA_ARGS__);
#define PRIn(str, ...) printf(str "\n", ##__VA_ARGS__);
#define DATA_SIZE 10

static const TEEC_UUID uuid = {
    0x25081234, 0x4132, 0x5532, {'k', 'e', 'y', 's', 't', 'o', 'r', 'e'}};

int main() {
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
  TEEC_SharedMemory inout_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result tee_rv;
  uint8_t data[DATA_SIZE];

  memset((void *)(&inout_mem), 0, sizeof(inout_mem));
  memset((void *)&out_mem, 0, sizeof(out_mem));
  memset((void *)&operation, 0, sizeof(operation));
  memset(data, 'y', sizeof(data));

  tee_rv = TEEC_InitializeContext(NULL, &context);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
  }

  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INOUT,
                                          TEEC_NONE, TEEC_NONE);

  tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                            &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
  }

  inout_mem.buffer = data;
  inout_mem.size = DATA_SIZE;
  inout_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

  tee_rv = TEEC_RegisterSharedMemory(&context, &inout_mem);
  if (tee_rv != TEE_SUCCESS) {
    printf("Failed to register DATA shared memory\n");
  }

  printf("Registered in mem..\n");

  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INOUT,
                                          TEEC_NONE, TEEC_NONE);
  operation.params[0].memref.parent = &inout_mem;
  operation.params[1].value.a = 0;

  printf("Invoking command: Update sha1: ");
  // tee_rv =
  //     TEEC_InvokeCommand(&session, INVOKE_COMMAND_STOREKEY, &operation,
  //     NULL);
  // if (tee_rv != TEE_SUCCESS) {
  //   printf("Failed to invoke command %x\n", tee_rv);
  // }
  printf("%d\n", operation.params[1].value.a);
  // uint32_t id = operation.params[1].value.a;
  memset(data, 'z', sizeof(data));
  tee_rv =
      TEEC_InvokeCommand(&session, INVOKE_COMMAND_GETKEY, &operation, NULL);

  // tee_rv =
  //     TEEC_InvokeCommand(&session, INVOKE_COMMAND_STOREKEY, &operation,
  //     NULL);
  //
  // if (tee_rv != TEEC_SUCCESS) {
  //   printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
  // }
  //
  // memset(data, '0', DATA_SIZE);
  // tee_rv =
  //     TEEC_InvokeCommand(&session, INVOKE_COMMAND_GETKEY, &operation, NULL);
  //
  // memset((void *)(&data), 1, sizeof(data));
  char *buf = inout_mem.buffer;
  for (int i = 0; i < DATA_SIZE; i++) {

    printf(" %c\n", *buf);
    buf++;
  }
}
