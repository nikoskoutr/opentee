#include "tee_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef HEADER_DH_H
#include <openssl/dh.h>
#endif

// Available commands
#define ENCRYPTION 0
#define DECRYPTION 1
#define SIGNATURE 2
#define VERIFICATION 3
#define HASH 4
#define KEYGENERATION 5
#define DHOP 6
#define DHDERIVE 7
#define DHGETPUBLIC 8

#define TEE_TYPE_RSA_KEYPAIR 0xA1000030
#define TEE_ALG_RSA_NOPAD 0x60000030
#define TEE_ALG_AES_ECB_NOPAD 0x10000010
#define TEE_ALG_AES_CBC_NOPAD 0x10000110
#define TEE_TYPE_AES 0xA0000010
#define TEE_ALG_SHA256 0x50000004
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 0x70414930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 0x70212930

typedef enum { RSAALG = 0, AES = 1 } Algorithm_type;

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

  printf("-- Please select operation:\n-- 1 - Encrypt/Decrypt AES\n-- 2 - "
         "Encrypt/Decrypt RSA\n-- 3 - HASH\n-- 4 - Sign/Verify\n-- 5 - Key "
         "Exchange\n");
  int selection;
  scanf("%d", &selection);
  {
    char c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
  }
  if (selection == 1) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    operation.params[0].value.a = 256;
    operation.params[0].value.b = TEE_TYPE_AES;
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

    char *p = malloc(256);
    char *result = malloc(256);

    memset((void *)&in_mem, 'z', sizeof(in_mem));
    memset((void *)&out_mem, 'z', sizeof(out_mem));
    memset(p, 'z', 256);
    memset(result, 'z', 256);

    printf("-- Registering shared memories.\n");

    in_mem.buffer = p;
    in_mem.size = 256;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = result;
    out_mem.size = 256;
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
    printf("-- Key generation successful, the key id is: %d\n", key_id);

    printf("++ Enter key to encrypt:\n");

    fgets(p, 256, stdin);

    printf("-- Encrypting with generated AES key.\n");
    operation.params[0].value.a = key_id; // id
    operation.params[0].value.b = AES;
    operation.params[1].value.a = TEE_ALG_AES_CBC_NOPAD;
    ret = TEEC_InvokeCommand(&session, ENCRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful encryption\n");
    printf("-- Decrypting with generated AES key.\n");

    char *temp = malloc(256);
    memcpy(temp, result, 256);
    memcpy(result, p, 256);
    memcpy(p, temp, 256);
    free(temp);

    printf("-- The encrypted string is: ");

    for (uint32_t i = 0; i < 256; i++) {
      printf("%x", p[i]);
    }
    printf("\n");

    printf("-- The IV is: ");
    for (uint32_t i = 0; i < 56; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

    ret = TEEC_InvokeCommand(&session, DECRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error decrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- The decrypted string is: ");
    printf("%s\n", result);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 2) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
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
    printf("-- Key generation successful, the key id is: %d\n", key_id);

    printf("++ Enter key to encrypt:\n");

    fgets(p, 20, stdin);

    printf("-- Encrypting with generated RSA key.\n");
    operation.params[0].value.a = key_id;
    operation.params[0].value.b = RSAALG;
    operation.params[1].value.a = TEE_ALG_RSA_NOPAD;
    ret = TEEC_InvokeCommand(&session, ENCRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful encryption\n");
    printf("-- The encrypted string is: ");
    for (uint32_t i = 0; i < 32; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

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

    printf("-- The decrypted string is: %s", (char *)p);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 3) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    operation.params[0].value.a = TEE_ALG_SHA256;
    operation.params[0].value.b = 0;
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

    char *p = malloc(20);
    char *result = malloc(256);

    memset((void *)&in_mem, 'z', sizeof(in_mem));
    memset((void *)&out_mem, 'z', sizeof(out_mem));
    memset(p, 'z', 20);
    memset(result, 'z', 256);

    printf("-- Registering shared memories.\n");

    in_mem.buffer = p;
    in_mem.size = 20;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = result;
    out_mem.size = 256;
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

    printf("++ Enter text to digest:\n");

    fgets(p, 20, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Success. The result is: ");
    for (uint32_t i = 0; i < sizeof(result); i++) {
      printf("%x", result[i]);
    }
    printf("\n");
    TEEC_ReleaseSharedMemory(&out_mem);
    TEEC_ReleaseSharedMemory(&in_mem);

    free(p);
    free(result);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 4) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *p = malloc(32);
    char *result = malloc(128);

    memset((void *)&in_mem, 'z', sizeof(in_mem));
    memset((void *)&out_mem, 'z', sizeof(out_mem));
    memset(p, 'z', 32);
    memset(result, 'z', 128);

    printf("-- Registering shared memories.\n");

    in_mem.buffer = p;
    in_mem.size = 32;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = result;
    out_mem.size = 128;
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

    operation.params[0].value.a = 1024;
    operation.params[0].value.b = TEE_TYPE_RSA_KEYPAIR;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

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

    printf("++ Enter text to digest:\n");

    fgets(p, 32, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    operation.params[0].value.a = TEE_ALG_SHA256;

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    memcpy(p, result, 32);
    printf("-- Success. The result is: ");
    for (uint32_t i = 0; i < 256 / 8; i++) {
      printf("%x", p[i]);
    }
    printf("\n");

    printf("-- Signing with generated RSA key.\n");
    operation.params[0].value.a = key_id;
    operation.params[0].value.b = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
    ret = TEEC_InvokeCommand(&session, SIGNATURE, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful signing\n");
    char *signature = malloc(32);
    memcpy(signature, result, 32);

    printf("-- The signature string is: ");
    for (uint32_t i = 0; i < 1024 / 8; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

    printf("-- Verification with generated RSA key.\n");

    printf("++ Enter text to digest:\n");
    memset(p, 'z', 32);
    fgets(p, 32, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    operation.params[0].value.a = TEE_ALG_SHA256;

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    memcpy(p, result, 32);
    printf("-- Success. The result is: ");
    for (uint32_t i = 0; i < 256 / 8; i++) {
      printf("%x", p[i]);
    }
    printf("\n");

    memcpy(result, signature, 32);

    operation.params[0].value.a = key_id;
    operation.params[0].value.b = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;

    ret = TEEC_InvokeCommand(&session, VERIFICATION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf(
          "!! Error veryfying 0x%x\n!! The hash did not match the signature\n",
          ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Message verified\n");

    TEEC_ReleaseSharedMemory(&out_mem);
    TEEC_ReleaseSharedMemory(&in_mem);

    free(p);
    free(result);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 5) {
    static unsigned char dh512_p[] = {
        0xCD, 0xED, 0xF9, 0x6D, 0x4C, 0x65, 0x05, 0xFA, 0x8C, 0x7B, 0xBC,
        0xF8, 0x5D, 0x6E, 0xA8, 0xAB, 0x95, 0x4C, 0x21, 0x55, 0x00, 0xA8,
        0xC6, 0xF8, 0x90, 0x1D, 0xB6, 0x9B, 0x97, 0xC8, 0xFE, 0x57, 0xAD,
        0x56, 0xAA, 0xE2, 0xBE, 0xE8, 0x03, 0xF5, 0xB6, 0x1B, 0x2B, 0x82,
        0xFE, 0x00, 0xBB, 0x76, 0x1F, 0x15, 0x1A, 0x64, 0x89, 0x89, 0x78,
        0x07, 0x4E, 0x0E, 0xF3, 0xEA, 0xC4, 0x0D, 0x25, 0x83,
    };
    static unsigned char dh512_g[] = {
        0x02,
    };

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    memset((void *)&in_mem, 'z', sizeof(in_mem));
    memset((void *)&out_mem, 'z', sizeof(out_mem));
    uint32_t mem_size = 64;
    char *buffer1 = malloc(mem_size);
    char *buffer2 = malloc(mem_size);
    memcpy(buffer1, dh512_p, sizeof(dh512_p));
    memcpy(buffer2, dh512_g, sizeof(dh512_g));

    printf("-- Registering shared memories.\n");

    in_mem.buffer = buffer1;
    in_mem.size = sizeof(dh512_p);
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = buffer2;
    out_mem.size = sizeof(dh512_g);
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

    operation.params[0].value.a = 0;
    operation.params[0].value.b = 0;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

    printf("-- Generating DH keys\n");
    ret = TEEC_InvokeCommand(&session, DHOP, &operation, NULL);
    uint32_t id1 = operation.params[0].value.a;
    printf("-- Key 1 id: %d\n", id1);

    ret = TEEC_InvokeCommand(&session, DHOP, &operation, NULL);
    uint32_t id2 = operation.params[0].value.a;
    printf("-- Key 2 id: %d\n", id2);

    in_mem.size = mem_size;
    out_mem.size = mem_size;
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
    memset(buffer1, 'z', mem_size);
    printf("-\n");
    printf("-- Getting public DH keys\n");
    operation.params[0].value.a = id1;
    ret = TEEC_InvokeCommand(&session, DHGETPUBLIC, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error getting public key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    uint32_t public1_size = operation.params[1].value.b;
    char *public1 = malloc(public1_size);
    memcpy(public1, buffer1, public1_size);

    operation.params[0].value.a = id2;
    ret = TEEC_InvokeCommand(&session, DHGETPUBLIC, &operation, NULL);
    uint32_t public2_size = operation.params[1].value.b;
    char *public2 = malloc(public2_size);
    memcpy(public2, buffer1, public2_size);

    printf("Public1:\n");
    for (uint32_t i = 0; i < public1_size; i++) {
      printf("%x", public1[i]);
    }
    printf("\nPublic2:\n");
    for (uint32_t i = 0; i < public2_size; i++) {
      printf("%x", public2[i]);
    }
    printf("\n");

    printf("-- Deriving private DH keys\n");
    in_mem.size = public1_size;
    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[0].value.a = id1;
    memcpy(buffer1, public2, public1_size);
    ret = TEEC_InvokeCommand(&session, DHDERIVE, &operation, NULL);
    uint32_t secret1_size = operation.params[1].value.b;
    char *secret1 = malloc(secret1_size);
    memcpy(secret1, buffer1, secret1_size);

    in_mem.size = public2_size;
    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[0].value.a = id2;
    memcpy(buffer1, public1, mem_size);

    ret = TEEC_InvokeCommand(&session, DHDERIVE, &operation, NULL);
    uint32_t secret2_size = operation.params[1].value.b;
    char *secret2 = malloc(secret2_size);
    memcpy(secret2, buffer1, secret2_size);

    printf("Secret1:\n");
    for (uint32_t i = 0; i < secret1_size; i++) {
      printf("%x", secret1[i]);
    }
    printf("\nSecret2:\n");
    for (uint32_t i = 0; i < secret2_size; i++) {
      printf("%x", secret2[i]);
    }
    printf("\n");
    return 0;
  }
}
