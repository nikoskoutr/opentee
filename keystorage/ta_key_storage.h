#ifdef TA_PLUGIN
#include "tee_ta_properties.h"
SET_TA_PROPERTIES({0x25081234,
                   0x4132,
                   0x5532,
                   {'k', 'e', 'y', 's', 't', 'o', 'r', 'e'}}, /* UUID */
                  512,                                        /* dataSize */
                  255,                                        /* stackSize */
                  1, /* singletonInstance */
                  1, /* multiSession */
                  1) /* instanceKeepAlive */
#endif

#define INVOKE_COMMAND_STOREKEY 0
#define INVOKE_COMMAND_GETKEY 1
#define INVOKE_COMMAND_REMOVEKEY 2
#define INVOKE_COMMAND_UPDATEKEY 3
#define DUMMY_TEST 4
