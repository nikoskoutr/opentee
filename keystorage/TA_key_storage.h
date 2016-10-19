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

#define STORE_KEY_COMMAND 0x00000000
#define GET_KEY_COMMAND 0x00000001
#define REMOVE_KEY_COMMAND 0x00000002
#define UPDATE_KEY_COMMAND 0x00000003
