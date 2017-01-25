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
