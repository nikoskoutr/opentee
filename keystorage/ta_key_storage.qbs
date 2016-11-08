import qbs

DynamicLibrary {
    name: "ta_key_storage"

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
    "ta_key_storage.c",
    "../include/tee_ta_properties.h"
    ]
}
