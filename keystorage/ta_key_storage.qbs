import qbs

DynamicLibrary {
    name: "ta_keystorage"
    Group {
      name: "project-install"
      fileTagsFilter: "dynamiclibrary"
      qbs.install: false
      qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
    "ta_keystorage_final.c",
    "ta_key_storage.h",
    "../include/tee_ta_properties.h"
    ]
}
