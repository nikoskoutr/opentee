import qbs

DynamicLibrary {
    name: "ta_key_storage_final"
    Group {
        fileTagsFilter: "dynamiclibrary"
        qbs.install: true
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["ta_key_storage_final.c", "../include/tee_ta_properties.h"]
}
