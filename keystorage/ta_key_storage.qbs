import qbs

 DynamicLibrary {
     name: "ta_key_storage"
     Group {
         name: "project-install"
         fileTagsFilter: "dynamiclibrary"
         qbs.install: false
         qbs.installDir: "TAs"
     }

     Depends { name: "cpp" }
     Depends { name: "InternalApi" }

     cpp.includePaths: ["../include"]
     cpp.driverFlags: ["-lssl", "-lcrypto"]
     destinationDirectory: './TAs'
     cpp.defines: ["TA_PLUGIN"]

     files: ["ta_key_storage.c", "../include/tee_ta_properties.h"]
 }
