import qbs

CppApplication {
    type: "application"
    name: "ca_keystorage_test"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    Depends { name: "cpp"}
    cpp.driverFlags: ["-lssl", "-lcrypto"]
    consoleApplication: true
    destinationDirectory: '.'

    files: ['ca_keystorage_test.c']
}
