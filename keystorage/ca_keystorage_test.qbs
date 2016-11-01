import qbs

CppApplication {
    type: "application"
    name: "keystorage_app"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['ca_keystoragetest_new.c']
}
