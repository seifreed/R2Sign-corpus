# Goodware fixtures

These fixtures are compiled from `goodware_fixture.c`, which is original
repository metadata covered by the MIT license in the repository root. They
are included to exercise the goodware extractor across formats and
architectures without redistributing an unlicensed third-party database.

Build commands used for the published bundle:

```bash
clang -target x86_64-linux-gnu -O2 -c goodware_fixture.c -o ../goodware/fixtures/elf-x86-64.o
clang -target aarch64-linux-gnu -O2 -c goodware_fixture.c -o ../goodware/fixtures/elf-arm64.o
clang -target arm64-apple-macos11 -O2 -c goodware_fixture.c -o ../goodware/fixtures/mach-arm64.o
x86_64-w64-mingw32-gcc -O2 -s goodware_fixture.c -o ../goodware/fixtures/pe-x86-64.exe
i686-w64-mingw32-gcc -O2 -s goodware_fixture.c -o ../goodware/fixtures/pe-x86.exe
```
