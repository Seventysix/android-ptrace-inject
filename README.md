# Android ptrace inject

## Introduction
Inject module into process use ptrace() on Android arm32 and arm64. Tested on onepuls 7 (rooted), Android 10.

## How to build
Just use : `ndk-build`

## How to use
- step 1 : Build the project, or use the built file.

- step 2 : Push "myinjector" into android phone, like : `adb push myinjector /data/local/tmp/myinjector`.
Then grant permission to "myinjector" like : `chmod +x /data/local/tmp/myinjector`

- step 3 : Use commad : `./myinjector pid lib-path-to-inject func-symbol params`. Example : `./myinjector 1234 /data/local/tmp/libtest.so _Z10hook_entryPc paramstr`

## Experiment result

Execute:

![execute](https://raw.githubusercontent.com/Seventysix/android-ptrace-inject/dev/res/execute.png "execute")

Inject result:

![inject_func](https://raw.githubusercontent.com/Seventysix/android-ptrace-inject/dev/res/inject_func_execute.png "inject_func")

![inject_so](https://raw.githubusercontent.com/Seventysix/android-ptrace-inject/dev/res/inject_so.png "inject_so")

Symbol of libtest64.so:

![libtest64.so](https://raw.githubusercontent.com/Seventysix/android-ptrace-inject/dev/res/libtest_symbol.png "libtest64.so")



