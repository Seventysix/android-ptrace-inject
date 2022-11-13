#include <cstdio>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <elf.h>


#ifdef __aarch64__
    #define pt_regs user_pt_regs
    #define uregs regs
    #define ARM_sp sp
    #define ARM_pc pc
    #define ARM_lr regs[30]
	#define ARM_r0 regs[0]
    #define ARM_cpsr pstate
    #define Param_Regs_Num 8    // arm64 前8个寄存器放函数参数，剩余入栈
    //#define Libc_Path "/system/lib64/libc.so"
    //#define Linker_Path "/system/bin/linker64"
    #define Libc_Path "/apex/com.android.runtime/lib64/bionic/libc.so"
    #define Linker_Path "/apex/com.android.runtime/bin/linker64"
    #define Libdl_Path "/apex/com.android.runtime/lib64/bionic/libdl.so"
#else
    #define Param_Regs_Num 4    // arm32 前4个寄存器放函数参数，剩余入栈
    //#define Libc_Path "/system/lib/libc.so"
    //#define Linker_Path "/system/bin/linker"
    #define Libc_Path "/apex/com.android.runtime/lib/bionic/libc.so"
    #define Linker_Path "/apex/com.android.runtime/bin/linker"
    #define Libdl_Path "/apex/com.android.runtime/lib/bionic/libdl.so"
#endif

#define CPSR_T_MASK (1u << 5)

// 附加进程
bool try_attach_process(pid_t pid){
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0){
        printf("[Error] Attach process %d failed. Ptrace failed. \n", pid);
        return false;
    }
    if(waitpid(pid, nullptr, WUNTRACED) < 0){
        printf("[Error] Attach process %d failed. Waitpid failed. \n", pid);
        return false;
    };

    printf("[Info] Attach process %d success. \n", pid);
    return true;
}

// 脱离进程
bool try_detach_process(pid_t pid){
    return ptrace(PTRACE_DETACH, pid, NULL, NULL) >= 0;
}

// 读远程进程寄存器
bool try_read_process_regs(pid_t pid, struct pt_regs* regs){
#ifdef __aarch64__
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(*regs);
    if(ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) < 0){
        return false;
    }
#else
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0){
        return false;
    }
#endif
    return true;
}

// 写远程进程寄存器
bool try_write_process_regs(pid_t pid, struct pt_regs* regs){
#ifdef __aarch64__
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(*regs);
    if(ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io) < 0){
        return false;
    }
#else
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0){
        return false;
    }
#endif
    return true;
}

// 获取函数执行结果
long ptrace_retval(struct pt_regs* regs){
    return regs->ARM_r0;
}

// 继续执行进程
int ptrace_continue(pid_t pid){
    if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
        printf("[Error] Ptrace continue failed. \n");
        return -1;
    } else{
        return 0;
    }
}

// 向远程进程内存写入数据
int ptrace_write_data(pid_t pid, uint8_t * startAddr, uint8_t * data, size_t size){
    size_t byteWidth = sizeof(long);
    uint8_t * temp_addr = startAddr;
    uint8_t * temp_data = data;

    long u_data;

    for(int i=0; i< size/4; i++){
        memcpy(&u_data, temp_data, byteWidth);
        if(ptrace(PTRACE_POKETEXT, pid, temp_addr, u_data) < 0){
            printf("[Error] write data error, addr: 0x%lx, data: %s \n", (long)temp_addr, temp_data);
            return -1;
        }
        temp_data += byteWidth;
        temp_addr += byteWidth;
    }

    uint remain = size % 4;
    if(remain > 0){
        u_data = ptrace(PTRACE_PEEKTEXT, pid, temp_addr, NULL);
        memcpy(&u_data, temp_data, remain);
        if(ptrace(PTRACE_POKETEXT, pid, temp_addr, u_data) < 0){
            printf("[Error] write data error, addr: 0x%lx, data: %s \n", (long)temp_addr, temp_data);
            return -1;
        }
    }
    return 0;
}

int ptrace_write_data(pid_t pid, uint8_t * startAddr, const char * data, size_t size){
    size_t byteWidth = sizeof(long);
    uint8_t * temp_addr = startAddr;
    const char * temp_data = data;

    long u_data;

    for(int i=0; i< size/4; i++){
        memcpy(&u_data, temp_data, byteWidth);
        if(ptrace(PTRACE_POKETEXT, pid, temp_addr, u_data) < 0){
            return -1;
        }
        temp_data += byteWidth;
        temp_addr += byteWidth;
    }

    uint remain = size % 4;
    if(remain > 0){
        u_data = ptrace(PTRACE_PEEKTEXT, pid, temp_addr, NULL);
        memcpy(&u_data, temp_data, remain);
        if(ptrace(PTRACE_POKETEXT, pid, temp_addr, u_data) < 0){
            return -1;
        }
    }
    return 0;
}

// 向远程进程内存读取数据
int ptrace_read_data(pid_t pid, uint8_t * startAddr, uint8_t * buf, size_t size){
    size_t byteWidth = sizeof(long);
    uint8_t * temp_addr = startAddr;
    uint8_t * temp_data = buf;

    long u_data;

    for(int i=0; i< size/4; i++){
        u_data = ptrace(PTRACE_PEEKTEXT, pid, temp_addr, NULL);
        memcpy(temp_data, &u_data, byteWidth);
        temp_data += byteWidth;
        temp_addr += byteWidth;
    }

    uint remain = size % 4;
    if(remain > 0){
        u_data = ptrace(PTRACE_PEEKTEXT, pid, temp_addr, NULL);
        memcpy(temp_data, &u_data, remain);
    }

    return 0;
}

// 得到模块基址
void * get_module_base_address(pid_t pid, const char * moduleName){
    FILE *mapFile = nullptr;
    char dir[50];
    char mapFileLine[1024];
    long address = 0;

    if(pid < 0){
        sprintf(dir, "/proc/self/maps");
    } else{
        sprintf(dir, "/proc/%d/maps", pid);
    }

    mapFile = fopen(dir, "r");
    if(mapFile != nullptr){
        while (fgets(mapFileLine, sizeof(mapFileLine), mapFile)){
            if(strstr(mapFileLine, moduleName)){
//                printf("[Info] Find module: %s \n", mapFileLine);
                char * addrStr = strtok(mapFileLine, "-");
                address = strtoul(addrStr, nullptr, 16);
                break;
            }
        }
        fclose(mapFile);
    }
    return (void *)address;
}

// 得到本地进程和远程进程同一模块的同一函数的远程地址
void * get_remote_func_address(pid_t pid, const char * moduleName, void * localFuncAddr){
    void * remoteModuleAddr, * localModuleAddr, * remoteFuncAddr;
    localModuleAddr = get_module_base_address(-1, moduleName);
    remoteModuleAddr = get_module_base_address(pid, moduleName);

    remoteFuncAddr = (void *)((long)remoteModuleAddr + ((long)localFuncAddr - (long)localModuleAddr));

    return remoteFuncAddr;
}

int ptrace_call(pid_t pid, uintptr_t funcAddr, long * params, int paramsCount, struct pt_regs* regs){
    int i;

    for (i=0; i < paramsCount && i < Param_Regs_Num; i++){
        regs->uregs[i] = params[i];
    }
    //->>的参数入栈
    if(i < paramsCount){
        regs->ARM_sp -= (paramsCount - i)*sizeof(long);
        if(ptrace_write_data(pid, (uint8_t *)regs->ARM_sp, (uint8_t *)&params[i], (paramsCount-i)*sizeof(long)) < 0){
            printf("[Error] Ptrace call, push params to stack failed. \n");
            return -1;
        }
    }

    //pc寄存器写入目标函数地址
    regs->ARM_pc = (long)funcAddr;
    //判断指令集
    // 与BX跳转指令类似，判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
    // 若为0，则将CPSR寄存器的标志T复位，解释为ARM代码
    if(regs->ARM_pc & 1){
        // thumb
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
//        printf("[Info] Use thumb instruction. \n");
    }
    else{
        // arm
        regs->ARM_cpsr &= ~CPSR_T_MASK;
//        printf("[Info] Use ARM instruction. \n");
    }

//    regs->ARM_lr = 0;
    regs->ARM_lr = (long)get_module_base_address(pid, Libc_Path);   // 安卓7以上

    if(!try_write_process_regs(pid, regs)){
        printf("[Error] Ptrace set regs error. \n");
        return -1;
    }

    if(ptrace_continue(pid) < 0){
        printf("[Error] Continue error. \n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);

    while (stat != 0xb7f){
        if(ptrace_continue(pid) < 0){
            printf("[Error] Ptrace call failed. \n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    if(!try_read_process_regs(pid, regs)){
        printf("[Error] Get ptrace call result failed. \n");
    }

    return 0;
}


// 向进程pid中注入模块module，自动执行module入口函数
int inject_remote_process(pid_t pid, const char * module, const char * funcName, const char * funcParam){
    if(!try_attach_process(pid)){
        return -1;
    }

    // 保存寄存器环境
    pt_regs original_regs{};
    pt_regs current_regs{};
    if(!try_read_process_regs(pid, &current_regs)){
        printf("[Error] Save remote process registers failed. \n");
        return -1;
    }
    printf("[Info] Read remote process registers success. \n");
    memcpy(&original_regs, &current_regs, sizeof(current_regs));

    // 关键函数地址
    void * mmapAddr, * dlopenAddr, * dlsymAddr, * dlcloseAddr, * dlerrorAddr, * mallocAddr;
    long params[6];
    uint8_t * map_base;

    // 获取函数地址
    mmapAddr = get_remote_func_address(pid, Libc_Path, (void *)mmap);
    dlopenAddr = get_remote_func_address(pid, Libdl_Path, (void *)dlopen);
    dlsymAddr = get_remote_func_address(pid, Libdl_Path, (void *)dlsym);
    dlcloseAddr = get_remote_func_address(pid, Libdl_Path, (void *)dlclose);
    dlerrorAddr = get_remote_func_address(pid, Libdl_Path, (void *)dlerror);
    mallocAddr = get_remote_func_address(pid, Libc_Path, (void *)malloc);

    // mmap
    params[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址
    params[1] = 0x400; // 映射内存的大小
    params[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行
    params[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
    params[4] = 0; //  若需要映射文件到内存中，则为文件的fd
    params[5] = 0; //文件映射偏移量
    if(ptrace_call(pid, (uintptr_t)mmapAddr, params, 6, &current_regs) < 0){
        printf("[Error] Mmap call failed. \n");
        return -1;
    }
    map_base = (uint8_t *)ptrace_retval(&current_regs);
    printf("[Info] Remote Process map base 0x%lx. \n", (long)map_base);

//    // malloc (由于mmap开辟的空间写入出错)
//    params[0] = 0x400;
//    if(ptrace_call(pid, (uintptr_t)mallocAddr, params, 1, &current_regs) < 0){
//        printf("[Error] Malloc call failed. \n");
//        return -1;
//    }
//    map_base = (uint8_t *)ptrace_retval(&current_regs);
//    printf("[Info] Remote Process map base 0x%lx. \n", (long)map_base);

    // 将要注入的so写入远程进程内存空间
    if(ptrace_write_data(pid, map_base, (uint8_t *)module, strlen(module)+1) < 0){
        printf("[Error] Write %s failed. \n", module);
        return -1;
    }
    printf("[Info] Write %s success. \n", module);

    // dlopen
    params[0] = (long)map_base;
    params[1] = RTLD_NOW | RTLD_GLOBAL;
    if(ptrace_call(pid, (uintptr_t)dlopenAddr, params, 2, &current_regs) < 0){
        printf("[Error] Dlopen call failed. \n");
        return -1;
    }
    uint8_t * sohandle = (uint8_t *)ptrace_retval(&current_regs);
    if(!sohandle){
        if(ptrace_call(pid, (uintptr_t)dlerrorAddr, params, 0, &current_regs) >= 0){
            char *errorRet = (char *)ptrace_retval(&current_regs);
            char errorBuf[1024] = {0};
            ptrace_read_data(pid, (uint8_t *)errorRet, (uint8_t *)errorBuf, 1024);
            printf("[Error] dlopen error:%s\n", errorBuf);

        } else{
            printf("[Error] Dlerror call failed! \n");
        }
    }

    printf("[Info] Dlopen: module %s address 0x%lx. \n", module, (long)sohandle);

    // dlsym
    ptrace_write_data(pid, map_base + 0x100, funcName, strlen(funcName)+1);
    params[0] = (long)sohandle;
    params[1] = (long)map_base + 0x100;
    if(ptrace_call(pid, (uintptr_t)dlsymAddr, params, 2, &current_regs) < 0){
        printf("[Error] Dlsym call failed. \n");
        return -1;
    }
    uint8_t * hookFuncAddr = (uint8_t *)ptrace_retval(&current_regs);
    printf("[Info] Dlsym: function %s address 0x%lx. \n", funcName, (long)hookFuncAddr);

    // 调用注入函数
    ptrace_write_data(pid, map_base + 0x200, funcParam, strlen(funcParam)+1);
    params[0] = (long)map_base + 0x200;
    if(ptrace_call(pid, (uintptr_t)hookFuncAddr, params, 1, &current_regs) < 0){
        printf("[Error] Inject function call failed. \n");
        return -1;
    }
    printf("[Info] %s: execute. \n", funcName);

    // dlclose
    params[0] = (long)sohandle;
    if(ptrace_call(pid, (uintptr_t)dlcloseAddr, params, 1, &current_regs) < 0){
        printf("[Error] Dlclose call failed. \n");
        return -1;
    }
    printf("[Info] Dlclose: close. \n");

    // 恢复寄存器环境
    try_write_process_regs(pid, &original_regs);

    // 脱离进程
    if(!try_detach_process(pid)){
        printf("[Error] Detach process %d failed. \n", pid);
        return -1;
    }
    printf("[Info] Detach process %d success. \n", pid);
    return 0;

}

int main(int argc, char *argv[]){
    if(argc < 4){
        printf("[Info] Usage: %s pid module funcName param \n", argv[0]);
        printf("[Info] param is a string. \n");
        return -1;
    }

    int pid = atoi(argv[1]);
    char * module = argv[2];
    char * funcName = argv[3];
    char * param = argv[4];

    return inject_remote_process(pid, module, funcName, param);

}
