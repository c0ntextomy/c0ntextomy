#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <sys/socket.h>
#import <objc/runtime.h>

#undef memcpy
#undef memset
#undef mach_task_self
#undef mach_vm_round_page
#undef CFSTR

typedef struct {
    void (*enable_log_null_redirection)(void *agent);
    void (*disable_log_null_redirection)(void *agent);

    void *(*dlopen)(const char* path, int mode);
    void *(*dlsym)(void* handle, const char* symbol);

    int (*dprintf)(int, char *, ...);
    int *errno;
    char *(*strerror)(int errnum);

    void (*free)(void *);
    void *(*malloc)(size_t size);
    void *(*memcpy)(void *restrict dst, const void *restrict src, size_t n);
    void *(*memset)(void *b, int c, size_t len);

    mach_port_t (*mach_task_self)(void);
    vm_size_t *vm_page_mask;
    kern_return_t (*vm_allocate)(vm_map_t, vm_address_t *, vm_size_t, int);
    kern_return_t (*vm_deallocate)(vm_map_t, vm_address_t, vm_size_t);
    kern_return_t (*vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);

    id (*objc_msgSend)(id self, SEL op, ...);
    id (*objc_msgSendSuper2)(id self, SEL op, ...);
    id (*objc_getClass)(const char *name);
    SEL (*sel_registerName)(const char *str);
    id (*NSTemporaryDirectory)(void);

    Class (*objc_allocateClassPair)(Class, const char*, size_t);
    void (*objc_registerClassPair)(Class);
    BOOL (*class_addMethod)(Class, SEL, IMP, const char*);
    BOOL (*class_addIvar)(Class, const char*, size_t, uint8_t, const char*);
    Ivar (*class_getInstanceVariable)(Class, const char*);
    id (*object_getIvar)(id, Ivar);
    void (*object_setIvar)(id, Ivar, id);

    size_t (*strlen)(const char *s);
    char *(*strdup)(const char *s1);

    int (*stat)(const char *restrict path, struct stat *restrict buf);
    int (*open)(const char *path, int oflag, ...);
    int (*close)(int fildes);
    int (*remove)(const char *path);

    int (*dup)(int fildes);
    int (*dup2)(int fildes, int fildes2);

    ssize_t (*read)(int fildes, void *buf, size_t nbyte);

    ssize_t (*recv)(int socket, void *buffer, size_t length, int flags);
    ssize_t (*send)(int socket, const void *buffer, size_t length, int flags);

    unsigned int (*sleep)(unsigned int);

    id (*dispatch_get_global_queue)(long, unsigned long);
} trampoline_t, *trampoline_p;

typedef struct {
    trampoline_t trampoline;
    char *session_id;
    int fd;
    int stderr_fd;
    int stdout_fd;
} agent_t, *agent_p;


// arm64e support
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
    #define PTRAUTH_SIGN_UNAUTHENTICATED(v, k, d) __builtin_ptrauth_sign_unauthenticated((void *)v, k, d)
    #define GET_ABSOLUTE_ADDR(e, p) (uint64_t)e + (uint64_t)p
#else
    #define PTRAUTH_SIGN_UNAUTHENTICATED(v, k, d) v
    #define GET_ABSOLUTE_ADDR(e, p) p
#endif

#define PTRAUTH_KEY_ASIA 0
#define PTRAUTH_SIGN_UNAUTHENTICATED_FUNC(p) PTRAUTH_SIGN_UNAUTHENTICATED(p, PTRAUTH_KEY_ASIA, 0)
#define PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(e, p) PTRAUTH_SIGN_UNAUTHENTICATED_FUNC(GET_ABSOLUTE_ADDR(e, p))


// not a great solution but enough to inspect program state
#define breakpoint() asm volatile("BRK 0")

// respect memory alignment
#define mach_vm_round_page(x) ((mach_vm_offset_t)(x) + *(agent->trampoline.vm_page_mask)) & ~((signed)*(agent->trampoline.vm_page_mask))

/****** logging macros ******/
#define log_info(fmt, ...)  agent->trampoline.dprintf(agent->stderr_fd, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) agent->trampoline.dprintf(agent->stderr_fd, "[!] " fmt "\n", ##__VA_ARGS__)

/******* objc macros *******/
#define objcAllocateClassPair(super, name, extra) (agent->trampoline.objc_allocateClassPair(super, name, extra))
#define objcRegisterClassPair(class) (agent->trampoline.objc_registerClassPair(class))
#define getClass(obj) (void*)((*(uint64_t*)obj) & 0xFFFFFFFF8LL)
#define classAddMethod(class, sel, imp, types) (agent->trampoline.class_addMethod(class, sel, imp, types))
#define classAddIvar(class, name, size, alignment, types) (agent->trampoline.class_addIvar(class, name, size, alignment, types))
#define classGetInstanceVariable(class, name) (agent->trampoline.class_getInstanceVariable(class, name))
#define objectGetIvar(obj, ivar) (agent->trampoline.object_getIvar(obj, ivar))
#define objectSetIvar(obj, ivar, value) (agent->trampoline.object_setIvar(obj, ivar, value))
#define objcGetClass(name)      (agent->trampoline.objc_getClass(#name))
#define objcGetSelector(name)   (agent->trampoline.sel_registerName(#name))
#define objcMsgSendCast(...)    ((void *(*)(void *, SEL, ##__VA_ARGS__))(agent->trampoline.objc_msgSend))
#define objcMsgSendSuper2Cast(...) ((void *(*)(void *, SEL, ##__VA_ARGS__))(agent->trampoline.objc_msgSendSuper2))

struct objc_super {
	id receiver;
	Class class;
};

#define SUPER(x) &(struct objc_super){ .receiver = x, .class = getClass(x) }

#define objcAllocClass(class)       objcMsgSendCast()(objcGetClass(class), objcGetSelector(alloc))
#define objcAllocInitClass(class)   objcMsgSendCast()(objcAllocClass(class), objcGetSelector(init))

#define objcRetain(obj)     objcMsgSendCast()(obj, objcGetSelector(retain))
#define objcRelease(obj)    objcMsgSendCast()(obj, objcGetSelector(release))

#define CSTRING(cfstr) objcMsgSendCast()(cfstr, objcGetSelector(cString))
#define CFSTR(cstring)                              \
    objcMsgSendCast(char *)(                        \
        objcGetClass(NSString),                     \
        objcGetSelector(stringWithCString:),        \
        cstring                                     \
    )

#define objcArray(...)                              \
    objcMsgSendCast(...)(                           \
        objcGetClass(NSArray),                      \
        objcGetSelector(arrayWithObjects:),         \
        ##__VA_ARGS__                               \
    )

#define getAppPath()                                \
    objcMsgSendCast()(                              \
        objcMsgSendCast()(                          \
            objcGetClass(NSBundle),                 \
            objcGetSelector(mainBundle)             \
        ),                                          \
        objcGetSelector(bundlePath)                 \
    )

#define getTempPath()                               \
    objcMsgSendCast(void *, ...)(                   \
        objcGetClass(NSString),                     \
        objcGetSelector(stringWithFormat:),         \
        CFSTR("%@%@"),                              \
        agent->trampoline.NSTemporaryDirectory(),   \
        objcMsgSendCast()(                          \
            objcMsgSendCast()(                      \
                objcGetClass(NSUUID),               \
                objcGetSelector(UUID)               \
            ),                                      \
            objcGetSelector(UUIDString)             \
        )                                           \
    )

#define objcLoadBundle(bundle_path)                 \
    objcMsgSendCast()(                              \
        objcMsgSendCast(id)(                        \
            objcGetClass(NSBundle),                 \
            objcGetSelector(bundleWithPath:),       \
            CFSTR(bundle_path)                      \
        ),                                          \
        objcGetSelector(load)                       \
    )
