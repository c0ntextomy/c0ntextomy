#include <payload.h>

void start(void *entry, agent_p agent)
{
    char msg[] = "Hello world!";
    uint64_t size = sizeof(msg);

    agent->trampoline.dprintf(1, "%s\n", msg);

    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
    agent->trampoline.send(agent->fd, msg, sizeof(msg), 0);
}