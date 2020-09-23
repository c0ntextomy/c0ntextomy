# Security Advisory
**A design flaw in MobileDevice.framework/Xcode and iOS/iPadOS/tvOS Development Tools allows an attacker in the same network to gain remote code execution on a target device.**

## Authors
- Dany Lisiansky ([@danyl931](https://twitter.com/DanyL931)), Independent Security Researcher
- Nikias Bassen ([@pimskeks](https://twitter.com/pimskeks)), Security Researcher and VP of Product Security, ZIMPERIUM zLabs

## Mandatory Hash Tweet
[@danyL931 on twitter](https://twitter.com/DanyL931/status/1177309848997957635)

```
$ echo "Let's debug together [26/09/2019]: Successfully hijacked a remote lldb session with a second, fully working client" | shasum
10c51451543a93b90b2dc75657f9461b55e0ba2d  -
```

## Additional Credits
- **Eliyahu Stern** reported an issue regarding debugserver support on iOS 13 with libimobiledevice and stated that after the SSL handshake the connection continues in plain text:
[https://github.com/libimobiledevice/libimobiledevice/issues/793#issuecomment-500749243](https://git.io/JvK1R).

  Note that the issue he reported was about the USB communication failing.

## Affected Components
- macOS/Xcode MobileDevice.framework, IDEiOSSupportCore, DTDeviceKit(Base).framework, lldb-rpc-server
- iOS/iPadOS/tvOS debugserver et al. / Development Tools (Developer Disk Image)

## Affected Versions
- macOS 10.12.4 through 10.15.3 / Xcode 9.0 through 11.7
- iOS/iPadOS/tvOS 11.0 through iOS 13.7 running on latest hardware

## Vendor
- Apple, Inc.

## CVEs
- [CVE-2020-9992](https://support.apple.com/en-us/HT211850)

## Disclosure Timeline
- Vulnerability discovered: June 14, 2019
- Vendor notified: March 12, 2020
- Vendor asked to extend the disclosure period until “later this summer”: April 14, 2020
- Vendor notified us the patches are present in the new beta versions and are planned to be published in a future security update: August 6, 2020
- A downgrade attack bypassing the new patch was found, affecting iOS 13.6 and 13.7: August 14, 2020
- Vendor explained only the upcoming iOS/iPadOS/tvOS 14 and watchOS 7 are fully addressed: September 5, 2020
- Vulnerability patched: September 16, 2020

## Summary
A design flaw in macOS'/Xcode's MobileDevice.framework and the Development Tools for iOS/iPadOS/tvOS results in clear text communication over the network, despite the service connection setup performing an actual SSL handshake.

## Impact
An attacker in a privileged network position may be able to gain arbitrary **remote code execution** that ultimately results in **exfiltration of sensitive user data** from the victim's device.

## Description
MobileDevice.framework on macOS encapsulates the (private) API required to start services on iOS/iPad/tvOS devices via lockdownd, the main service daemon running on those devices. It supports both USB and WiFi connections (transparently, since this is actually handled through usbmuxd), and contains the protocol implementations for most of the services being used in host-device communications, like Apple File Conduit (AFC), Backup System (MobileBackup2), etc.

When a service is (successfully) started, the device's lockdownd reports back to the host a port number the service has been made available on, and the property-list encapsulated dictionary also contains a key called `EnableServiceSSL` with a value of either `True` or `False`. Up to iOS 12.4.x, all services started via USB had it set to `False`, but all services started via WiFi, or on a device with iOS/iPadOS/tvOS 13.x or higher via USB, will have this set to `True`.
If `True` it tells the host, or more precisely the handling code in MobileDevice.framework, that the communication is supposed to be encrypted, so it performs an SSL Handshake, and the communication will normally be continued in ciphered form.

However, this is different for the services of the developer tools, like debugserver. The device-side implementation is provisioned by Xcode through a Developer Disk Image (DDI) once Xcode sees a device to make them available.

On the device side, lockdownd is handling the SSL handshake for all services that are started. Services are performing a "check-in" with lockdownd, allowing them to take over the connection. According to the service startup code, if the connection is via WiFi, then EnableServiceSSL is always True; and a service does `secure_lockdown_checkin`, usually followed by `lockdown_get_socket` but also `lockdown_get_securecontext` so it can communicate securely. However in the debugserver case it never calls `lockdown_get_securecontext` so it does not even expect encrypted service communication in its current implementation.

The host-side implementations of the developer tool's services are implemented outside of MobileDevice.framework. The debugserver service startup is done inside Xcode's IDE plugin `IDEiOSSupportCore` in a method called `-[DVTiOSDevice startDebugServerServiceForLaunchSession:]` which will then call `-[DTDKMobileDeviceToken startDebugServerServiceWithExtension:]` (DTDeviceKitBase.framework) which - via a certain code path through other methods - calls out to AMDeviceSecureStartService in MobileDevice.framework, to request the service startup, and this will also perform the SSL Handshake.
Back in `IDEiOSSupportCore` a "success" block will be called which then requests the socket file descriptor of the connection that has been established, using `AMDServiceConnectionGetSocket`.
Finally Xcode will just pass this file descriptor as an argument to lldb-rpc-server:

> /Applications/Xcode-beta.app/Contents/SharedFrameworks/LLDBRPC.framework/Resources/lldb-rpc-server --unix-fd 68 --fd-passing-socket 70

The code doesn't check at all if SSL shall be used, but also the device-side implementation in debugserver does not even expect secure communication. As a result `lldb-rpc-server` communicates in plain text.

The same issue can be seen for the instruments service `com.apple.instruments.remoteserver` which is implemented in `Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` on the developer disk image. In the same way as with debugserver, Xcode starts the service, the SSL handshake is performed, but then it continues communicating in plain text. On the device side it will, again, simply get the socket from lockdownd after check-in without considering the need for SSL against what the service startup suggested.
More services might be affected but they haven't been analyzed yet by the time of writing this advisory.

Important to note is that there _is_ a MobileDevice.framework API which is also used at other places, for example for the crash report fetching service. This service uses AFC, and the host-side service implementation is also outside of MobileDevice.framework inside DTDeviceKitBase.framework. After getting the socket via `AMDServiceConnectionGetSocket` another call to `AMDServiceConnectionGetSecureIOContext` is performed, effectively allowing the process to use the SSL session that has been established.

However this is a different scenario: The full implementation is inside DTDeviceKitBase.framework, so it effectively runs in a single process after all. But in the debugserver case, the code is split across multiple processes; we have Xcode that - through the mentioned frameworks - requests the debugserver service startup, but will then spawn `lldb-rpc-server` that in turn is meant to communicate with the debugserver service on the remote device. Retrieving the 'SecureIOContext' is probably not feasible here due to the process boundary, but also `lldb-rpc-server` in its current implementation 'only' works with a file descriptor.

## The Design Flaw
The problem is clearly visible now: this is an architectural design flaw. When MobileDevice.framework was created for the iPhone, there was initially no service that used SSL. This is also due to the fact that there was no WiFi support for services in earlier iOS versions and security-wise no need for SSL for connections going over USB. When Xcode was created, or also for other external tools, it was no problem at all to just expose the file descriptor through an API for their usage. However, systems evolve, and so the day came on which "WiFi sync" was created, where services were then forced to communicate in a ciphered way. This is when MobileDevice.framework was extended to perform the SSL handshake upon service startup (if the device requested it) and support SSL service connections. A few years later with iOS 11, also Xcode (and iOS for that matter) received the capabilities of "Remote debugging" or "Remote development", only that it looks like the code wasn't adapted to reflect the SSL service requirement, which is both visible in the implementation of debugserver and the Xcode frameworks/lldb-rpc-server. This is why we see the SSL handshake (which is implemented inside MobileDevice.framework) on the service connection, but are then greeted with plain text communication.

Looking at the bigger picture here how the SSL support has been implemented and "external services" have been added the design flaw becomes visible: MobileDevice.framework handles the SSL handshake while you can still externally get the "raw" file descriptor that is directly connected to the service on the device. This basically breaks the abstraction of the service communication code from the consumer application. Yes, as mentioned above, you *can* get the 'SecureIOContext' through `AMDServiceConnectionGetSecureIOContext` but this is not usable across processes.
This design flaw made it possible/too easy to 'create' issues like the one described in this advisory, just by providing a way to break the service abstraction.

## Proposed Solution
There are multiple ways this issue can be resolved. One way could be to provide an API that would return a service context that is externally usable and can be passed to `AMDServiceConnectionSend`, `AMDServiceConnectionReceive`, etc. (which actually *can* transparently handle connections with or without SSL context).

Another option would be to make sure the SSL context can be used from another process; this should be achievable via shared memory or XPC, with the design of an appropriate API for this.

Finally, it should also be possible to move the service startup code into `lldb-rpc-server` instead. This way there wouldn't be a process boundary so there wouldn't be a reason to bypass the service abstraction.

In any case `lldb-rpc-server` and also the device-side `debugserver` need to be updated to support encrypted communication as well.

## The Patch
The vulnerability was fully patched with Xcode 12 and iOS/iPadOS/tvOS 14, and partially patched in iOS/iPadOS/tvOS 13.6 and 13.7 (see `Downgrade attack`).

The patch is contained within Xcode which provides updated Developer Disk Images that introduce new, secure variants of the affected lockdownd services.

On the host side, Xcode will now first try to connect to the secure variants (suffixed with `DVTSecureSocketProxy`). On success the connection will be routed through an in-process proxy which will make use of the SSL context to strip the encryption layer, and finally transmit the raw data to `lldb-rpc-server`.

On the device side, similar to the host, the secure services will internally proxy the secure connection to strip the encryption layer and expose the raw data to the component using it.

## Downgrade Attack
Before the patch was publicly released, we were informed the following versions should contain the patch:

- Xcode 12 beta 3+ Tools with iOS and iPadOS 13.6, macOS 10.15.6, tvOS 13.4.8, or watchOS 6.2.8
- Xcode 12 beta 3+ Tools with iOS and iPadOS 14 beta 3+, macOS Big Sur 11 beta 3+, tvOS 14 beta 3+, or watchOS 7 beta 3+

After analyzing `Xcode 12 beta 3` and `Xcode 12 beta 4` to verify the supposed fix for our reported vulnerability, we noticed that the Developer Disk Images for `iOS < 13.6` do not contain any mitigations at all. The `13.6 and 14.0 DDIs` for `Xcode 12 beta 3` *do* contain the new `*.DVTSecureSocketProxy` variants for the affected services; however, they also still provide the old, insecure variants. With `Xcode 12 beta 4` (and up), the `14.0 DDI` does *not* have the insecure variants anymore, while the `13.6 DDI` still has them.

The issue with the current mitigation in Xcode is that it will fall back to the insecure service variant when the secure variant of the service cannot be started. As mentioned, with the `14.0 DDI` of `Xcode 12 beta 4` (and above), the insecure variants are not available anymore so the fallback mechanism cannot be abused to facilitate a "downgrade" attack in this case, but `13.6-13.7 DDI` is still affected.

With packet inspection, a MITM-attacker could match the `*.DVTSecureSocketProxy` StartService packet (based on size or other heuristical data) that gets sent to `lockdownd` on the device. When the attacker then drops the connection on purpose, it will look to Xcode like the new secure variant is not available, and it will fall back to the insecure variant. This will result in the original vulnerability still being exploitable in those cases.

To prove that this "downgrade" attack is feasible, we came up with a simple PoC that will purposefully make the SSL connection fail as soon as lockdownd receives the StartService packet for the `com.apple.debugserver.DVTSecureSocketProxy` variant. By hooking `SSLRead` in `lockdownd`, scanning for the service string, and returning an error code, this will simulate the previously described scenario of a MITM-attacker dropping the connection. Xcode will then assume the service startup just failed and fall back to the insecure debugserver service (if it is available), and as a result you can still happily debug via WiFi on a plaintext connection.

## Proof of Concept
A Proof of Concept demonstrating the vulnerability with a debug session hijack, remote code execution, and sensitive data exfiltration is provided together with this advisory in the `c0ntextomy` directory. Consult README.md for further details.
