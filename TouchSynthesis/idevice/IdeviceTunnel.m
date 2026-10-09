#import "IdeviceTunnel.h"
#include "idevice.h"
#include <arpa/inet.h>
#include <pthread.h>

@implementation TunnelServiceInfo
@end

// ============================================================
// Architecture (iOS 26.6+, matching StikDebug 3.1.13):
//
// iOS 26.6 resets lockdownd (62078) connections that arrive through the
// loopback VPN, so the old "lockdownd heartbeat + CoreDeviceProxy" path no
// longer works on-device. Instead we open ONE RemotePairing tunnel to the
// pairing port (49152) with `tunnel_create_rppairing`. It pair-verifies with
// the RP keys in the pairing file (public_key / private_key / identifier, as
// written by iloader) and hands back a TCP adapter plus an RSD handshake.
//
// Every operation (screenshot, proxy) opens its own stream on that shared
// adapter. Re-creating the tunnel per operation is avoided on purpose: a new
// RemotePairing tunnel for the same host identity can tear down the old one,
// which would kill the long-lived testmanagerd proxies.
// ============================================================

static const uint16_t kRemotePairingPort = 49152;

/// Tracks one running proxy bridge (local TCP <-> ReadWriteOpaque stream).
@interface _ProxyBridge : NSObject
@property (nonatomic, assign) int serverFD;
@property (nonatomic, assign) int clientFD;
@property (nonatomic, assign) uint16_t localPort;
@property (nonatomic, assign) struct ReadWriteOpaque *stream;
@property (nonatomic, assign) BOOL running;
@end

@implementation _ProxyBridge
- (void)dealloc {
    [self stop];
}
- (void)stop {
    _running = NO;
    if (_clientFD > 0) { close(_clientFD); _clientFD = -1; }
    if (_serverFD > 0) { close(_serverFD); _serverFD = -1; }
    if (_stream) { idevice_stream_free(_stream); _stream = NULL; }
}
@end

@implementation IdeviceTunnel {
    // Shared RemotePairing tunnel; guarded by _tunnelLock together with the
    // FFI calls that borrow it (they take &mut on the Rust side).
    struct AdapterHandle *_adapter;
    struct RsdHandshakeHandle *_handshake;
    NSLock *_tunnelLock;

    // Saved connection params
    NSString *_savedPairingPath;
    NSString *_savedDeviceIP;
    BOOL _connected;

    // Active proxy bridges
    NSMutableArray<_ProxyBridge *> *_proxies;
}

- (instancetype)init {
    if ((self = [super init])) {
        _tunnelLock = [NSLock new];
    }
    return self;
}

- (BOOL)isConnected {
    return _connected;
}

/// There is no lockdownd heartbeat any more; the RemotePairing tunnel is the keepalive.
- (BOOL)heartbeatRunning {
    return _connected && _adapter != NULL;
}

// MARK: - Connect (opens the shared RemotePairing tunnel)

- (nullable NSString *)connectWithPairingFile:(NSString *)pairingFilePath
                                     deviceIP:(NSString *)deviceIP
                                         port:(uint16_t)port {
    (void)port;  // lockdownd's port is unused now; the tunnel goes through RemotePairing on 49152
    [self disconnect];

    _savedPairingPath = [pairingFilePath copy];
    _savedDeviceIP = [deviceIP copy];

    [_tunnelLock lock];
    NSString *err = [self _openTunnelLocked];
    [_tunnelLock unlock];
    if (err != nil) {
        return err;
    }

    _connected = YES;
    return nil;
}

// MARK: - Shared tunnel

/// Opens the RemotePairing tunnel if it isn't open yet. Call with _tunnelLock held.
/// Returns nil on success, or an error string.
- (nullable NSString *)_openTunnelLocked {
    if (_adapter != NULL && _handshake != NULL) {
        return nil;
    }
    if (!_savedPairingPath || !_savedDeviceIP) {
        return @"Not connected — call connect first";
    }

    struct RpPairingFileHandle *pairing = NULL;
    IdeviceFfiError *err = rp_pairing_file_read([_savedPairingPath UTF8String], &pairing);
    if (err != NULL) {
        NSString *msg = [NSString stringWithFormat:
            @"RP pairing file read failed: %s (the file needs public_key/private_key/identifier — "
            @"import the pairing file StikDebug uses)", err->message];
        idevice_error_free(err);
        return msg;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kRemotePairingPort);
    if (inet_pton(AF_INET, [_savedDeviceIP UTF8String], &addr.sin_addr) != 1) {
        rp_pairing_file_free(pairing);
        return @"Invalid device IP address";
    }

    struct AdapterHandle *adapter = NULL;
    struct RsdHandshakeHandle *handshake = NULL;
    err = tunnel_create_rppairing((const idevice_sockaddr *)&addr,
                                  (idevice_socklen_t)sizeof(addr),
                                  "TouchSynthesis",
                                  pairing,  // borrowed
                                  NULL, NULL,  // no PIN: pair-setup can't run here, pair-verify must succeed
                                  &adapter,
                                  &handshake);
    rp_pairing_file_free(pairing);
    if (err != NULL) {
        NSString *msg = [NSString stringWithFormat:@"RemotePairing tunnel to %@:%u failed: %s",
                         _savedDeviceIP, kRemotePairingPort, err->message];
        idevice_error_free(err);
        return msg;
    }

    _adapter = adapter;
    _handshake = handshake;
    NSLog(@"[IdeviceTunnel] RemotePairing tunnel up (%@:%u)", _savedDeviceIP, kRemotePairingPort);
    return nil;
}

/// Frees the shared tunnel. Call with _tunnelLock held.
- (void)_closeTunnelLocked {
    if (_handshake) { rsd_handshake_free(_handshake); _handshake = NULL; }
    if (_adapter) { adapter_free(_adapter); _adapter = NULL; }
}

/// After a failed operation, drop the tunnel so the next one reconnects —
/// but only when no proxy is still streaming through it.
- (void)_dropTunnelIfIdle {
    for (_ProxyBridge *bridge in _proxies) {
        if (bridge.running) return;
    }
    [_tunnelLock lock];
    [self _closeTunnelLocked];
    [_tunnelLock unlock];
}

// MARK: - Screenshot

- (nullable NSData *)takeScreenshotAndReturnError:(NSString *_Nullable *_Nullable)outError {
    // Create RemoteServer on the shared tunnel
    [_tunnelLock lock];
    NSString *tunnelErr = [self _openTunnelLocked];
    if (tunnelErr != nil) {
        [_tunnelLock unlock];
        if (outError) *outError = tunnelErr;
        return nil;
    }
    struct RemoteServerHandle *remoteServer = NULL;
    IdeviceFfiError *err = remote_server_connect_rsd(_adapter, _handshake, &remoteServer);
    [_tunnelLock unlock];
    if (err != NULL) {
        if (outError) *outError = [NSString stringWithFormat:@"RemoteServer: %s", err->message];
        idevice_error_free(err);
        [self _dropTunnelIfIdle];
        return nil;
    }

    // Create ScreenshotClient
    struct ScreenshotClientHandle *ssClient = NULL;
    err = screenshot_client_new(remoteServer, &ssClient);
    if (err != NULL) {
        if (outError) *outError = [NSString stringWithFormat:@"ScreenshotClient: %s", err->message];
        idevice_error_free(err);
        remote_server_free(remoteServer);
        return nil;
    }

    // Take screenshot
    uint8_t *pngData = NULL;
    uintptr_t pngLen = 0;
    err = screenshot_client_take_screenshot(ssClient, &pngData, &pngLen);
    if (err != NULL) {
        if (outError) *outError = [NSString stringWithFormat:@"Screenshot: %s", err->message];
        idevice_error_free(err);
        screenshot_client_free(ssClient);
        remote_server_free(remoteServer);
        return nil;
    }

    // Copy PNG data before freeing FFI memory
    NSData *result = nil;
    if (pngData != NULL && pngLen > 0) {
        result = [NSData dataWithBytes:pngData length:pngLen];
        idevice_data_free(pngData, pngLen);
    }

    // Cleanup (the tunnel itself stays up)
    screenshot_client_free(ssClient);
    remote_server_free(remoteServer);

    if (result == nil && outError) {
        *outError = @"Screenshot returned empty data";
    }
    return result;
}

// MARK: - RSD TCP Proxy

- (uint16_t)createProxyToRSDService:(NSString *)serviceName
                              error:(NSString *_Nullable *_Nullable)outError {
    if (!_proxies) _proxies = [NSMutableArray new];

    // Step 1-3: find the service via RSD and open a stream to it on the shared tunnel
    [_tunnelLock lock];
    NSString *tunnelErr = [self _openTunnelLocked];
    if (tunnelErr != nil) {
        [_tunnelLock unlock];
        if (outError) *outError = tunnelErr;
        return 0;
    }

    struct CRsdService *svcInfo = NULL;
    IdeviceFfiError *err = rsd_get_service_info(_handshake, [serviceName UTF8String], &svcInfo);
    if (err != NULL) {
        [_tunnelLock unlock];
        if (outError) *outError = [NSString stringWithFormat:@"RSD service '%@': %s", serviceName, err->message];
        idevice_error_free(err);
        return 0;
    }

    uint16_t servicePort = svcInfo->port;
    NSLog(@"[Proxy] Found %@ on port %u", serviceName, servicePort);
    rsd_free_service(svcInfo);

    struct ReadWriteOpaque *stream = NULL;
    err = adapter_connect(_adapter, servicePort, &stream);
    [_tunnelLock unlock];
    if (err != NULL) {
        if (outError) *outError = [NSString stringWithFormat:@"adapter_connect to port %u: %s", servicePort, err->message];
        idevice_error_free(err);
        [self _dropTunnelIfIdle];
        return 0;
    }

    // Step 4: Create local TCP server socket on 127.0.0.1:0
    int serverFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverFD < 0) {
        if (outError) *outError = @"socket() failed for local proxy";
        idevice_stream_free(stream);
        return 0;
    }

    int reuse = 1;
    setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    localAddr.sin_port = 0; // random port

    if (bind(serverFD, (struct sockaddr *)&localAddr, sizeof(localAddr)) < 0) {
        if (outError) *outError = [NSString stringWithFormat:@"bind() failed: errno=%d", errno];
        close(serverFD);
        idevice_stream_free(stream);
        return 0;
    }

    if (listen(serverFD, 1) < 0) {
        if (outError) *outError = [NSString stringWithFormat:@"listen() failed: errno=%d", errno];
        close(serverFD);
        idevice_stream_free(stream);
        return 0;
    }

    // Get assigned port
    struct sockaddr_in boundAddr;
    socklen_t addrLen = sizeof(boundAddr);
    getsockname(serverFD, (struct sockaddr *)&boundAddr, &addrLen);
    uint16_t localPort = ntohs(boundAddr.sin_port);

    NSLog(@"[Proxy] Listening on 127.0.0.1:%u -> %@:%u", localPort, serviceName, servicePort);

    // Step 5: Create bridge object
    _ProxyBridge *bridge = [_ProxyBridge new];
    bridge.serverFD = serverFD;
    bridge.clientFD = -1;
    bridge.localPort = localPort;
    bridge.stream = stream;
    bridge.running = YES;
    [_proxies addObject:bridge];

    // Step 6: Start bridge threads
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSLog(@"[Proxy] Waiting for DTXConnection on port %u...", localPort);

        // Set accept timeout (30s)
        struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
        setsockopt(serverFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientFD = accept(serverFD, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientFD < 0) {
            NSLog(@"[Proxy] accept() failed: errno=%d", errno);
            bridge.running = NO;
            return;
        }

        bridge.clientFD = clientFD;
        NSLog(@"[Proxy] DTXConnection accepted on port %u", localPort);

        // Bridge thread A: local socket -> readwrite_send
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            uint8_t buf[16384];
            while (bridge.running) {
                ssize_t n = recv(clientFD, buf, sizeof(buf), 0);
                if (n <= 0) {
                    NSLog(@"[Proxy->Device] recv returned %zd, errno=%d", n, errno);
                    bridge.running = NO;
                    break;
                }
                IdeviceFfiError *sendErr = readwrite_send(stream, buf, (uintptr_t)n);
                if (sendErr != NULL) {
                    NSLog(@"[Proxy->Device] readwrite_send failed: %s", sendErr->message);
                    idevice_error_free(sendErr);
                    bridge.running = NO;
                    break;
                }
            }
            NSLog(@"[Proxy->Device] Thread exiting for port %u", localPort);
        });

        // Bridge thread B: readwrite_recv -> local socket
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            uint8_t buf[16384];
            while (bridge.running) {
                uintptr_t bytesRead = 0;
                IdeviceFfiError *recvErr = readwrite_recv(stream, buf, &bytesRead, sizeof(buf));
                if (recvErr != NULL) {
                    NSLog(@"[Device->Proxy] readwrite_recv failed: %s", recvErr->message);
                    idevice_error_free(recvErr);
                    bridge.running = NO;
                    break;
                }
                if (bytesRead == 0) {
                    NSLog(@"[Device->Proxy] readwrite_recv returned 0 bytes");
                    bridge.running = NO;
                    break;
                }
                uintptr_t totalSent = 0;
                while (totalSent < bytesRead && bridge.running) {
                    ssize_t n = send(clientFD, buf + totalSent, bytesRead - totalSent, 0);
                    if (n <= 0) {
                        NSLog(@"[Device->Proxy] send returned %zd", n);
                        bridge.running = NO;
                        break;
                    }
                    totalSent += n;
                }
            }
            NSLog(@"[Device->Proxy] Thread exiting for port %u", localPort);
        });
    });

    return localPort;
}

- (void)stopAllProxies {
    for (_ProxyBridge *bridge in _proxies) {
        [bridge stop];
    }
    [_proxies removeAllObjects];
}

/// Cheap reachability check for the UI. Opening a fresh RemotePairing tunnel
/// here (like the old CDTunnel ping did) would tear down the shared one.
- (BOOL)pingTunnel {
    if (!_connected) return NO;
    [_tunnelLock lock];
    NSString *err = [self _openTunnelLocked];
    [_tunnelLock unlock];
    return err == nil;
}

// MARK: - Disconnect

- (void)disconnect {
    // Stop proxies first: their streams live on the shared adapter
    [self stopAllProxies];

    [_tunnelLock lock];
    [self _closeTunnelLocked];
    [_tunnelLock unlock];
    _connected = NO;
}

- (void)dealloc {
    [self disconnect];
}

@end
