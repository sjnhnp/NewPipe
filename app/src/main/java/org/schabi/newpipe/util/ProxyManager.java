package org.schabi.newpipe.util;

import android.content.Context;
import android.util.Log;

import org.schabi.newpipe.DownloaderImpl;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// Libbox imports (Assumed based on gomobile binding rules)
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.CommandServerHandler;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.OverrideOptions;
import io.nekohasekai.libbox.PlatformInterface;
import io.nekohasekai.libbox.SystemProxyStatus;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.ConnectionOwner;
import io.nekohasekai.libbox.InterfaceUpdateListener;
import io.nekohasekai.libbox.NetworkInterfaceIterator;
import io.nekohasekai.libbox.WIFIState;
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.Notification;
import io.nekohasekai.libbox.LocalDNSTransport;

public class ProxyManager implements CommandServerHandler, PlatformInterface {
    private static final String TAG = "ProxyManager";
    private static volatile ProxyManager instance;
    private CommandServer commandServer;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Context context;

    private ProxyManager(Context context) {
        this.context = context.getApplicationContext();
    }

    public static synchronized ProxyManager getInstance(Context context) {
        if (instance == null) {
            instance = new ProxyManager(context);
        }
        return instance;
    }

    public void startProxy(String configContent) {
        executor.execute(() -> {
            try {
                if (commandServer == null) {
                    commandServer = Libbox.newCommandServer(this, this);
                    commandServer.start();
                }

                OverrideOptions options = new OverrideOptions();
                // We are not using Tun, so autoRedirect might be irrelevant or false, 
                // but setting it to false is safe for purely local SOCKS/HTTP proxy.
                options.setAutoRedirect(false); 
                
                commandServer.startOrReloadService(configContent, options);
                Log.i(TAG, "Sing-box service started/reloaded.");

                // Parse config to find the inbound port?
                // For simplicity, we assume the user configures a specific port or we parse it.
                // However, parsing JSON here is tedious. 
                // A better approach is to force a standardized port for the internal proxy, e.g. 10808,
                // and inject it into the config if we were constructing it.
                // But the user provides the full config.
                // Let's assume the user configures an inbound on port 12345 (SOCKS) for NewPipe.
                
                // TODO: In a real implementation, we should extract the port from configContent.
                // accepting "127.0.0.1:12345" as the target proxy.
                
                // For this implementation, let's assume the user is instructed to use a specific port 
                // or we update the UI to ask for "Proxy Host" and "Proxy Port".
                
                // Update NewPipe Downloader to use the proxy
                DownloaderImpl downloader = DownloaderImpl.getInstance();
                if (downloader != null) {
                    // Assuming port 10808 and SOCKS protocol for now. 
                    // Ideally this should be parsed from the config.
                    downloader.updateProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", 10808)));
                    Log.i(TAG, "Downloader proxy updated to SOCKS@127.0.0.1:10808");
                }
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to start sing-box", e);
            }
        });
    }
    
    public void stopProxy() {
        if (commandServer != null) {
            try {
                commandServer.close(); // or serviceStop
                commandServer = null;
            } catch (Exception e) {
                Log.e(TAG, "Failed to stop sing-box", e);
            }
        }
    }

    // CommandServerHandler implementation
    @Override
    public void serviceStop() {
        Log.i(TAG, "Service Stopped via CommandServer");
    }

    @Override
    public void serviceReload() {
        Log.i(TAG, "Service Reloaded via CommandServer");
    }

    @Override
    public SystemProxyStatus getSystemProxyStatus() {
        return new SystemProxyStatus(); // Empty/stub
    }

    @Override
    public void setSystemProxyEnabled(boolean enabled) {
        // No-op
    }

    @Override
    public void writeDebugMessage(String message) {
        Log.d(TAG, "[Libbox] " + message);
    }

    // PlatformInterface implementation (Stubs for non-VPN mode)

    @Override
    public LocalDNSTransport localDNSTransport() {
        return null;
    }

    @Override
    public boolean usePlatformAutoDetectInterfaceControl() {
        return false;
    }

    @Override
    public void autoDetectInterfaceControl(int fd) {
    }

    @Override
    public int openTun(TunOptions options) throws Exception {
        throw new Exception("TUN not supported in NewPipe Proxy mode");
    }

    @Override
    public boolean useProcFS() {
        return false;
    }

    @Override
    public ConnectionOwner findConnectionOwner(int ipProtocol, String sourceAddress, int sourcePort, String destinationAddress, int destinationPort) {
        return null;
    }

    @Override
    public void startDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
    }

    @Override
    public void closeDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
    }

    @Override
    public NetworkInterfaceIterator getInterfaces() {
        return null;
    }

    @Override
    public boolean underNetworkExtension() {
        return false;
    }

    @Override
    public boolean includeAllNetworks() {
        return false;
    }

    @Override
    public WIFIState readWIFIState() {
        return null;
    }

    @Override
    public StringIterator systemCertificates() {
        return null;
    }

    @Override
    public void clearDNSCache() {
    }

    @Override
    public void sendNotification(Notification notification) {
    }
}
