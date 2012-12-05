package org.gaeproxy;

import android.content.Context;
import android.net.ProxyProperties;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.util.Log;

import java.util.List;

public class WifiProxyManager {

  private static int networkID = -1;

  private static final String TAG = "WifiProxyManager";

  public static boolean setWifiProxy(String proxy, int port, Context context) {

    try {

      Handler handler = new Handler(context.getMainLooper());

      final WifiManager manager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);

      if (!manager.isWifiEnabled()) return false;
      List<WifiConfiguration> configurationList = manager.getConfiguredNetworks();
      WifiConfiguration configuration = null;
      int cur = manager.getConnectionInfo().getNetworkId();
      for (WifiConfiguration wifiConfiguration : configurationList) {
        if (wifiConfiguration.networkId == cur)
          configuration = wifiConfiguration;
      }
      if (configuration == null) return false;

      WifiConfiguration config = new WifiConfiguration(configuration);
      config.ipAssignment = WifiConfiguration.IpAssignment.UNASSIGNED;
      config.proxySettings = WifiConfiguration.ProxySettings.STATIC;
      config.linkProperties.clear();

      config.linkProperties.setHttpProxy(new ProxyProperties("127.0.0.1", port, ""));
      manager.updateNetwork(config);

      manager.setWifiEnabled(false);
      handler.postDelayed(new Runnable() {
        @Override
        public void run() {
          manager.setWifiEnabled(true);
        }
      }, 1000);

      networkID = cur;
    } catch (Exception ignored) {
      // Ignore all private API exception
      Log.d(TAG, "Non support API", ignored);
      return false;
    }
    return true;
  }

  public static void clearWifiProxy(Context context) {
    if (networkID == -1) return;
    try {

      Handler handler = new Handler(context.getMainLooper());

      final WifiManager manager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
      List<WifiConfiguration> configurationList = manager.getConfiguredNetworks();
      WifiConfiguration configuration = null;
      for (WifiConfiguration wifiConfiguration : configurationList) {
        if (wifiConfiguration.networkId == networkID)
          configuration = wifiConfiguration;
      }
      if (configuration == null) return;

      WifiConfiguration config = new WifiConfiguration(configuration);
      config.ipAssignment = WifiConfiguration.IpAssignment.UNASSIGNED;
      config.proxySettings = WifiConfiguration.ProxySettings.NONE;
      config.linkProperties.clear();

      manager.updateNetwork(config);

      manager.setWifiEnabled(false);
      handler.postDelayed(new Runnable() {
        @Override
        public void run() {
          manager.setWifiEnabled(true);
        }
      }, 1000);

      networkID = -1;
    } catch (Exception ignored) {
      // Ignore all private API exception
      Log.d(TAG, "Non support API", ignored);
    }
  }
}
