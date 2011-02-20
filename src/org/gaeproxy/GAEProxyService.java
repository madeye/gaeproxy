package org.gaeproxy;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileReader;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

public class GAEProxyService extends Service {

	private Notification notification;
	private NotificationManager notificationManager;
	private Intent intent;
	private PendingIntent pendIntent;

	private static final String TAG = "GAEProxy";
	public static final String PREFS_NAME = "GAEProxy";

	private String proxy;
	private int port;
	private boolean isAutoSetProxy = false;
	private DNSServer dnsServer = null;
	private HTTPServer httpServer = null;

	// Flag indicating if this is an ARMv6 device (-1: unknown, 0: no, 1: yes)
	private static int isARMv6 = -1;

	/**
	 * Check if this is an ARMv6 device
	 * 
	 * @return true if this is ARMv6
	 */
	private static boolean isARMv6() {
		if (isARMv6 == -1) {
			BufferedReader r = null;
			try {
				isARMv6 = 0;
				r = new BufferedReader(new FileReader("/proc/cpuinfo"));
				for (String line = r.readLine(); line != null; line = r
						.readLine()) {
					if (line.startsWith("Processor") && line.contains("ARMv6")) {
						isARMv6 = 1;
						break;
					} else if (line.startsWith("CPU architecture")
							&& (line.contains("6TE") || line.contains("5TE"))) {
						isARMv6 = 1;
						break;
					}
				}
			} catch (Exception ex) {
			} finally {
				if (r != null)
					try {
						r.close();
					} catch (Exception ex) {
					}
			}
		}
		return (isARMv6 == 1);
	}

	public static boolean runRootCommand(String command) {
		Process process = null;
		DataOutputStream os = null;
		try {
			process = Runtime.getRuntime().exec("su");
			os = new DataOutputStream(process.getOutputStream());
			os.writeBytes(command + "\n");
			os.writeBytes("exit\n");
			os.flush();
			process.waitFor();
		} catch (Exception e) {
			Log.e(TAG, e.getMessage());
			return false;
		} finally {
			try {
				if (os != null) {
					os.close();
				}
				process.destroy();
			} catch (Exception e) {
				// nothing
			}
		}
		return true;
	}

	/**
	 * Internal method to request actual PTY terminal once we've finished
	 * authentication. If called before authenticated, it will just fail.
	 */
	private void finishConnection() {

		try {
			Log.e(TAG, "Forward Successful");
			if (isAutoSetProxy) {
				runRootCommand("/data/data/org.gaeproxy/proxy.sh start " + port);

				if (isARMv6()) {
					runRootCommand("/data/data/org.gaeproxy/iptables_g1 -t nat -A OUTPUT -p tcp "
							+ "-d ! 74.125.153.141 --dport 80  -j REDIRECT --to-ports 8123");
					runRootCommand("/data/data/org.gaeproxy/iptables_g1 -t nat -A OUTPUT -p tcp "
							+ "-d ! 74.125.153.141 --dport 443 -j REDIRECT --to-ports 8124");
					runRootCommand("/data/data/org.gaeproxy/iptables_g1 -t nat -A OUTPUT -p udp "
							+ "--dport 53 -j REDIRECT --to-ports 8153");
				} else {
					runRootCommand("/data/data/org.gaeproxy/iptables_n1 -t nat -A OUTPUT -p tcp "
							+ "-d ! 74.125.153.141 --dport 80 -j REDIRECT --to-ports 8123");
					runRootCommand("/data/data/org.gaeproxy/iptables_n1 -t nat -A OUTPUT -p tcp "
							+ "-d ! 74.125.153.141 --dport 443 -j REDIRECT --to-ports 8124");
					runRootCommand("/data/data/org.gaeproxy/iptables_g1 -t nat -A OUTPUT -p udp "
							+ "--dport 53 -j REDIRECT --to-ports 8153");
				}
			}

		} catch (Exception e) {
			Log.e(TAG, "Error setting up port forward during connect", e);
		}

	}

	/** Called when the activity is first created. */
	public boolean handleCommand(Intent it) {

		Log.e(TAG, "Service Start");

		Bundle bundle = it.getExtras();
		proxy = bundle.getString("proxy");
		port = bundle.getInt("port");
		isAutoSetProxy = bundle.getBoolean("isAutoSetProxy");
		
		Log.e(TAG, "GAE Proxy: " + proxy);
		Log.e(TAG, "Local Port: " + port);

		dnsServer = new DNSServer("DNS Server", 8153, "127.0.0.1", 1053);
		dnsServer.setBasePath("/data/data/org.gaeproxy");
		new Thread(dnsServer).start();

		httpServer = new HTTPServer(proxy, port);
		new Thread(httpServer).start();

		if (httpServer.isInService() && dnsServer.isInService())
			finishConnection();
		return true;
	}

	private void notifyAlert(String title, String info) {
		notification.icon = R.drawable.icon;
		notification.tickerText = title;
		notification.setLatestEventInfo(this, getString(R.string.app_name),
				info, pendIntent);
		notificationManager.notify(0, notification);
	}

	@Override
	public IBinder onBind(Intent intent) {
		return null;
	}

	@Override
	public void onCreate() {
		super.onCreate();
		notificationManager = (NotificationManager) this
				.getSystemService(NOTIFICATION_SERVICE);

		intent = new Intent(this, GAEProxy.class);
		pendIntent = PendingIntent.getActivity(this, 0, intent, 0);
		notification = new Notification();
	}

	/** Called when the activity is closed. */
	@Override
	public void onDestroy() {

		notifyAlert(getString(R.string.forward_stop),
				getString(R.string.service_stopped));

		// Make sure the connection is closed, important here
		onDisconnect();

		try {
			if (httpServer != null)
				httpServer.close();
		} catch (Exception e) {
			Log.e(TAG, "HTTP Server close unexpected");
		}

		try {
			if (dnsServer != null)
				dnsServer.close();
		} catch (Exception e) {
			Log.e(TAG, "DNS Server close unexpected");
		}
		super.onDestroy();
	}

	private void onDisconnect() {

		if (isAutoSetProxy) {
			if (isARMv6()) {
				runRootCommand("/data/data/org.gaeproxy/iptables_g1 -t nat -F OUTPUT");
			} else {
				runRootCommand("/data/data/org.gaeproxy/iptables_n1 -t nat -F OUTPUT");
			}

			runRootCommand("/data/data/org.gaeproxy/proxy.sh stop");
		}

	}

	// This is the old onStart method that will be called on the pre-2.0
	// platform. On 2.0 or later we override onStartCommand() so this
	// method will not be called.
	@Override
	public void onStart(Intent intent, int startId) {
		if (handleCommand(intent)) {
			// Connection and forward successful
			notifyAlert(getString(R.string.forward_success),
					getString(R.string.service_running));

			super.onStart(intent, startId);

		} else {
			// Connection or forward unsuccessful
			notifyAlert(getString(R.string.forward_fail),
					getString(R.string.service_failed));
			stopSelf();
		}
	}

}
