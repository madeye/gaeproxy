package org.gaeproxy;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.appwidget.AppWidgetManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Bundle;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.RemoteViews;

public class GAEProxyService extends Service {

	private Notification notification;
	private NotificationManager notificationManager;
	private Intent intent;
	private PendingIntent pendIntent;

	public static final String BASE = "/data/data/org.gaeproxy/";

	private static final String TAG = "GAEProxyService";

	private Process httpProcess = null;
	private DataOutputStream httpOS = null;

	private String proxy;
	private String appHost = "203.208.39.99";
	private int port;
	private DNSServer dnsServer = null;

	private SharedPreferences settings = null;

	// Flag indicating if this is an ARMv6 device (-1: unknown, 0: no, 1: yes)
	private static int isARMv6 = -1;

	private static final Class<?>[] mStartForegroundSignature = new Class[] {
			int.class, Notification.class };
	private static final Class<?>[] mStopForegroundSignature = new Class[] { boolean.class };

	private Method mStartForeground;
	private Method mStopForeground;

	private Object[] mStartForegroundArgs = new Object[2];
	private Object[] mStopForegroundArgs = new Object[1];

	void invokeMethod(Method method, Object[] args) {
		try {
			method.invoke(this, mStartForegroundArgs);
		} catch (InvocationTargetException e) {
			// Should not happen.
			Log.w("ApiDemos", "Unable to invoke method", e);
		} catch (IllegalAccessException e) {
			// Should not happen.
			Log.w("ApiDemos", "Unable to invoke method", e);
		}
	}

	/**
	 * This is a wrapper around the new startForeground method, using the older
	 * APIs if it is not available.
	 */
	void startForegroundCompat(int id, Notification notification) {
		// If we have the new startForeground API, then use it.
		if (mStartForeground != null) {
			mStartForegroundArgs[0] = Integer.valueOf(id);
			mStartForegroundArgs[1] = notification;
			invokeMethod(mStartForeground, mStartForegroundArgs);
			return;
		}

		// Fall back on the old API.
		setForeground(true);
		notificationManager.notify(id, notification);
	}

	/**
	 * This is a wrapper around the new stopForeground method, using the older
	 * APIs if it is not available.
	 */
	void stopForegroundCompat(int id) {
		// If we have the new stopForeground API, then use it.
		if (mStopForeground != null) {
			mStopForegroundArgs[0] = Boolean.TRUE;
			try {
				mStopForeground.invoke(this, mStopForegroundArgs);
			} catch (InvocationTargetException e) {
				// Should not happen.
				Log.w("ApiDemos", "Unable to invoke stopForeground", e);
			} catch (IllegalAccessException e) {
				// Should not happen.
				Log.w("ApiDemos", "Unable to invoke stopForeground", e);
			}
			return;
		}

		// Fall back on the old API. Note to cancel BEFORE changing the
		// foreground state, since we could be killed at that point.
		notificationManager.cancel(id);
		setForeground(false);
	}

	/**
	 * Check if this is an ARMv6 device
	 * 
	 * @return true if this is ARMv6
	 */
	public static boolean isARMv6() {
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
			if (isARMv6 == 1) {
				Process process = null;
				DataOutputStream os = null;
				DataInputStream is = null;
				try {
					process = Runtime.getRuntime().exec("/system/bin/sh");
					os = new DataOutputStream(process.getOutputStream());
					is = new DataInputStream(process.getInputStream());
					os.writeBytes("/data/data/org.sshtunnel/iptables_g1 --version"
							+ "\n");
					os.flush();
					isARMv6 = 0;
					while (true) {
						String line = is.readLine();
						if (line == null || line.equals(""))
							break;
						if (line.contains("1.4.7")) {
							isARMv6 = 1;
							break;
						}
					}
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
			}
		}
		Log.d(TAG, "isARMv6: " + isARMv6);
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

	public boolean connect() {

		try {

			File conf = new File(BASE + "proxy.conf");
			if (!conf.exists())
				conf.createNewFile();
			FileOutputStream is = new FileOutputStream(conf);
			byte[] buffer = ("listen_port = " + port + "\n" + "fetch_server = "
					+ proxy + "\n").getBytes();
			is.write(buffer);
			is.flush();
			is.close();

			String cmd = BASE + "localproxy.sh";
			Log.e(TAG, cmd);

			httpProcess = Runtime.getRuntime().exec("su");
			httpOS = new DataOutputStream(httpProcess.getOutputStream());
			httpOS.writeBytes(cmd + "\n");
			httpOS.flush();

		} catch (Exception e) {
			Log.e(TAG, e.getMessage());
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
			runRootCommand(BASE + "proxy.sh start " + port);

			if (isARMv6()) {
				runRootCommand(BASE + "iptables_g1 -t nat -A OUTPUT -p tcp "
						+ "-d ! " + appHost
						+ " --dport 80  -j REDIRECT --to-ports 8123");
				// runRootCommand(BASE
				// + "iptables_g1 -t nat -A OUTPUT -p tcp "
				// + "--dport 443 -j REDIRECT --to-ports 8124");
				runRootCommand(BASE + "iptables_g1 -t nat -A OUTPUT -p udp "
						+ "--dport 53 -j REDIRECT --to-ports 8153");
			} else {
				runRootCommand(BASE + "iptables_n1 -t nat -A OUTPUT -p tcp "
						+ "-d ! " + appHost
						+ " --dport 80 -j REDIRECT --to-ports 8123");
				// runRootCommand(BASE
				// + "iptables_n1 -t nat -A OUTPUT -p tcp "
				// + "--dport 443 -j REDIRECT --to-ports 8124");
				runRootCommand(BASE + "iptables_g1 -t nat -A OUTPUT -p udp "
						+ "--dport 53 -j REDIRECT --to-ports 8153");
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

		Log.e(TAG, "GAE Proxy: " + proxy);
		Log.e(TAG, "Local Port: " + port);

		appHost = settings.getString("appHost", "");

		if (appHost.equals("")) {
			try {
				InetAddress addr = InetAddress.getByName("www.google.cn");
				appHost = addr.getHostAddress();
				Editor ed = settings.edit();
				ed.putString("appHost", appHost);
				ed.commit();
			} catch (Exception ignore) {
				return false;
			}
		}

		/*
		 * try { URL aURL = new URL("http://myhosts.sinaapp.com/apphosts");
		 * HttpURLConnection conn = (HttpURLConnection) aURL.openConnection();
		 * conn.setReadTimeout(10 * 1000); conn.connect(); InputStream is =
		 * conn.getInputStream(); BufferedReader reader = new BufferedReader(
		 * new InputStreamReader(is)); String line = reader.readLine(); if (line
		 * == null) return false; if (!line.startsWith("#GAEPROXY")) return
		 * false; while (true) { line = reader.readLine(); if (line == null)
		 * break; if (line.startsWith("#")) continue; line =
		 * line.trim().toLowerCase(); if (line.equals("")) continue; appHost =
		 * line; } } catch (Exception e) { Log.e(TAG,
		 * "cannot get remote host files", e); return false; }
		 */

		// String host = proxy.trim().toLowerCase().split("/")[2];
		// if (host == null || host.equals(""))
		// return false;

		// Add hosts here
		// runRootCommand(BASE + "host.sh add " + appHost + " " + host);

		dnsServer = new DNSServer("DNS Server", 8153, "8.8.8.8", 53,
				appHost);
		dnsServer.setBasePath(BASE);
		new Thread(dnsServer).start();

		int i = 0;
		while (!dnsServer.isInService() && i < 3) {
			try {
				Thread.sleep(5 * 1000);
			} catch (InterruptedException e) {
				// Nothing
			}
			i++;
		}
		
		if (i >= 3)
			return false;

		connect();
		finishConnection();
		return true;
	}

	private void notifyAlert(String title, String info) {
		notification.icon = R.drawable.icon;
		notification.tickerText = title;
		notification.flags = Notification.FLAG_ONGOING_EVENT;
		notification.defaults = Notification.DEFAULT_SOUND;
		notification.setLatestEventInfo(this, getString(R.string.app_name),
				info, pendIntent);
		startForegroundCompat(1, notification);
	}

	private void notifyAlert(String title, String info, int flags) {
		notification.icon = R.drawable.icon;
		notification.tickerText = title;
		notification.flags = flags;
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
		settings = PreferenceManager.getDefaultSharedPreferences(this);
		notificationManager = (NotificationManager) this
				.getSystemService(NOTIFICATION_SERVICE);

		intent = new Intent(this, GAEProxy.class);
		pendIntent = PendingIntent.getActivity(this, 0, intent, 0);
		notification = new Notification();

		try {
			mStartForeground = getClass().getMethod("startForeground",
					mStartForegroundSignature);
			mStopForeground = getClass().getMethod("stopForeground",
					mStopForegroundSignature);
		} catch (NoSuchMethodException e) {
			// Running on an older platform.
			mStartForeground = mStopForeground = null;
		}
	}

	/** Called when the activity is closed. */
	@Override
	public void onDestroy() {

		stopForegroundCompat(1);

		// runRootCommand(BASE + "host.sh remove");

		notifyAlert(getString(R.string.forward_stop),
				getString(R.string.service_stopped),
				Notification.FLAG_AUTO_CANCEL);

		// Make sure the connection is closed, important here
		onDisconnect();

		try {
			if (httpOS != null) {
				httpOS.writeBytes("\\cC");
				httpOS.writeBytes("exit\n");
				httpOS.flush();
				httpOS.close();
			}
			if (httpProcess != null)
				httpProcess.destroy();
		} catch (Exception e) {
			Log.e(TAG, "HTTP Server close unexpected");
		}

		try {
			if (dnsServer != null)
				dnsServer.close();
		} catch (Exception e) {
			Log.e(TAG, "DNS Server close unexpected");
		}

		// for widget, maybe exception here
		try {
			RemoteViews views = new RemoteViews(getPackageName(),
					R.layout.gaeproxy_appwidget);
			views.setImageViewResource(R.id.serviceToggle, R.drawable.off);
			AppWidgetManager.getInstance(this).updateAppWidget(
					GAEProxyWidgetProvider.widgets, views);
		} catch (Exception ignore) {
			// Nothing
		}

		super.onDestroy();
	}

	private void onDisconnect() {

		if (isARMv6()) {
			runRootCommand(BASE + "iptables_g1 -t nat -F OUTPUT");
		} else {
			runRootCommand(BASE + "iptables_n1 -t nat -F OUTPUT");
		}

		runRootCommand(BASE + "proxy.sh stop");

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
			Editor ed = settings.edit();
			ed.putBoolean("isRunning", true);
			ed.commit();

			// for widget, maybe exception here
			try {
				RemoteViews views = new RemoteViews(getPackageName(),
						R.layout.gaeproxy_appwidget);
				views.setImageViewResource(R.id.serviceToggle, R.drawable.on);
				AppWidgetManager.getInstance(this).updateAppWidget(
						GAEProxyWidgetProvider.widgets, views);
			} catch (Exception ignore) {
				// Nothing
			}

			super.onStart(intent, startId);

		} else {
			// Connection or forward unsuccessful
			notifyAlert(getString(R.string.forward_fail),
					getString(R.string.service_failed));
			Editor ed = settings.edit();
			ed.putBoolean("isRunning", false);
			ed.commit();
			stopSelf();
		}
	}

}
