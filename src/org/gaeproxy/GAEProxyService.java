/* gaeproxy - GAppProxy / WallProxy client App for Android
 * Copyright (C) 2011 <max.c.lv@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 *                            ___====-_  _-====___
 *                      _--^^^#####//      \\#####^^^--_
 *                   _-^##########// (    ) \\##########^-_
 *                  -############//  |\^^/|  \\############-
 *                _/############//   (@::@)   \\############\_
 *               /#############((     \\//     ))#############\
 *              -###############\\    (oo)    //###############-
 *             -#################\\  / VV \  //#################-
 *            -###################\\/      \//###################-
 *           _#/|##########/\######(   /\   )######/\##########|\#_
 *           |/ |#/\#/\#/\/  \#/\##\  |  |  /##/\#/  \/\#/\#/\#| \|
 *           `  |/  V  V  `   V  \#\| |  | |/#/  V   '  V  V  \|  '
 *              `   `  `      `   / | |  | | \   '      '  '   '
 *                               (  | |  | |  )
 *                              __\ | |  | | /__
 *                             (vvv(VVV)(VVV)vvv)
 *
 *                              HERE BE DRAGONS
 *
 */

package org.gaeproxy;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.Random;

import com.flurry.android.FlurryAgent;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.appwidget.AppWidgetManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.RemoteViews;

public class GAEProxyService extends Service {

	private Notification notification;
	private NotificationManager notificationManager;
	private Intent intent;
	private PendingIntent pendIntent;
	private PowerManager.WakeLock mWakeLock;

	public static final String BASE = "/data/data/org.gaeproxy/";
	private static final int MSG_CONNECT_START = 0;
	private static final int MSG_CONNECT_FINISH = 1;
	private static final int MSG_CONNECT_SUCCESS = 2;
	private static final int MSG_CONNECT_FAIL = 3;
	private static final int MSG_HOST_CHANGE = 4;
	private static final int MSG_STOP_SELF = 5;

	final static String CMD_IPTABLES_REDIRECT_ADD_HTTP = BASE
			+ "iptables -t nat -A OUTPUT -p tcp " + "! -d 203.208.0.0/16 "
			+ "--dport 80 -j REDIRECT --to 8123\n";
	final static String CMD_IPTABLES_REDIRECT_ADD_HTTPS = BASE
			+ "iptables -t nat -A OUTPUT -p tcp " + "! -d 203.208.0.0/16 "
			+ "--dport 443 -j REDIRECT --to 8124\n";

	final static String CMD_IPTABLES_DNAT_ADD_HTTP = BASE
			+ "iptables -t nat -A OUTPUT -p tcp " + "! -d 203.208.0.0/16 "
			+ "--dport 80 -j DNAT --to-destination 127.0.0.1:8123\n";
	final static String CMD_IPTABLES_DNAT_ADD_HTTPS = BASE
			+ "iptables -t nat -A OUTPUT -p tcp " + "! -d 203.208.0.0/16 "
			+ "--dport 443 -j DNAT --to-destination 127.0.0.1:8124\n";

	private static final String TAG = "GAEProxyService";

	private Process httpProcess = null;
	private DataOutputStream httpOS = null;

	private String proxy;
	private String appHost = "203.208.46.1";
	private String appMask = "203.208.0.0";
	private int port;
	private String sitekey;
	private String proxyType = "GoAgent";
	private DNSServer dnsServer = null;

	private SharedPreferences settings = null;

	private boolean hasRedirectSupport = true;
	private boolean isGlobalProxy = false;
	private boolean isHTTPSProxy = false;
	private boolean isDNSBlocked = true;
	private boolean isGFWList = false;

	private ProxyedApp apps[];

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

	private void initHasRedirectSupported() {
		Process process = null;
		DataOutputStream os = null;
		DataInputStream es = null;

		String command;
		String line = null;

		command = "/data/data/org.gaeproxy/iptables -t nat -A OUTPUT -p udp --dport 54 -j REDIRECT --to 8154";

		try {
			process = Runtime.getRuntime().exec("su");
			es = new DataInputStream(process.getErrorStream());
			os = new DataOutputStream(process.getOutputStream());
			os.writeBytes(command + "\n");
			os.writeBytes("exit\n");
			os.flush();
			process.waitFor();

			while (null != (line = es.readLine())) {
				Log.d(TAG, line);
				if (line.contains("No chain/target/match")) {
					this.hasRedirectSupport = false;
					break;
				}
			}
		} catch (Exception e) {
			Log.e(TAG, e.getMessage());
		} finally {
			try {
				if (os != null) {
					os.close();
				}
				if (es != null)
					es.close();
				process.destroy();
			} catch (Exception e) {
				// nothing
			}
		}

		// flush the check command
		runRootCommand(command.replace("-A", "-D"));
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

	public static boolean runRootCommand(String command) {
		Process process = null;
		DataOutputStream os = null;
		Log.d(TAG, command);
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

	public static boolean runCommand(String command) {
		Process process = null;
		Log.d(TAG, command);
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor();
		} catch (Exception e) {
			Log.e(TAG, e.getMessage());
			return false;
		} finally {
			try {
				if (process != null)
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

			String cmd = BASE;
			if (isDNSBlocked)
				cmd = BASE + "localproxy.sh";
			else
				cmd = BASE + "localproxy_en.sh";

			if (proxyType.equals("GAppProxy")) {
				cmd += " gappproxy";
			} else if (proxyType.equals("WallProxy")) {
				cmd += " wallproxy " + proxy + " " + port + " " + sitekey;
			} else if (proxyType.equals("GoAgent")) {
				String[] proxyString = proxy.split("\\/");
				if (proxyString.length < 4)
					return false;
				cmd += " goagent " + proxyString[2] + " " + port + " "
						+ appHost + " " + proxyString[3] + " " + sitekey;
			}
			Log.e(TAG, cmd);

			httpProcess = Runtime.getRuntime().exec(cmd);
			// httpOS = new DataOutputStream(httpProcess.getOutputStream());
			// httpOS.writeBytes(cmd + "\n");
			// httpOS.flush();

			Thread t = new Thread() {
				public void run() {
					try {
						httpProcess.waitFor();
					} catch (InterruptedException e) {
						// Interrupted
					}
					handler.sendEmptyMessage(MSG_STOP_SELF);
				}
			};
			t.setDaemon(true);
			t.start();

		} catch (Exception e) {
			Log.e(TAG, "Cannot connect");
		}

		return true;
	}

	/**
	 * Internal method to request actual PTY terminal once we've finished
	 * authentication. If called before authenticated, it will just fail.
	 */
	private boolean preConnection() {

		if (isHTTPSProxy) {
			InputStream is = null;
			String socksIp = "173.192.90.214";
			String socksPort = "16976";
			try {
				URL aURL = new URL("http://www.madeye.dotcloud.com/port.php");
				HttpURLConnection conn = (HttpURLConnection) aURL
						.openConnection();
				conn.connect();
				is = conn.getInputStream();

				BufferedReader reader = new BufferedReader(
						new InputStreamReader(is));

				String line = reader.readLine();
				if (!line.startsWith("#ip"))
					throw new Exception("Format error");
				line = reader.readLine();
				socksIp = line.trim().toLowerCase();

				line = reader.readLine();
				if (!line.startsWith("#port"))
					throw new Exception("Format error");
				line = reader.readLine();
				socksPort = line.trim().toLowerCase();
			} catch (Exception e) {
				Log.e(TAG, "cannot get remote port info", e);
				return false;
			}

			Log.d(TAG, "Forward Successful");
			runCommand(BASE + "proxy_socks.sh stop");
			runCommand(BASE + "proxy_socks.sh start " + port + " " + socksIp
					+ " " + socksPort);

		} else {

			String socksIp = "173.224.211.42";
			try {
				InetAddress addr = InetAddress.getByName("apps.madeye.me");
				socksIp = addr.getHostAddress();

			} catch (Exception ignore) {
				socksIp = "173.224.211.42";
			}

			Log.d(TAG, "Forward Successful");
			runCommand(BASE + "proxy.sh stop");
			runCommand(BASE + "proxy.sh start " + port + " " + socksIp + " "
					+ "1984");
		}

		StringBuffer cmd = new StringBuffer();

		if (hasRedirectSupport) {
			cmd.append(BASE
					+ "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to 8153\n");
		} else {
			cmd.append(BASE
					+ "iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:8153\n");
		}

		if (isGFWList) {
			String cmd_http = hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTP
					: CMD_IPTABLES_DNAT_ADD_HTTP;
			String cmd_https = hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTPS
					: CMD_IPTABLES_DNAT_ADD_HTTPS;

			String[] gfw_list = getResources().getStringArray(R.array.gfw_list);

			for (String item : gfw_list) {
				cmd.append(cmd_http
						.replace("! -d 203.208.0.0/16", "-d " + item));
				cmd.append(cmd_https.replace("! -d 203.208.0.0/16", "-d "
						+ item));
			}
		} else if (isGlobalProxy) {
			cmd.append(hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTP
					: CMD_IPTABLES_DNAT_ADD_HTTP);
			cmd.append(hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTPS
					: CMD_IPTABLES_DNAT_ADD_HTTPS);
		} else {
			// for proxy specified apps
			if (apps == null || apps.length <= 0)
				apps = AppManager.getProxyedApps(this);

			for (int i = 0; i < apps.length; i++) {
				if (apps[i].isProxyed()) {
					cmd.append((hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTP
							: CMD_IPTABLES_DNAT_ADD_HTTP).replace("-t nat",
							"-t nat -m owner --uid-owner " + apps[i].getUid()));
					cmd.append((hasRedirectSupport ? CMD_IPTABLES_REDIRECT_ADD_HTTPS
							: CMD_IPTABLES_DNAT_ADD_HTTPS).replace("-t nat",
							"-t nat -m owner --uid-owner " + apps[i].getUid()));
				}
			}
		}

		String iptables_rules = cmd.toString().replace("203.208.0.0", appMask);

		runRootCommand(iptables_rules);

		return true;

	}

	/** Called when the activity is first created. */
	public boolean handleCommand() {

		// try {
		// InetAddress addr = InetAddress.getByName("www.google.co.jp");
		// appHost = addr.getHostAddress();
		//
		// if (appHost.length() > 8) {
		// String[] ips = appHost.split("\\.");
		// if (ips.length == 4)
		// appHost = ips[0] + "." + ips[1] + ".0.0";
		// Log.d(TAG, appHost);
		// }
		//
		// } catch (Exception ignore) {
		// return false;
		// }

		if (isDNSBlocked) {
			appHost = settings.getString("appHost", "203.208.46.1");

			try {
				URL aURL = new URL("http://myhosts.sinaapp.com/apphost");
				HttpURLConnection conn = (HttpURLConnection) aURL
						.openConnection();
				conn.setReadTimeout(10 * 1000);
				conn.connect();
				InputStream is = conn.getInputStream();
				BufferedReader reader = new BufferedReader(
						new InputStreamReader(is));
				String line = reader.readLine();
				if (line == null)
					return false;
				if (!line.startsWith("#GAEPROXY"))
					return false;
				while (true) {
					line = reader.readLine();
					if (line == null)
						break;
					if (line.startsWith("#"))
						continue;
					line = line.trim().toLowerCase();
					if (line.equals(""))
						continue;
					if (!line.equals(appHost)) {
						File cache = new File(GAEProxyService.BASE
								+ "cache/dnscache");
						if (cache.exists())
							cache.delete();
					}
					appHost = line;
					break;
				}

				handler.sendEmptyMessage(MSG_HOST_CHANGE);

			} catch (Exception e) {
				Log.e(TAG, "cannot get remote host files", e);
			}
		} else {
			try {
				InetAddress addr = InetAddress
						.getByName("gaednsproxy.appspot.com");
				appHost = addr.getHostAddress();
			} catch (Exception ignore) {
				return false;
			}
		}

		try {
			if (appHost.length() > 8) {
				String[] ips = appHost.split("\\.");
				if (ips.length == 4)
					appMask = ips[0] + "." + ips[1] + ".0.0";
				Log.d(TAG, appMask);
			}

		} catch (Exception ignore) {
			return false;
		}

		// String host = proxy.trim().toLowerCase().split("/")[2];
		// if (host == null || host.equals(""))
		// return false;

		// Add hosts here
		// runRootCommand(BASE + "host.sh add " + appHost + " " + host);

		dnsServer = new DNSServer("DNS Server", 8153, "8.8.8.8", 53, appHost,
				isDNSBlocked);
		dnsServer.setBasePath(BASE);

		if (proxy.equals("https://proxyofmax.appspot.com/fetch.py")) {
			proxyType = "GoAgent";
			Random random = new Random(System.currentTimeMillis());
			int n = random.nextInt(20);
			if (n > 0)
				proxy = "https://proxyofmax" + n + ".appspot.com/fetch.py";
			Log.d(TAG, "Balance Proxy: " + proxy);
		}

		if (!preConnection())
			return false;

		Thread dnsThread = new Thread(dnsServer);
		dnsThread.setDaemon(true);
		dnsThread.start();

		connect();

		return true;
	}

	private void initSoundVibrateLights(Notification notification) {
		final String ringtone = settings.getString(
				"settings_key_notif_ringtone", null);
		AudioManager audioManager = (AudioManager) this
				.getSystemService(Context.AUDIO_SERVICE);
		if (audioManager.getStreamVolume(AudioManager.STREAM_RING) == 0) {
			notification.sound = null;
		} else if (ringtone != null)
			notification.sound = Uri.parse(ringtone);
		else
			notification.defaults |= Notification.DEFAULT_SOUND;

		if (settings.getBoolean("settings_key_notif_vibrate", false)) {
			long[] vibrate = { 0, 1000, 500, 1000, 500, 1000 };
			notification.vibrate = vibrate;
		}

		notification.defaults |= Notification.DEFAULT_LIGHTS;
	}

	private void notifyAlert(String title, String info) {
		notification.icon = R.drawable.stat;
		notification.tickerText = title;
		notification.flags = Notification.FLAG_ONGOING_EVENT;
		initSoundVibrateLights(notification);
		// notification.defaults = Notification.DEFAULT_SOUND;
		notification.setLatestEventInfo(this, getString(R.string.app_name),
				info, pendIntent);
		startForegroundCompat(1, notification);
	}

	private void notifyAlert(String title, String info, int flags) {
		notification.icon = R.drawable.stat;
		notification.tickerText = title;
		notification.flags = flags;
		initSoundVibrateLights(notification);
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
		intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
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

		FlurryAgent.onEndSession(this);

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
			AppWidgetManager awm = AppWidgetManager.getInstance(this);
			awm.updateAppWidget(awm.getAppWidgetIds(new ComponentName(this,
					GAEProxyWidgetProvider.class)), views);
		} catch (Exception ignore) {
			// Nothing
		}

		Editor ed = settings.edit();
		ed.putBoolean("isRunning", false);
		ed.putBoolean("isConnecting", false);
		ed.commit();

		try {
			notificationManager.cancel(0);
		} catch (Exception ignore) {
			// Nothing
		}

		// APNManager.clearAPNProxy("127.0.0.1", Integer.toString(port), this);

		super.onDestroy();
	}

	private void onDisconnect() {

		runRootCommand(BASE + "iptables -t nat -F OUTPUT");

		runCommand(BASE + "proxy.sh stop");

	}

	final Handler handler = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			Editor ed = settings.edit();
			switch (msg.what) {
			case MSG_CONNECT_START:
				ed.putBoolean("isConnecting", true);

				PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
				mWakeLock = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK
						| PowerManager.ON_AFTER_RELEASE, "GAEProxy");

				mWakeLock.acquire();

				break;
			case MSG_CONNECT_FINISH:
				ed.putBoolean("isConnecting", false);

				if (mWakeLock != null && mWakeLock.isHeld())
					mWakeLock.release();

				break;
			case MSG_CONNECT_SUCCESS:
				ed.putBoolean("isRunning", true);
				break;
			case MSG_CONNECT_FAIL:
				ed.putBoolean("isRunning", false);
				break;
			case MSG_HOST_CHANGE:
				ed.putString("appHost", appHost);
				break;
			case MSG_STOP_SELF:
				stopSelf();
				break;
			}
			ed.commit();
			super.handleMessage(msg);
		}
	};

	// This is the old onStart method that will be called on the pre-2.0
	// platform. On 2.0 or later we override onStartCommand() so this
	// method will not be called.
	@Override
	public void onStart(Intent intent, int startId) {

		super.onStart(intent, startId);

		Log.d(TAG, "Service Start");

		FlurryAgent.onStartSession(this, "46W95Q7YQQ6IY1NFIQW4");

		Bundle bundle = intent.getExtras();
		proxy = bundle.getString("proxy");
		proxyType = bundle.getString("proxyType");
		port = bundle.getInt("port");
		sitekey = bundle.getString("sitekey");
		isGlobalProxy = bundle.getBoolean("isGlobalProxy");
		isHTTPSProxy = bundle.getBoolean("isHTTPSProxy");
		isGFWList = bundle.getBoolean("isGFWList");

		Log.e(TAG, "GAE Proxy: " + proxy);
		Log.e(TAG, "Local Port: " + port);

		// APNManager.setAPNProxy("127.0.0.1", Integer.toString(port), this);

		new Thread(new Runnable() {
			public void run() {

				handler.sendEmptyMessage(MSG_CONNECT_START);

				int tries = 0;
				try {
					URL url = new URL("http://gae-ip-country.appspot.com/");
					HttpURLConnection conn = (HttpURLConnection) url
							.openConnection();
					conn.setConnectTimeout(5000);
					conn.setReadTimeout(8000);
					conn.connect();
					InputStream is = conn.getInputStream();
					BufferedReader input = new BufferedReader(
							new InputStreamReader(is));
					String code = input.readLine();
					if (code != null && code.length() > 0 && code.length() < 5) {
						Log.d(TAG, "Location: " + code);
						if (!code.contains("CN") && !code.contains("ZZ"))
							isDNSBlocked = false;
					}
				} catch (Exception e) {
					isDNSBlocked = true;
					Log.d(TAG, "Cannot get country info", e);
					// Nothing
				}
				tries++;

				// Test for Redirect Support
				initHasRedirectSupported();

				if (handleCommand()) {
					// Connection and forward successful
					notifyAlert(getString(R.string.forward_success),
							getString(R.string.service_running));

					handler.sendEmptyMessage(MSG_CONNECT_SUCCESS);

					// for widget, maybe exception here
					try {
						RemoteViews views = new RemoteViews(getPackageName(),
								R.layout.gaeproxy_appwidget);
						views.setImageViewResource(R.id.serviceToggle,
								R.drawable.on);
						AppWidgetManager awm = AppWidgetManager
								.getInstance(GAEProxyService.this);
						awm.updateAppWidget(awm
								.getAppWidgetIds(new ComponentName(
										GAEProxyService.this,
										GAEProxyWidgetProvider.class)), views);
					} catch (Exception ignore) {
						// Nothing
					}

				} else {
					// Connection or forward unsuccessful
					notifyAlert(getString(R.string.forward_fail),
							getString(R.string.service_failed));

					stopSelf();
					handler.sendEmptyMessage(MSG_CONNECT_FAIL);
				}

				handler.sendEmptyMessage(MSG_CONNECT_FINISH);

			}
		}).start();
	}

}
