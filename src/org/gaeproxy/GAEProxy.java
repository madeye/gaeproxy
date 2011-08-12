/* gaeproxy - GoAgent / WallProxy client App for Android
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

import java.io.BufferedInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.flurry.android.FlurryAgent;
import com.google.ads.AdRequest;
import com.google.ads.AdSize;
import com.google.ads.AdView;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.app.AlertDialog;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.preference.CheckBoxPreference;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.LinearLayout;
import android.widget.RemoteViews;
import android.widget.Toast;

public class GAEProxy extends PreferenceActivity implements
		OnSharedPreferenceChangeListener {

	class DownloadFileRunnable implements Runnable {

		private String[] path;

		public DownloadFileRunnable(String... path) {
			this.path = path;
			notification.contentView.setProgressBar(R.id.pb, 100, 0, false);
			nm.notify(notification_id, notification);
		}

		private int progress_count = 0;

		protected void publishProgress(String progress) {
			Log.d("ANDRO_ASYNC", progress);
			int now = Integer.parseInt(progress);
			if (now - progress_count > 5) {
				notification.contentView.setProgressBar(R.id.pb, 100,
						Integer.parseInt(progress), false);
				nm.notify(notification_id, notification);
				progress_count = now;
			}
		}

		public void unzip(String file, String path) {
			dirChecker(path);
			try {
				FileInputStream fin = new FileInputStream(file);
				ZipInputStream zin = new ZipInputStream(fin);
				ZipEntry ze = null;
				while ((ze = zin.getNextEntry()) != null) {
					if (ze.getName().contains("__MACOSX"))
						continue;
					Log.v("Decompress", "Unzipping " + ze.getName());
					if (ze.isDirectory()) {
						dirChecker(path + ze.getName());
					} else {
						FileOutputStream fout = new FileOutputStream(path
								+ ze.getName());
						byte data[] = new byte[2048];
						int count;
						while ((count = zin.read(data)) != -1) {
							fout.write(data, 0, count);
						}
						zin.closeEntry();
						fout.close();
					}

				}
				zin.close();
			} catch (Exception e) {
				Log.e("Decompress", "unzip", e);
			}

		}

		@Override
		public void run() {
			int count;

			handler.sendEmptyMessage(MSG_INSTALL_START);
			PowerManager.WakeLock mWakeLock;
			PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
			mWakeLock = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK
					| PowerManager.ON_AFTER_RELEASE, "GAEProxy");

			mWakeLock.acquire();

			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(
					"www.google.com.hk", 80));

			try {

				File zip = new File(path[1]);
				URL url = new URL(path[0]);
				URLConnection conexion = url.openConnection(proxy);
				conexion.connect();
				int lenghtOfFile = conexion.getContentLength();

				if (!zip.exists() || lenghtOfFile != zip.length()) {

					Log.d("ANDRO_ASYNC", "Lenght of file: " + lenghtOfFile);

					InputStream input = new BufferedInputStream(
							url.openStream());
					OutputStream output = new FileOutputStream(path[1]);

					byte data[] = new byte[1024];

					long total = 0;

					while ((count = input.read(data)) != -1) {
						total += count;
						publishProgress(""
								+ (int) ((total * 50) / lenghtOfFile));
						output.write(data, 0, count);
					}

					output.flush();
					output.close();
					input.close();
				} else {
					publishProgress("" + 50);
				}

				// Unzip now
				unzip(path[1], path[2]);

				// Unzip another file
				zip = new File(path[4]);

				url = new URL(path[3]);
				conexion = url.openConnection(proxy);
				conexion.connect();

				lenghtOfFile = conexion.getContentLength();

				if (!zip.exists() || zip.length() != lenghtOfFile) {

					Log.d("ANDRO_ASYNC", "Lenght of file: " + lenghtOfFile);

					InputStream input = new BufferedInputStream(
							url.openStream());
					OutputStream output = new FileOutputStream(path[4]);

					byte data[] = new byte[1024];

					long total = 0;

					while ((count = input.read(data)) != -1) {
						total += count;
						publishProgress(""
								+ (int) (50 + (total * 50) / lenghtOfFile));
						output.write(data, 0, count);
					}

					output.flush();
					output.close();
					input.close();
				} else {
					publishProgress("" + 100);
				}

				// Unzip File
				unzip(path[4], path[5]);
				handler.sendEmptyMessage(MSG_INSTALL_SUCCESS);

			} catch (Exception e) {
				handler.sendEmptyMessage(MSG_INSTALL_FAIL);
				Log.e("error", e.getMessage().toString());
			}

			if (mWakeLock.isHeld())
				mWakeLock.release();

			nm.cancel(notification_id);
		}

	}

	private static final String TAG = "GAEProxy";
	public static final String PREFS_NAME = "GAEProxy";
	private static final String SERVICE_NAME = "org.gaeproxy.GAEProxyService";

	private String proxy;
	private int port;
	private String sitekey = "";
	private String proxyType = "GoAgent";
	private boolean isGlobalProxy = false;
	private boolean isHTTPSProxy = false;
	private boolean isGFWList = false;

	// Notification Progress Bar
	int notification_id = 19172439;
	NotificationManager nm;
	Notification notification;

	private static final int MSG_INSTALL_START = 0;
	private static final int MSG_INSTALL_SUCCESS = 1;
	private static final int MSG_INSTALL_FAIL = 2;
	private static final int MSG_CRASH_RECOVER = 3;

	final Handler handler = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			SharedPreferences settings = PreferenceManager
					.getDefaultSharedPreferences(GAEProxy.this);
			Editor ed = settings.edit();
			switch (msg.what) {
			case MSG_INSTALL_START:
				ed.putBoolean("isInstalled", false);
				break;
			case MSG_INSTALL_SUCCESS:
				ed.putBoolean("isInstalling", false);
				ed.putBoolean("isInstalled", true);
				break;
			case MSG_INSTALL_FAIL:
				ed.putBoolean("isInstalling", false);
				ed.putBoolean("isInstalled", false);
				break;
			case MSG_CRASH_RECOVER:
				Toast.makeText(GAEProxy.this, R.string.crash_alert,
						Toast.LENGTH_LONG).show();
				break;
			}
			ed.commit();
			super.handleMessage(msg);
		}
	};

	private ProgressDialog pd = null;

	public static boolean isRoot = false;

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

	public static boolean runCommand(String command) {
		Process process = null;
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor();
		} catch (Exception e) {
			Log.e(TAG, e.getMessage());
			return false;
		} finally {
			try {
				process.destroy();
			} catch (Exception e) {
				// nothing
			}
		}
		return true;
	}

	private CheckBoxPreference isAutoConnectCheck;
	private CheckBoxPreference isGlobalProxyCheck;
	private Preference proxyedApps;
	private CheckBoxPreference isInstalledCheck;
	private EditTextPreference proxyText;
	private EditTextPreference portText;
	private EditTextPreference sitekeyText;
	private ListPreference proxyTypeList;
	private CheckBoxPreference isHTTPSProxyCheck;
	private CheckBoxPreference isGFWListCheck;

	private CheckBoxPreference isRunningCheck;

	private void CopyAssets(String path) {

		AssetManager assetManager = getAssets();
		String[] files = null;
		try {
			files = assetManager.list(path);
		} catch (IOException e) {
			Log.e(TAG, e.getMessage());
		}
		for (int i = 0; i < files.length; i++) {
			InputStream in = null;
			OutputStream out = null;
			try {
				// if (!(new File("/data/data/org.gaeproxy/" +
				// files[i])).exists()) {
				if (files[i].equals("hosts")
						&& (new File("/data/data/org.gaeproxy/" + files[i]))
								.exists())
					continue;
				in = assetManager.open(files[i]);
				out = new FileOutputStream("/data/data/org.gaeproxy/"
						+ files[i]);
				copyFile(in, out);
				in.close();
				in = null;
				out.flush();
				out.close();
				out = null;
				// }
			} catch (Exception e) {
				Log.e(TAG, e.getMessage());
			}
		}
	}

	private void copyFile(InputStream in, OutputStream out) throws IOException {
		byte[] buffer = new byte[1024];
		int read;
		while ((read = in.read(buffer)) != -1) {
			out.write(buffer, 0, read);
		}
	}

	private void disableAll() {
		proxyText.setEnabled(false);
		portText.setEnabled(false);
		sitekeyText.setEnabled(false);
		proxyedApps.setEnabled(false);
		isGFWListCheck.setEnabled(false);

		isAutoConnectCheck.setEnabled(false);
		isGlobalProxyCheck.setEnabled(false);
		isHTTPSProxyCheck.setEnabled(false);
		isInstalledCheck.setEnabled(false);
		proxyTypeList.setEnabled(false);
	}

	private void enableAll() {
		proxyText.setEnabled(true);
		portText.setEnabled(true);
		if (proxyTypeList.getValue().equals("WallProxy")
				|| proxyTypeList.getValue().equals("GoAgent"))
			sitekeyText.setEnabled(true);
		if (!isGFWListCheck.isChecked()) {
			isGlobalProxyCheck.setEnabled(true);
			if (!isGlobalProxyCheck.isChecked())
				proxyedApps.setEnabled(true);
		}

		isAutoConnectCheck.setEnabled(true);
		isGFWListCheck.setEnabled(true);
		isHTTPSProxyCheck.setEnabled(true);
		isInstalledCheck.setEnabled(true);
		proxyTypeList.setEnabled(true);
	}

	private void dirChecker(String dir) {
		File f = new File(dir);

		if (!f.isDirectory()) {
			f.mkdirs();
		}
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if (keyCode == KeyEvent.KEYCODE_BACK && event.getRepeatCount() == 0) { // 按下的如果是BACK，同时没有重复
			try {
				finish();
			} catch (Exception ignore) {
				// Nothing
			}
			return true;
		}
		return super.onKeyDown(keyCode, event);
	}

	private boolean install() {

		if (!Environment.MEDIA_MOUNTED.equals(Environment
				.getExternalStorageState()))
			return false;

		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);
		if (settings.getBoolean("isInstalling", false))
			return false;

		Editor ed = settings.edit();
		ed.putBoolean("isInstalling", true);
		ed.commit();

		DownloadFileRunnable progress = new DownloadFileRunnable(
				"http://gaeproxy.googlecode.com/files/python_r2.zip",
				"/sdcard/python.zip", "/data/data/org.gaeproxy/",
				"http://gaeproxy.googlecode.com/files/python-extras_r2.zip",
				"/sdcard/python-extras.zip", "/sdcard/");
		new Thread(progress).start();
		showAToast(getString(R.string.downloading));
		return true;
	}

	private boolean isTextEmpty(String s, String msg) {
		if (s == null || s.length() <= 0) {
			showAToast(msg);
			return true;
		}
		return false;
	}

	public boolean isWorked(String service) {
		ActivityManager myManager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
		ArrayList<RunningServiceInfo> runningService = (ArrayList<RunningServiceInfo>) myManager
				.getRunningServices(30);
		for (int i = 0; i < runningService.size(); i++) {
			if (runningService.get(i).service.getClassName().toString()
					.equals(service)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void onStart() {
		super.onStart();
		FlurryAgent.onStartSession(this, "46W95Q7YQQ6IY1NFIQW4");
	}

	@Override
	public void onStop() {
		super.onStop();
		FlurryAgent.onEndSession(this);
	}

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.main);
		addPreferencesFromResource(R.xml.gae_proxy_preference);
		// Create the adView
		AdView adView = new AdView(this, AdSize.BANNER, "a14d8be8a284afc");
		// Lookup your LinearLayout assuming it’s been given
		// the attribute android:id="@+id/mainLayout"
		LinearLayout layout = (LinearLayout) findViewById(R.id.ad);
		// Add the adView to it
		layout.addView(adView);
		// Initiate a generic request to load it with an ad
		AdRequest aq = new AdRequest();
		// aq.setTesting(true);
		adView.loadAd(aq);

		nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
		notification = new Notification(R.drawable.icon,
				getString(R.string.download), System.currentTimeMillis());
		notification.contentView = new RemoteViews(getPackageName(),
				R.layout.layout_progress_bar);
		// 使用notification.xml文件作VIEW
		notification.contentView.setProgressBar(R.id.pb, 100, 0, false);
		// 设置进度条，最大值 为100,当前值为0，最后一个参数为true时显示条纹
		// （就是在Android Market下载软件，点击下载但还没获取到目标大小时的状态）
		Intent notificationIntent = new Intent(this, GAEProxy.class);
		PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
				notificationIntent, 0);
		notification.contentIntent = contentIntent;

		proxyText = (EditTextPreference) findPreference("proxy");
		portText = (EditTextPreference) findPreference("port");
		sitekeyText = (EditTextPreference) findPreference("sitekey");
		proxyedApps = (Preference) findPreference("proxyedApps");

		isRunningCheck = (CheckBoxPreference) findPreference("isRunning");
		isAutoConnectCheck = (CheckBoxPreference) findPreference("isAutoConnect");
		isHTTPSProxyCheck = (CheckBoxPreference) findPreference("isHTTPSProxy");
		isGlobalProxyCheck = (CheckBoxPreference) findPreference("isGlobalProxy");
		isInstalledCheck = (CheckBoxPreference) findPreference("isInstalled");
		proxyTypeList = (ListPreference) findPreference("proxyType");
		isGFWListCheck = (CheckBoxPreference) findPreference("isGFWList");

		final CheckBoxPreference isRunningCheck = (CheckBoxPreference) findPreference("isRunning");

		if (!runRootCommand("")) {
			isRoot = false;
		} else {
			isRoot = true;
		}

		new Thread() {
			public void run() {

				if (!isWorked(SERVICE_NAME)) {
					CopyAssets("");

					runCommand("chmod 777 /data/data/org.gaeproxy/iptables");
					runCommand("chmod 777 /data/data/org.gaeproxy/redsocks");
					runCommand("chmod 777 /data/data/org.gaeproxy/proxy.sh");
					runCommand("chmod 777 /data/data/org.gaeproxy/proxy_socks.sh");
					runCommand("chmod 777 /data/data/org.gaeproxy/localproxy.sh");
					runCommand("chmod 777 /data/data/org.gaeproxy/localproxy_en.sh");
				}

				try {
					URL aURL = new URL("http://myhosts.sinaapp.com/hosts");
					InputStream input = new BufferedInputStream(
							aURL.openStream());
					OutputStream output = new FileOutputStream(
							"/data/data/org.gaeproxy/hosts");

					byte data[] = new byte[1024];

					int count = 0;

					while ((count = input.read(data)) != -1) {
						output.write(data, 0, count);
					}

					output.flush();
					output.close();
					input.close();
				} catch (Exception e) {
					// Nothing
				}
			}
		}.start();
	}

	/** Called when the activity is closed. */
	@Override
	public void onDestroy() {
		SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);

		SharedPreferences.Editor editor = settings.edit();
		editor.putBoolean("isConnected", isWorked(SERVICE_NAME));

		editor.commit();
		super.onDestroy();
	}

	@Override
	protected void onPause() {
		super.onPause();

		// Unregister the listener whenever a key changes
		getPreferenceScreen().getSharedPreferences()
				.unregisterOnSharedPreferenceChangeListener(this);
	}

	@Override
	public boolean onPreferenceTreeClick(PreferenceScreen preferenceScreen,
			Preference preference) {
		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		if (preference.getKey() != null
				&& preference.getKey().equals("proxyedApps")) {
			Intent intent = new Intent(this, AppManager.class);
			startActivity(intent);
		} else if (preference.getKey() != null
				&& preference.getKey().equals("isInstalled")) {
			if (settings.getBoolean("isInstalled", false)) {
				if (install()) {
				} else {
					showAToast(getString(R.string.sdcard_alert));
					Editor ed = settings.edit();
					ed.putBoolean("isInstalled", false);
					ed.commit();
				}
			} else {
				uninstall();
			}
		} else if (preference.getKey() != null
				&& preference.getKey().equals("isRunning")) {
			if (!settings.getBoolean("isInstalled", false)) {
				showAToast(getString(R.string.install_alert));
				Editor edit = settings.edit();
				edit.putBoolean("isRunning", false);
				edit.commit();
				return false;
			}
			if (!serviceStart()) {
				Editor edit = settings.edit();
				edit.putBoolean("isRunning", false);
				edit.commit();
			}
		}
		return super.onPreferenceTreeClick(preferenceScreen, preference);
	}

	@Override
	protected void onResume() {
		super.onResume();
		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		if (settings.getBoolean("isGFWList", false)) {
			isGlobalProxyCheck.setEnabled(false);
			proxyedApps.setEnabled(false);
		} else {
			isGlobalProxyCheck.setEnabled(true);
			if (settings.getBoolean("isGlobalProxy", false))
				proxyedApps.setEnabled(false);
			else
				proxyedApps.setEnabled(true);
		}

		if (proxyTypeList.getValue().equals("WallProxy")
				|| proxyTypeList.getValue().equals("GoAgent"))
			sitekeyText.setEnabled(true);
		else
			sitekeyText.setEnabled(false);

		Editor edit = settings.edit();

		if (this.isWorked(SERVICE_NAME)) {
			edit.putBoolean("isRunning", true);
		} else {
			if (settings.getBoolean("isRunning", false)) {
				new Thread() {
					public void run() {
						handler.sendEmptyMessage(MSG_CRASH_RECOVER);
						recovery();
					}
				}.start();
			}
			edit.putBoolean("isRunning", false);
		}

		edit.commit();

		if (settings.getBoolean("isRunning", false)) {
			isRunningCheck.setChecked(true);
			disableAll();
		} else {
			if (settings.getBoolean("isInstalling", false)) {
				disableAll();
			} else {
				enableAll();
			}
			isRunningCheck.setChecked(false);
		}

		// Setup the initial values

		if (!settings.getString("sitekey", "").equals(""))
			sitekeyText.setSummary(settings.getString("sitekey", ""));

		if (!settings.getString("proxyType", "").equals(""))
			proxyTypeList.setSummary(settings.getString("proxyType", ""));

		if (!settings.getString("port", "").equals(""))
			portText.setSummary(settings.getString("port",
					getString(R.string.port_summary)));

		if (!settings.getString("proxy", "").equals(""))
			proxyText.setSummary(settings.getString("proxy",
					getString(R.string.proxy_summary)));

		// Set up a listener whenever a key changes
		getPreferenceScreen().getSharedPreferences()
				.registerOnSharedPreferenceChangeListener(this);
	}

	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {
		// Let's do something a preference value changes
		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		if (key.equals("isConnecting")) {
			if (settings.getBoolean("isConnecting", false)) {
				Log.d(TAG, "Connecting start");
				pd = ProgressDialog.show(this, "",
						getString(R.string.connecting), true, false);
			} else {
				Log.d(TAG, "Connecting finish");
				if (pd != null) {
					pd.dismiss();
					pd = null;
				}
			}
		}

		if (key.equals("isMarketEnable")) {
			if (settings.getBoolean("isMarketEnable", false)) {
				TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
				String countryCode = tm.getSimCountryIso();

				try {
					Log.d(TAG, "Location: " + countryCode);
					if (countryCode.toLowerCase().equals("cn")) {
						String command = "setprop gsm.sim.operator.numeric 31026\n"
								+ "setprop gsm.operator.numeric 31026\n"
								+ "setprop gsm.sim.operator.iso-country us\n"
								+ "setprop gsm.operator.iso-country us\n"
								+ "chmod 777 /data/data/com.android.vending/shared_prefs\n"
								+ "chmod 666 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "setpref com.android.vending vending_preferences boolean metadata_paid_apps_enabled true\n"
								+ "chmod 660 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "chmod 771 /data/data/com.android.vending/shared_prefs\n"
								+ "setown com.android.vending /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "kill $(ps | grep vending | tr -s  ' ' | cut -d ' ' -f2)\n"
								+ "rm -rf /data/data/com.android.vending/cache/*\n";
						runRootCommand(command);
					}
				} catch (Exception e) {
					// Nothing
				}
			}
		}

		if (key.equals("isInstalled")) {
			if (settings.getBoolean("isInstalled", false))
				isInstalledCheck.setChecked(true);
			else
				isInstalledCheck.setChecked(false);
		}

		if (key.equals("isGFWList")) {
			if (settings.getBoolean("isGFWList", false)) {
				isGlobalProxyCheck.setEnabled(false);
				proxyedApps.setEnabled(false);
			} else {
				isGlobalProxyCheck.setEnabled(true);
				if (settings.getBoolean("isGlobalProxy", false))
					proxyedApps.setEnabled(false);
				else
					proxyedApps.setEnabled(true);
			}
		}

		if (key.equals("isGlobalProxy")) {
			if (!settings.getBoolean("isGFWList", false)) {
				if (settings.getBoolean("isGlobalProxy", false))
					proxyedApps.setEnabled(false);
				else
					proxyedApps.setEnabled(true);
			}
		}

		if (key.equals("isRunning")) {
			if (settings.getBoolean("isRunning", false)) {
				disableAll();
				isRunningCheck.setChecked(true);
			} else {
				if (settings.getBoolean("isInstalling", false)) {
					disableAll();
				} else {
					enableAll();
				}
				isRunningCheck.setChecked(false);
			}
		}

		if (key.equals("isInstalling")) {
			if (settings.getBoolean("isInstalling", false)) {
				disableAll();
			} else {
				enableAll();
			}
		}

		if (key.equals("proxyType")) {
			proxyTypeList.setSummary(settings.getString("proxyType", ""));
			if (settings.getString("proxyType", "").equals("WallProxy")
					|| settings.getString("proxyType", "").equals("GoAgent"))
				sitekeyText.setEnabled(true);
			else
				sitekeyText.setEnabled(false);
		} else if (key.equals("port"))
			if (settings.getString("port", "").equals(""))
				portText.setSummary(getString(R.string.port_summary));
			else
				portText.setSummary(settings.getString("port", ""));
		else if (key.equals("sitekey"))
			if (settings.getString("sitekey", "").equals(""))
				sitekeyText.setSummary(getString(R.string.sitekey_summary));
			else
				sitekeyText.setSummary(settings.getString("sitekey", ""));
		else if (key.equals("proxy"))
			if (settings.getString("proxy", "").equals("")) {
				proxyText.setSummary(getString(R.string.proxy_summary));
			} else {
				String host = settings.getString("proxy", "");
				Editor ed = settings.edit();
				if (!host.startsWith("https://")) {
					ed.putString("proxy", "https://" + host);
				}
				ed.commit();
				proxyText.setSummary(settings.getString("proxy", ""));
			}
	}

	/**
	 * Called when connect button is clicked.
	 * 
	 * @throws Exception
	 */
	public boolean serviceStart() {

		if (isWorked(SERVICE_NAME)) {
			try {
				stopService(new Intent(this, GAEProxyService.class));
			} catch (Exception e) {
				// Nothing
			}
			return false;
		}

		runCommand("chmod 777 /data/data/org.gaeproxy/python/bin/python");

		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		proxyType = settings.getString("proxyType", "GoAgent");

		proxy = settings.getString("proxy", "");
		if (isTextEmpty(proxy, getString(R.string.proxy_empty)))
			return false;

		if (!proxy.startsWith("https://")) {
			showAToast(getString(R.string.https_alert));
			return false;
		}

		String portText = settings.getString("port", "");
		if (isTextEmpty(portText, getString(R.string.port_empty)))
			return false;
		try {
			port = Integer.valueOf(portText);
			if (port <= 1024) {
				this.showAToast(getString(R.string.port_alert));
				return false;
			}
		} catch (Exception e) {
			this.showAToast(getString(R.string.port_alert));
			return false;
		}

		sitekey = settings.getString("sitekey", "");

		isGlobalProxy = settings.getBoolean("isGlobalProxy", false);
		isHTTPSProxy = settings.getBoolean("isHTTPSProxy", false);
		isGFWList = settings.getBoolean("isGFWList", false);

		try {

			Intent it = new Intent(this, GAEProxyService.class);
			Bundle bundle = new Bundle();
			bundle.putString("proxy", proxy);
			bundle.putInt("port", port);
			bundle.putString("sitekey", sitekey);
			bundle.putBoolean("isGlobalProxy", isGlobalProxy);
			bundle.putBoolean("isHTTPSProxy", isHTTPSProxy);
			bundle.putString("proxyType", proxyType);
			bundle.putBoolean("isGFWList", isGFWList);

			it.putExtras(bundle);
			startService(it);
		} catch (Exception e) {
			// Nothing
			return false;
		}

		return true;
	}

	private void showAToast(String msg) {
		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setMessage(msg)
				.setCancelable(false)
				.setNegativeButton(getString(R.string.ok_iknow),
						new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int id) {
								dialog.cancel();
							}
						});
		AlertDialog alert = builder.create();
		alert.show();
	}

	private void uninstall() {
		File f = new File("/sdcard/python.zip");
		if (f.exists())
			f.delete();
		f = new File("/sdcard/python-extras.zip");
		if (f.exists())
			f.delete();
	}

	// 点击Menu时，系统调用当前Activity的onCreateOptionsMenu方法，并传一个实现了一个Menu接口的menu对象供你使用
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		/*
		 * add()方法的四个参数，依次是： 1、组别，如果不分组的话就写Menu.NONE,
		 * 2、Id，这个很重要，Android根据这个Id来确定不同的菜单 3、顺序，那个菜单现在在前面由这个参数的大小决定
		 * 4、文本，菜单的显示文本
		 */
		menu.add(Menu.NONE, Menu.FIRST + 1, 1, getString(R.string.recovery))
				.setIcon(android.R.drawable.ic_menu_delete);
		menu.add(Menu.NONE, Menu.FIRST + 2, 2, getString(R.string.about))
				.setIcon(android.R.drawable.ic_menu_info_details);
		// return true才会起作用
		return true;

	}

	// 菜单项被选择事件
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case Menu.FIRST + 1:
			recovery();
			break;
		case Menu.FIRST + 2:
			showAToast(getString(R.string.copy_rights));
			break;
		}

		return true;
	}

	private void recovery() {
		try {
			stopService(new Intent(this, GAEProxyService.class));
		} catch (Exception e) {
			// Nothing
		}

		runRootCommand(GAEProxyService.BASE + "iptables -t nat -F OUTPUT");

		runRootCommand(GAEProxyService.BASE + "proxy.sh stop");

		File cache = new File(GAEProxyService.BASE + "cache/dnscache");
		if (cache.exists())
			cache.delete();

		CopyAssets("");

		runCommand("chmod 777 /data/data/org.gaeproxy/iptables");
		runCommand("chmod 777 /data/data/org.gaeproxy/redsocks");
		runCommand("chmod 777 /data/data/org.gaeproxy/proxy.sh");
		runCommand("chmod 777 /data/data/org.gaeproxy/proxy_socks.sh");
		runCommand("chmod 777 /data/data/org.gaeproxy/localproxy.sh");
		runCommand("chmod 777 /data/data/org.gaeproxy/localproxy_en.sh");

		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		Editor ed = settings.edit();
		ed.putBoolean("isInstalling", false);
		ed.putBoolean("isRunning", false);
		ed.commit();
	}

}