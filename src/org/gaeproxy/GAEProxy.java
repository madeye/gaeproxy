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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.gaeproxy.db.DNSResponse;
import org.gaeproxy.db.DatabaseHelper;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.res.AssetManager;
import android.os.Bundle;
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
import android.text.SpannableString;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.ads.AdRequest;
import com.google.ads.AdSize;
import com.google.ads.AdView;
import com.google.analytics.tracking.android.EasyTracker;
import com.j256.ormlite.android.apptools.OpenHelperManager;
import com.j256.ormlite.dao.Dao;

public class GAEProxy extends PreferenceActivity implements
		OnSharedPreferenceChangeListener {

	private static final String TAG = "GAEProxy";

	public static final String PREFS_NAME = "GAEProxy";
	private String proxy;

	private int port;
	private String sitekey = "";
	private String proxyType = "GoAgent";
	private boolean isGlobalProxy = false;
	private boolean isHTTPSProxy = false;
	private boolean isGFWList = false;

	private static final int MSG_CRASH_RECOVER = 1;
	private static final int MSG_INITIAL_FINISH = 2;

	final Handler handler = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			SharedPreferences settings = PreferenceManager
					.getDefaultSharedPreferences(GAEProxy.this);
			Editor ed = settings.edit();
			switch (msg.what) {
			case MSG_CRASH_RECOVER:
				Toast.makeText(GAEProxy.this, R.string.crash_alert,
						Toast.LENGTH_LONG).show();
				ed.putBoolean("isRunning", false);
				break;
			case MSG_INITIAL_FINISH:
				if (pd != null) {
					pd.dismiss();
					pd = null;
				}
				break;
			}
			ed.commit();
			super.handleMessage(msg);
		}
	};

	private static ProgressDialog pd = null;

	private CheckBoxPreference isAutoConnectCheck;

	private CheckBoxPreference isGlobalProxyCheck;
	private EditTextPreference proxyText;
	private EditTextPreference portText;
	private EditTextPreference sitekeyText;
	private CheckBoxPreference isHTTPSProxyCheck;
	private CheckBoxPreference isGFWListCheck;
	private CheckBoxPreference isRunningCheck;
	private AdView adView;
	private Preference proxyedApps;

	private Preference browser;

	private void copyAssets(String path) {

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
				in = assetManager.open(files[i]);
				out = new FileOutputStream("/data/data/org.gaeproxy/"
						+ files[i]);
				copyFile(in, out);
				in.close();
				in = null;
				out.flush();
				out.close();
				out = null;
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

	private void crash_recovery() {

		Utils.runRootCommand(Utils.getIptables() + " -t nat -F OUTPUT");

		Utils.runCommand(GAEProxyService.BASE + "proxy.sh stop");

	}

	private void dirChecker(String dir) {
		File f = new File(dir);

		if (!f.isDirectory()) {
			f.mkdirs();
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
	}

	private void enableAll() {
		proxyText.setEnabled(true);
		portText.setEnabled(true);
		sitekeyText.setEnabled(true);
		if (!isGlobalProxyCheck.isChecked())
			proxyedApps.setEnabled(true);

		isGlobalProxyCheck.setEnabled(true);
		isAutoConnectCheck.setEnabled(true);
		isGFWListCheck.setEnabled(true);
		isHTTPSProxyCheck.setEnabled(true);
	}

	private boolean install() {

		PowerManager.WakeLock mWakeLock;
		PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
		mWakeLock = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK
				| PowerManager.ON_AFTER_RELEASE, "GAEProxy");

		String data_path = Utils.getDataPath(this);

		try {
			final InputStream pythonZip = getAssets()
					.open("modules/python.mp3");
			final InputStream extraZip = getAssets().open(
					"modules/python-extras.mp3");

			unzip(pythonZip, "/data/data/org.gaeproxy/");
			unzip(extraZip, data_path + "/");
		} catch (IOException e) {
			Log.e(TAG, "unable to install python");
		}
		if (mWakeLock.isHeld())
			mWakeLock.release();

		return true;
	}

	private boolean isTextEmpty(String s, String msg) {
		if (s == null || s.length() <= 0) {
			showAToast(msg);
			return true;
		}
		return false;
	}

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.main);
		addPreferencesFromResource(R.xml.gae_proxy_preference);

		// Create the adView
		adView = new AdView(GAEProxy.this, AdSize.BANNER, "a14d8be8a284afc");
		// Lookup your LinearLayout assuming it’s been given
		// the attribute android:id="@+id/mainLayout"
		FrameLayout layout = (FrameLayout) findViewById(R.id.ad);
		// Add the adView to it
		layout.addView(adView);
		// Initiate a generic request to load it with an ad
		AdRequest aq = new AdRequest();
		// aq.setTesting(true);
		adView.loadAd(aq);

		proxyText = (EditTextPreference) findPreference("proxy");
		portText = (EditTextPreference) findPreference("port");
		sitekeyText = (EditTextPreference) findPreference("sitekey");
		proxyedApps = findPreference("proxyedApps");
		browser = findPreference("browser");

		isRunningCheck = (CheckBoxPreference) findPreference("isRunning");
		isAutoConnectCheck = (CheckBoxPreference) findPreference("isAutoConnect");
		isHTTPSProxyCheck = (CheckBoxPreference) findPreference("isHTTPSProxy");
		isGlobalProxyCheck = (CheckBoxPreference) findPreference("isGlobalProxy");
		isGFWListCheck = (CheckBoxPreference) findPreference("isGFWList");

		if (pd == null)
			pd = ProgressDialog.show(this, "",
					getString(R.string.initializing), true, true);

		final SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		new Thread() {
			@Override
			public void run() {

				Utils.isRoot();

				String versionName;
				try {
					versionName = getPackageManager().getPackageInfo(
							getPackageName(), 0).versionName;
				} catch (NameNotFoundException e) {
					versionName = "NONE";
				}

				if (!settings.getBoolean(versionName, false)) {

					Editor edit = settings.edit();
					edit.putBoolean(versionName, true);
					edit.commit();

					File f = new File("/data/data/org.gaeproxy/certs");
					if (f.exists() && f.isFile())
						f.delete();
					if (!f.exists())
						f.mkdir();

					File hosts = new File("/data/data/org.gaeproxy/hosts");

					if (hosts.exists())
						hosts.delete();

					copyAssets("");

					Utils.runCommand("chmod 755 /data/data/org.gaeproxy/iptables\n"
							+ "chmod 755 /data/data/org.gaeproxy/redsocks\n"
							+ "chmod 755 /data/data/org.gaeproxy/stunnel\n"
							+ "chmod 755 /data/data/org.gaeproxy/proxy.sh\n"
							+ "chmod 755 /data/data/org.gaeproxy/localproxy.sh\n"
							+ "chmod 755 /data/data/org.gaeproxy/localproxy_en.sh\n"
							+ "chmod 755 /data/data/org.gaeproxy/python-cl\n");

					install();

				}

				if (!(new File(Utils.getDataPath(GAEProxy.this)
						+ "/python-extras")).exists()) {
					install();
				}

				if (!Utils.isInitialized()
						&& !GAEProxyService.isServiceStarted()) {

					try {
						URL aURL = new URL("http://myhosts.sinaapp.com/hosts");
						HttpURLConnection conn = (HttpURLConnection) aURL
								.openConnection();
						conn.setConnectTimeout(3 * 1000);
						conn.setReadTimeout(6 * 1000);
						conn.connect();
						InputStream input = new BufferedInputStream(
								conn.getInputStream());
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

				handler.sendEmptyMessage(MSG_INITIAL_FINISH);
			}
		}.start();
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

	/** Called when the activity is closed. */
	@Override
	public void onDestroy() {
		SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);

		SharedPreferences.Editor editor = settings.edit();
		editor.putBoolean("isConnected", GAEProxyService.isServiceStarted());
		editor.commit();

		if (pd != null) {
			pd.dismiss();
			pd = null;
		}

		adView.destroy();

		super.onDestroy();
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

	// 菜单项被选择事件
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case Menu.FIRST + 1:
			recovery();
			break;
		case Menu.FIRST + 2:
			String versionName = "";
			try {
				versionName = getPackageManager().getPackageInfo(
						getPackageName(), 0).versionName;
			} catch (NameNotFoundException e) {
				versionName = "";
			}
			showAToast(getString(R.string.about) + " (" + versionName + ")\n\n"
					+ getString(R.string.copy_rights));
			break;
		}

		return true;
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
				&& preference.getKey().equals("browser")) {
			Intent intent = new Intent(this,
					org.gaeproxy.zirco.ui.activities.MainActivity.class);
			startActivity(intent);
		} else if (preference.getKey() != null
				&& preference.getKey().equals("isRunning")) {
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

		if (settings.getBoolean("isGlobalProxy", false))
			proxyedApps.setEnabled(false);
		else
			proxyedApps.setEnabled(true);

		sitekeyText.setEnabled(true);

		Editor edit = settings.edit();

		if (GAEProxyService.isServiceStarted()) {
			edit.putBoolean("isRunning", true);
		} else {
			if (settings.getBoolean("isRunning", false)) {
				new Thread() {
					@Override
					public void run() {
						crash_recovery();
						handler.sendEmptyMessage(MSG_CRASH_RECOVER);
					}
				}.start();
			}
			edit.putBoolean("isRunning", false);
		}

		edit.commit();

		if (settings.getBoolean("isRunning", false)) {
			isRunningCheck.setChecked(true);
			disableAll();
			browser.setEnabled(true);
		} else {
			browser.setEnabled(false);
			isRunningCheck.setChecked(false);
			enableAll();
		}

		// Setup the initial values

		if (!settings.getString("sitekey", "").equals(""))
			sitekeyText.setSummary(settings.getString("sitekey", ""));

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
				if (pd == null)
					pd = ProgressDialog.show(this, "",
							getString(R.string.connecting), true, true);
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
								+ "chmod 755 /data/data/com.android.vending/shared_prefs\n"
								+ "chmod 666 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "setpref com.android.vending vending_preferences boolean metadata_paid_apps_enabled true\n"
								+ "chmod 660 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "chmod 771 /data/data/com.android.vending/shared_prefs\n"
								+ "setown com.android.vending /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
								+ "kill $(ps | grep vending | tr -s  ' ' | cut -d ' ' -f2)\n"
								+ "rm -rf /data/data/com.android.vending/cache/*\n";
						Utils.runRootCommand(command);
					}
				} catch (Exception e) {
					// Nothing
				}
			}
		}

		if (key.equals("isGlobalProxy")) {
			if (settings.getBoolean("isGlobalProxy", false))
				proxyedApps.setEnabled(false);
			else
				proxyedApps.setEnabled(true);
		}

		if (key.equals("isRunning")) {
			if (settings.getBoolean("isRunning", false)) {
				disableAll();
				browser.setEnabled(true);
				isRunningCheck.setChecked(true);
			} else {
				browser.setEnabled(false);
				isRunningCheck.setChecked(false);
				enableAll();
			}
		}

		if (key.equals("port"))
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
				if (!host.startsWith("http://") && !host.startsWith("https://")) {
					ed.putString("proxy", "http://" + host);
				}
				ed.commit();
				proxyText.setSummary(settings.getString("proxy", ""));
			}
	}

	@Override
	public void onStart() {
		super.onStart();
		EasyTracker.getInstance().activityStart(this);
	}

	@Override
	public void onStop() {
		super.onStop();
		EasyTracker.getInstance().activityStop(this);
	}

	private void recovery() {

		if (pd == null)
			pd = ProgressDialog.show(this, "", getString(R.string.recovering),
					true, true);

		final Handler h = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				if (pd != null) {
					pd.dismiss();
					pd = null;
				}
			}
		};

		try {
			stopService(new Intent(this, GAEProxyService.class));
		} catch (Exception e) {
			// Nothing
		}

		new Thread() {
			@Override
			public void run() {

				Utils.runRootCommand(Utils.getIptables() + " -t nat -F OUTPUT");

				Utils.runCommand(GAEProxyService.BASE + "proxy.sh stop");

				try {
					DatabaseHelper helper = OpenHelperManager.getHelper(
							GAEProxy.this, DatabaseHelper.class);
					Dao<DNSResponse, String> dnsCacheDao = helper
							.getDNSCacheDao();
					List<DNSResponse> list = dnsCacheDao.queryForAll();
					for (DNSResponse resp : list) {
						dnsCacheDao.delete(resp);
					}
					OpenHelperManager.releaseHelper();
				} catch (Exception ignore) {
					// Nothing
				}

				File f = new File("/data/data/org.gaeproxy/certs");
				if (f.exists() && f.isFile())
					f.delete();

				if (f.exists() && f.isDirectory()) {
					File[] files = f.listFiles();
					for (int i = 0; i < files.length; i++)
						if (!files[i].isDirectory())
							files[i].delete();
					f.delete();
				}

				if (!f.exists())
					f.mkdir();

				File hosts = new File("/data/data/org.gaeproxy/hosts");

				if (hosts.exists())
					hosts.delete();

				copyAssets("");

				Utils.runCommand("chmod 755 /data/data/org.gaeproxy/iptables\n"
						+ "chmod 755 /data/data/org.gaeproxy/redsocks\n"
						+ "chmod 755 /data/data/org.gaeproxy/stunnel\n"
						+ "chmod 755 /data/data/org.gaeproxy/proxy.sh\n"
						+ "chmod 755 /data/data/org.gaeproxy/localproxy.sh\n"
						+ "chmod 755 /data/data/org.gaeproxy/localproxy_en.sh\n"
						+ "chmod 755 /data/data/org.gaeproxy/python-cl\n");

				install();

				h.sendEmptyMessage(0);
			}
		}.start();

	}

	/**
	 * Called when connect button is clicked.
	 * 
	 * @throws Exception
	 */
	public boolean serviceStart() {

		if (GAEProxyService.isServiceStarted()) {
			try {
				stopService(new Intent(this, GAEProxyService.class));
			} catch (Exception e) {
				// Nothing
			}
			return false;
		}

		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		proxyType = settings.getString("proxyType", "GoAgent");

		proxy = settings.getString("proxy", "");
		if (isTextEmpty(proxy, getString(R.string.proxy_empty)))
			return false;

		if (proxy.contains("proxyofmax.appspot.com")) {
			final TextView message = new TextView(this);
			message.setPadding(10, 5, 10, 5);
			final SpannableString s = new SpannableString(
					getText(R.string.default_proxy_alert));
			Linkify.addLinks(s, Linkify.WEB_URLS);
			message.setText(s);
			message.setMovementMethod(LinkMovementMethod.getInstance());

			new AlertDialog.Builder(this)
					.setTitle(R.string.warning)
					.setCancelable(false)
					.setIcon(android.R.drawable.ic_dialog_info)
					.setNegativeButton(getString(R.string.ok_iknow),
							new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog,
										int id) {
									dialog.cancel();
								}
							}).setView(message).create().show();
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

	public void unzip(InputStream zip, String path) {
		dirChecker(path);
		try {
			ZipInputStream zin = new ZipInputStream(zip);
			ZipEntry ze = null;
			while ((ze = zin.getNextEntry()) != null) {
				if (ze.getName().contains("__MACOSX"))
					continue;
				// Log.v("Decompress", "Unzipping " + ze.getName());
				if (ze.isDirectory()) {
					dirChecker(path + ze.getName());
				} else {
					FileOutputStream fout = new FileOutputStream(path
							+ ze.getName());
					byte data[] = new byte[10 * 1024];
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

}