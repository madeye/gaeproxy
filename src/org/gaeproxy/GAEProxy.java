package org.gaeproxy;

import java.io.BufferedInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.res.AssetManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.preference.CheckBoxPreference;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.provider.Contacts.Settings;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

public class GAEProxy extends PreferenceActivity implements
		OnSharedPreferenceChangeListener {

	class DownloadFileAsync extends AsyncTask<String, String, String> {

		@Override
		protected String doInBackground(String... path) {
			int count;

			PowerManager.WakeLock mWakeLock;
			PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
			mWakeLock = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK
					| PowerManager.ON_AFTER_RELEASE, "GAEProxy");

			mWakeLock.acquire();

			try {
				File zip = new File(path[1]);
				URL url = new URL(path[0]);
				URLConnection conexion = url.openConnection();
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
				conexion = url.openConnection();
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

			} catch (Exception e) {

				Log.e("error", e.getMessage().toString());
				System.out.println(e.getMessage().toString());
			}

			if (mWakeLock.isHeld())
				mWakeLock.release();
			return null;

		}

		@Override
		protected void onPostExecute(String unused) {
			try {
				dismissDialog(DIALOG_DOWNLOAD_PROGRESS);
			} catch (Exception ignore) {
				// Nothing
			}
		}

		@Override
		protected void onPreExecute() {
			super.onPreExecute();
			showDialog(DIALOG_DOWNLOAD_PROGRESS);
		}

		@Override
		protected void onProgressUpdate(String... progress) {
			Log.d("ANDRO_ASYNC", progress[0]);
			mProgressDialog.setProgress(Integer.parseInt(progress[0]));
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

	}

	private static final String TAG = "GAEProxy";
	public static final String PREFS_NAME = "GAEProxy";
	private static final String SERVICE_NAME = "org.gaeproxy.GAEProxyService";

	public static final int DIALOG_DOWNLOAD_PROGRESS = 0;
	private String proxy;
	private int port;
	public static boolean isAutoStart = false;

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
	private CheckBoxPreference isInstalledCheck;
	private EditTextPreference proxyText;

	private EditTextPreference portText;

	private CheckBoxPreference isRunningCheck;

	private ProgressDialog mProgressDialog;

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

		isAutoConnectCheck.setEnabled(false);
		isInstalledCheck.setEnabled(false);
	}

	private void enableAll() {
		proxyText.setEnabled(true);
		portText.setEnabled(true);

		isAutoConnectCheck.setEnabled(true);
		isInstalledCheck.setEnabled(true);
	}

	private void dirChecker(String dir) {
		File f = new File(dir);

		if (!f.isDirectory()) {
			f.mkdirs();
		}
	}

	private boolean install() {

		if (!Environment.MEDIA_MOUNTED.equals(Environment
				.getExternalStorageState()))
			return false;

		DownloadFileAsync progress = new DownloadFileAsync();
		progress.execute("http://gaeproxy.googlecode.com/files/python.zip",
				"/sdcard/python.zip", "/data/data/org.gaeproxy/",
				"http://gaeproxy.googlecode.com/files/python-extras.zip",
				"/sdcard/python-extras.zip", "/sdcard/");

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

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		addPreferencesFromResource(R.xml.gae_proxy_preference);

		proxyText = (EditTextPreference) findPreference("proxy");
		portText = (EditTextPreference) findPreference("port");

		isRunningCheck = (CheckBoxPreference) findPreference("isRunning");
		isAutoConnectCheck = (CheckBoxPreference) findPreference("isAutoConnect");
		isInstalledCheck = (CheckBoxPreference) findPreference("isInstalled");

		final CheckBoxPreference isRunningCheck = (CheckBoxPreference) findPreference("isRunning");
		if (this.isWorked(SERVICE_NAME)) {
			isRunningCheck.setChecked(true);
		} else {
			isRunningCheck.setChecked(false);
		}

		if (!runRootCommand("ls")) {
			isRoot = false;
		} else {
			isRoot = true;
		}

		if (!isWorked(SERVICE_NAME)) {
			CopyAssets("");

			runCommand("chmod 777 /data/data/org.gaeproxy/iptables_g1");
			runCommand("chmod 777 /data/data/org.gaeproxy/iptables_n1");
			runCommand("chmod 777 /data/data/org.gaeproxy/redsocks");
			runCommand("chmod 777 /data/data/org.gaeproxy/proxy.sh");
			runCommand("chmod 777 /data/data/org.gaeproxy/localproxy.sh");
		}
	}

	@Override
	protected Dialog onCreateDialog(int id) {
		switch (id) {
		case DIALOG_DOWNLOAD_PROGRESS:
			mProgressDialog = new ProgressDialog(this);
			mProgressDialog.setMessage(getString(R.string.download));
			mProgressDialog.setProgressStyle

			(ProgressDialog.STYLE_HORIZONTAL);
			mProgressDialog.setCancelable(false);
			mProgressDialog.show();
			return mProgressDialog;
		default:
			return null;
		}
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
				&& preference.getKey().equals("isInstalled")) {
			if (settings.getBoolean("isInstalled", false)) {
				if (install()) {
					isInstalledCheck.setChecked(true);
				} else {
					showAToast(getString(R.string.sdcard_alert));
					Editor ed = settings.edit();
					ed.putBoolean("isInstalled", false);
					ed.commit();
					isInstalledCheck.setChecked(false);
				}
			} else {
				uninstall();
				isInstalledCheck.setChecked(false);
			}
		} else if (preference.getKey() != null
				&& preference.getKey().equals("isRunning")) {
			if (!isInstalledCheck.isChecked()) {
				showAToast(getString(R.string.install_alert));

				Editor edit = settings.edit();

				edit.putBoolean("isRunning", false);

				edit.commit();

				isRunningCheck.setChecked(false);
				enableAll();
				return false;
			}
			if (!serviceStart()) {

				Editor edit = settings.edit();

				edit.putBoolean("isRunning", false);

				edit.commit();

				isRunningCheck.setChecked(false);
				enableAll();
			}
		}
		return super.onPreferenceTreeClick(preferenceScreen, preference);
	}

	@Override
	protected void onResume() {
		super.onResume();
		SharedPreferences settings = PreferenceManager
				.getDefaultSharedPreferences(this);

		Editor edit = settings.edit();

		if (this.isWorked(SERVICE_NAME)) {
			edit.putBoolean("isRunning", true);
		} else {
			edit.putBoolean("isRunning", false);
		}

		edit.commit();

		if (settings.getBoolean("isRunning", false)) {
			isRunningCheck.setChecked(true);
			disableAll();
		} else {
			isRunningCheck.setChecked(false);
			enableAll();
		}

		// Setup the initial values

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

		if (key.equals("isRunning")) {
			if (settings.getBoolean("isRunning", false)) {
				disableAll();
				isRunningCheck.setChecked(true);
			} else {
				enableAll();
				isRunningCheck.setChecked(false);
			}
		}

		if (key.equals("port"))
			if (settings.getString("port", "").equals(""))
				portText.setSummary(getString(R.string.port_summary));
			else
				portText.setSummary(settings.getString("port", ""));
		else if (key.equals("proxy"))
			if (settings.getString("proxy", "").equals("")) {
				proxyText.setSummary(getString(R.string.proxy_summary));
			} else {
				if (!settings.getString("proxy", "").startsWith("http://")) {
					String host = settings.getString("proxy", "");
					Editor ed = settings.edit();
					ed.putString("proxy", "http://" + host);
					ed.commit();
				}
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

		proxy = settings.getString("proxy", "");
		if (isTextEmpty(proxy, getString(R.string.proxy_empty)))
			return false;

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

		isAutoStart = settings.getBoolean("isAutoStart", false);

		try {

			Intent it = new Intent(this, GAEProxyService.class);
			Bundle bundle = new Bundle();
			bundle.putString("proxy", proxy);
			bundle.putInt("port", port);

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
		}

		return true;
	}

	private void recovery() {
		try {
			stopService(new Intent(this, GAEProxyService.class));
		} catch (Exception e) {
			// Nothing
		}

		if (GAEProxyService.isARMv6()) {
			runRootCommand(GAEProxyService.BASE
					+ "iptables_g1 -t nat -F OUTPUT");
		} else {
			runRootCommand(GAEProxyService.BASE
					+ "iptables_n1 -t nat -F OUTPUT");
		}

		runRootCommand(GAEProxyService.BASE + "proxy.sh stop");
	}

}