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

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.res.AssetManager;
import android.net.Uri;
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
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.google.ads.AdRequest;
import com.google.ads.AdSize;
import com.google.ads.AdView;
import com.google.analytics.tracking.android.EasyTracker;
import com.j256.ormlite.android.apptools.OpenHelperManager;
import de.keyboardsurfer.android.widget.crouton.Crouton;
import de.keyboardsurfer.android.widget.crouton.Style;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.gaeproxy.db.DatabaseHelper;

public class GAEProxyActivity extends PreferenceActivity
    implements OnSharedPreferenceChangeListener {

  public static final String PREFS_NAME = "GAEProxy";
  private static final String TAG = "GAEProxy";
  private static final int MSG_CRASH_RECOVER = 1;
  private static final int MSG_INITIAL_FINISH = 2;
  private static ProgressDialog sProgressDialog = null;
  final Handler handler = new Handler() {
    @Override
    public void handleMessage(Message msg) {
      SharedPreferences settings =
          PreferenceManager.getDefaultSharedPreferences(GAEProxyActivity.this);
      Editor ed = settings.edit();
      switch (msg.what) {
        case MSG_CRASH_RECOVER:
          Crouton.makeText(GAEProxyActivity.this, R.string.crash_alert, Style.ALERT).show();
          ed.putBoolean("isRunning", false);
          break;
        case MSG_INITIAL_FINISH:
          if (sProgressDialog != null) {
            sProgressDialog.dismiss();
            sProgressDialog = null;
          }
          break;
      }
      ed.commit();
      super.handleMessage(msg);
    }
  };
  private CheckBoxPreference isAutoConnectCheck;
  private CheckBoxPreference isGlobalProxyCheck;
  private EditTextPreference proxyText;
  private EditTextPreference portText;
  private EditTextPreference sitekeyText;
  private ListPreference proxyTypeList;
  private CheckBoxPreference isHTTPSProxyCheck;
  private CheckBoxPreference isGFWListCheck;
  private CheckBoxPreference isRunningCheck;
  private Preference proxiedApps;
  private CheckBoxPreference isBypassAppsCheck;
  private Preference browser;
  private AdView adView;

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
        in = assetManager.open(path + (path.isEmpty() ? "" : "/") + files[i]);
        out = new FileOutputStream("/data/data/org.gaeproxy/" + files[i]);
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
    proxiedApps.setEnabled(false);
    isGFWListCheck.setEnabled(false);
    isBypassAppsCheck.setEnabled(false);

    isAutoConnectCheck.setEnabled(false);
    isGlobalProxyCheck.setEnabled(false);
    isHTTPSProxyCheck.setEnabled(false);
    proxyTypeList.setEnabled(false);
  }

  private void enableAll() {
    proxyText.setEnabled(true);
    portText.setEnabled(true);
    sitekeyText.setEnabled(true);
    isGlobalProxyCheck.setEnabled(true);
    isGFWListCheck.setEnabled(true);
    isHTTPSProxyCheck.setEnabled(true);
    if (!isGlobalProxyCheck.isChecked()) {
      proxiedApps.setEnabled(true);
      isBypassAppsCheck.setEnabled(true);
    }

    isAutoConnectCheck.setEnabled(true);
    proxyTypeList.setEnabled(true);
  }

  private boolean install() {

    PowerManager.WakeLock mWakeLock;
    PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
    mWakeLock = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK | PowerManager.ON_AFTER_RELEASE,
        "GAEProxy");

    File tmp = new File("/data/data/org.gaeproxy/python.mp3");

    copyAssets("modules");
    String[] argc = {
        "7z", "x", tmp.getAbsolutePath(), "/data/data/org.gaeproxy"
    };
    LZMA.extract(argc);

    tmp.delete();
    if (mWakeLock.isHeld()) mWakeLock.release();

    return true;
  }

  private boolean isTextEmpty(String s, String msg) {
    if (s == null || s.length() <= 0) {
      showADialog(msg);
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
    adView = new AdView(GAEProxyActivity.this, AdSize.SMART_BANNER, "a14d8be8a284afc");
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
    proxiedApps = findPreference("proxiedApps");
    browser = findPreference("browser");

    isRunningCheck = (CheckBoxPreference) findPreference("isRunning");
    isAutoConnectCheck = (CheckBoxPreference) findPreference("isAutoConnect");
    isHTTPSProxyCheck = (CheckBoxPreference) findPreference("isHTTPSProxy");
    isGlobalProxyCheck = (CheckBoxPreference) findPreference("isGlobalProxy");
    isGFWListCheck = (CheckBoxPreference) findPreference("isGFWList");
    isBypassAppsCheck = (CheckBoxPreference) findPreference("isBypassApps");

    proxyTypeList = (ListPreference) findPreference("proxyType");

    if (sProgressDialog == null) {
      sProgressDialog = ProgressDialog.show(this, "", getString(R.string.initializing), true, true);
    }

    final SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);

    new Thread() {
      @Override
      public void run() {

        Utils.isRoot();

        String versionName;
        try {
          versionName = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
          versionName = "NONE";
        }

        if (!settings.getBoolean(versionName, false)) {

          Editor edit = settings.edit();
          edit.putBoolean(versionName, true);
          edit.commit();

          File f = new File("/data/data/org.gaeproxy/certs");
          if (f.exists() && f.isFile()) f.delete();
          if (!f.exists()) f.mkdir();

          File hosts = new File("/data/data/org.gaeproxy/hosts");

          if (hosts.exists()) hosts.delete();

          copyAssets("");

          Utils.runCommand("chmod 755 /data/data/org.gaeproxy/iptables\n"
              + "chmod 755 /data/data/org.gaeproxy/redsocks\n"
              + "chmod 755 /data/data/org.gaeproxy/proxy.sh\n"
              + "chmod 755 /data/data/org.gaeproxy/localproxy.sh\n"
              + "chmod 755 /data/data/org.gaeproxy/python-cl\n");

          install();
        }

        handler.sendEmptyMessage(MSG_INITIAL_FINISH);
      }
    }.start();
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    menu.add(Menu.NONE, Menu.FIRST + 1, 1, getString(R.string.recovery))
        .setIcon(android.R.drawable.ic_menu_delete);
    menu.add(Menu.NONE, Menu.FIRST + 2, 3, getString(R.string.about))
        .setIcon(android.R.drawable.ic_menu_info_details);
    menu.add(Menu.NONE, Menu.FIRST + 3, 2, getString(R.string.install_ca))
        .setIcon(android.R.drawable.ic_menu_add);
    return true;
  }

  /** Called when the activity is closed. */
  @Override
  public void onDestroy() {
    SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);

    SharedPreferences.Editor editor = settings.edit();
    editor.putBoolean("isConnected", GAEProxyService.isServiceStarted());
    editor.commit();

    if (sProgressDialog != null) {
      sProgressDialog.dismiss();
      sProgressDialog = null;
    }

    adView.destroy();

    Crouton.cancelAllCroutons();

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

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    switch (item.getItemId()) {
      case Menu.FIRST + 1:
        recovery();
        break;
      case Menu.FIRST + 2:
        String versionName = "";
        try {
          versionName = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
          versionName = "";
        }
        showAbout();
        break;
      case Menu.FIRST + 3:
        Intent i = new Intent(Intent.ACTION_VIEW);
        i.setData(Uri.parse("http://myhosts.sinaapp.com/ca.crt"));
        startActivity(i);
        break;
    }

    return true;
  }

  @Override
  protected void onPause() {
    super.onPause();

    // Unregister the listener whenever a key changes
    getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(this);
  }

  @Override
  public boolean onPreferenceTreeClick(PreferenceScreen preferenceScreen, Preference preference) {
    SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);

    if (preference.getKey() != null && preference.getKey().equals("proxiedApps")) {
      Intent intent = new Intent(this, ProxiedAppActivity.class);
      startActivity(intent);
    } else if (preference.getKey() != null && preference.getKey().equals("browser")) {
      Intent intent = new Intent(this, org.gaeproxy.zirco.ui.activities.MainActivity.class);
      startActivity(intent);
    } else if (preference.getKey() != null && preference.getKey().equals("isRunning")) {
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
    SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);

    if (settings.getBoolean("isGlobalProxy", false)) {
      proxiedApps.setEnabled(false);
      isBypassAppsCheck.setEnabled(false);
    } else {
      proxiedApps.setEnabled(true);
      isBypassAppsCheck.setEnabled(true);
    }

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

    if (!settings.getString("proxyType", "").equals("")) {
      proxyTypeList.setSummary(settings.getString("proxyType", ""));
    }

    if (!settings.getString("sitekey", "").equals("")) {
      sitekeyText.setSummary(settings.getString("sitekey", ""));
    }

    if (!settings.getString("port", "").equals("")) {
      portText.setSummary(settings.getString("port", getString(R.string.port_summary)));
    }

    if (!settings.getString("proxy", "").equals("")) {
      proxyText.setSummary(settings.getString("proxy", getString(R.string.proxy_summary)));
    }

    // Set up a listener whenever a key changes
    getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);
  }

  @Override
  public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
    // Let's do something a preference value changes
    SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);

    if (key.equals("isConnecting")) {
      if (settings.getBoolean("isConnecting", false)) {
        Log.d(TAG, "Connecting start");
        if (sProgressDialog == null) {
          sProgressDialog =
              ProgressDialog.show(this, "", getString(R.string.connecting), true, true);
        }
      } else {
        Log.d(TAG, "Connecting finish");
        if (sProgressDialog != null) {
          sProgressDialog.dismiss();
          sProgressDialog = null;
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
            String command = "setprop gsm.sim.operator.numeric 310026\n"
                + "setprop gsm.operator.numeric 310026\n"
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
      if (settings.getBoolean("isGlobalProxy", false)) {
        proxiedApps.setEnabled(false);
        isBypassAppsCheck.setEnabled(false);
      } else {
        proxiedApps.setEnabled(true);
        isBypassAppsCheck.setEnabled(true);
      }
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

    if (key.equals("proxyType")) {
      proxyTypeList.setSummary(settings.getString("proxyType", ""));
    } else if (key.equals("port")) {
      if (settings.getString("port", "").equals("")) {
        portText.setSummary(getString(R.string.port_summary));
      } else {
        portText.setSummary(settings.getString("port", ""));
      }
    } else if (key.equals("sitekey")) {
      if (settings.getString("sitekey", "").equals("")) {
        sitekeyText.setSummary(getString(R.string.sitekey_summary));
      } else {
        sitekeyText.setSummary(settings.getString("sitekey", ""));
      }
    } else if (key.equals("proxy")) {
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

    if (sProgressDialog == null) {
      sProgressDialog = ProgressDialog.show(this, "", getString(R.string.recovering), true, true);
    }

    final Handler h = new Handler() {
      @Override
      public void handleMessage(Message msg) {
        if (sProgressDialog != null) {
          sProgressDialog.dismiss();
          sProgressDialog = null;
        }
      }
    };

    try {
      stopService(new Intent(this, GAEProxyService.class));
    } catch (Exception e) {
      // Nothing
    }

    // Flush DNS
    try {
      OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
      DatabaseHelper helper = OpenHelperManager.getHelper(this, DatabaseHelper.class);
      helper.getDNSCacheDao().executeRaw("delete from dnsresponse");
    } catch (Exception ignored) {
      Log.e(TAG, "Unexpected exception", ignored);
    }

    new Thread() {
      @Override
      public void run() {

        Utils.runRootCommand(Utils.getIptables() + " -t nat -F OUTPUT");
        Utils.runCommand(GAEProxyService.BASE + "proxy.sh stop");

        File f = new File("/data/data/org.gaeproxy/certs");
        if (f.exists() && f.isFile()) f.delete();

        if (f.exists() && f.isDirectory()) {
          File[] files = f.listFiles();
          for (int i = 0; i < files.length; i++)
            if (!files[i].isDirectory()) files[i].delete();
          f.delete();
        }

        if (!f.exists()) f.mkdir();

        File hosts = new File("/data/data/org.gaeproxy/hosts");

        if (hosts.exists()) hosts.delete();

        copyAssets("");

        Utils.runCommand("chmod 755 /data/data/org.gaeproxy/iptables\n"
            + "chmod 755 /data/data/org.gaeproxy/redsocks\n"
            + "chmod 755 /data/data/org.gaeproxy/proxy.sh\n"
            + "chmod 755 /data/data/org.gaeproxy/localproxy.sh\n"
            + "chmod 755 /data/data/org.gaeproxy/busybox\n"
            + "chmod 755 /data/data/org.gaeproxy/python-cl\n");

        install();

        h.sendEmptyMessage(0);
      }
    }.start();
  }

  /** Called when connect button is clicked. */
  public boolean serviceStart() {

    if (GAEProxyService.isServiceStarted()) {
      try {
        stopService(new Intent(this, GAEProxyService.class));
      } catch (Exception e) {
        // Nothing
      }
      return false;
    }

    SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);

    final String proxy = settings.getString("proxy", "");
    if (isTextEmpty(proxy, getString(R.string.proxy_empty))) return false;

    if (proxy.contains("proxyofmax.appspot.com")) {
      final TextView message = new TextView(this);
      message.setPadding(10, 5, 10, 5);
      final SpannableString s = new SpannableString(getText(R.string.default_proxy_alert));
      Linkify.addLinks(s, Linkify.WEB_URLS);
      message.setText(s);
      message.setMovementMethod(LinkMovementMethod.getInstance());

      new AlertDialog.Builder(this).setTitle(R.string.warning)
          .setCancelable(false)
          .setIcon(android.R.drawable.ic_dialog_info)
          .setNegativeButton(getString(R.string.ok_iknow), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int id) {
              dialog.cancel();
            }
          })
          .setView(message)
          .create()
          .show();
    }

    String portText = settings.getString("port", "");
    if (isTextEmpty(portText, getString(R.string.port_empty))) return false;
    try {
      int port = Integer.valueOf(portText);
      if (port <= 1024) {
        this.showADialog(getString(R.string.port_alert));
        return false;
      }
    } catch (Exception e) {
      this.showADialog(getString(R.string.port_alert));
      return false;
    }

    try {
      Intent it = new Intent(this, GAEProxyService.class);
      startService(it);
    } catch (Exception e) {
      // Nothing
      return false;
    }

    return true;
  }

  private void showAbout() {

    WebView web = new WebView(this);
    web.loadUrl("file:///android_asset/startpage/about.html");
    web.setWebViewClient(new WebViewClient() {
      @Override
      public boolean shouldOverrideUrlLoading(WebView view, String url) {
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        return true;
      }
    });

    String versionName = "";
    try {
      versionName = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
    } catch (NameNotFoundException ex) {
        versionName = "";
    }

    new AlertDialog.Builder(this)
        .setTitle(String.format(getString(R.string.about_title), versionName))
        .setCancelable(false)
        .setNegativeButton(getString(R.string.ok_iknow), new DialogInterface.OnClickListener() {
          @Override
          public void onClick(DialogInterface dialog, int id) {
            dialog.cancel();
          }
        }).setView(web).create().show();
  }

  private void showADialog(String msg) {
    AlertDialog.Builder builder = new AlertDialog.Builder(this);
    builder.setMessage(msg)
        .setCancelable(false)
        .setNegativeButton(getString(R.string.ok_iknow), new DialogInterface.OnClickListener() {
          @Override
          public void onClick(DialogInterface dialog, int id) {
            dialog.cancel();
          }
        });
    AlertDialog alert = builder.create();
    alert.show();
  }
}
