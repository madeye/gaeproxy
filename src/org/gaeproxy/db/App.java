package org.gaeproxy.db;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import com.j256.ormlite.android.apptools.OpenHelperManager;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

@DatabaseTable(tableName = "proxiedapp")
public class App implements Comparable<App> {

  private static final String TAG = "GAEProxy.App";
  @DatabaseField(columnName = "uid", id = true)
  private int uid;
  @DatabaseField(columnName = "username")
  private String username;
  @DatabaseField(columnName = "name")
  private String name;
  @DatabaseField(columnName = "procname")
  private String procname;
  @DatabaseField(columnName = "enabled")
  private boolean enabled = false;
  @DatabaseField(columnName = "proxied")
  private boolean proxied = false;

  public static List<App> getApps(Context context) {
    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return null;

    Dao<App, String> appDao = null;
    try {
      appDao = helper.getAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (appDao == null) {
      OpenHelperManager.releaseHelper();
      return null;
    }

    List<App> apps = new ArrayList<App>();
    try {
      apps = appDao.queryForAll();
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }
    if (apps == null) {
      OpenHelperManager.releaseHelper();
      return null;
    }

    OpenHelperManager.releaseHelper();

    return apps;
  }

  public static Set<Integer> getProxiedApps(Context context) {
    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);
    Set<Integer> result = new HashSet<Integer>();

    if (helper == null) return result;

    Dao<App, String> appDao = null;
    try {
      appDao = helper.getAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (appDao == null) {
      OpenHelperManager.releaseHelper();
      return result;
    }

    List<App> proxiedApps = null;
    try {
      App query = new App();
      query.setProxied(true);
      proxiedApps = appDao.queryForMatching(query);
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }
    if (proxiedApps == null) {
      OpenHelperManager.releaseHelper();
      return result;
    }

    for (App app : proxiedApps) {
      result.add(app.getUid());
    }

    OpenHelperManager.releaseHelper();

    return result;
  }

  public static void updateApps(Context context, Set<Integer> ids) {

    // else load the apps up
    PackageManager pMgr = context.getPackageManager();
    List<ApplicationInfo> lAppInfo = pMgr.getInstalledApplications(0);
    Iterator<ApplicationInfo> itAppInfo = lAppInfo.iterator();
    ApplicationInfo aInfo = null;

    List<App> apps = new ArrayList<App>();

    while (itAppInfo.hasNext()) {
      aInfo = itAppInfo.next();

      // ignore system apps
      if (aInfo.uid < 10000) continue;
      if (aInfo.processName == null) continue;
      if (pMgr.getApplicationLabel(aInfo) == null || pMgr.getApplicationLabel(aInfo)
          .toString()
          .equals("")) {
        continue;
      }
      if (pMgr.getApplicationIcon(aInfo) == null) continue;

      App app = new App();

      app.setEnabled(aInfo.enabled);
      app.setUid(aInfo.uid);
      app.setUsername(pMgr.getNameForUid(app.getUid()));
      app.setProcname(aInfo.processName);
      app.setName(pMgr.getApplicationLabel(aInfo).toString());
      if (ids.contains(app.getUid())) {
        app.setProxied(true);
      } else {
        app.setProxied(false);
      }

      apps.add(app);
    }

    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return;

    Dao<App, String> appDao = null;
    try {
      appDao = helper.getAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (appDao == null) {
      OpenHelperManager.releaseHelper();
      return;
    }

    try {
      appDao.executeRaw("DELETE FROM proxiedapp");
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }

    for (App app : apps) {
      try {
        appDao.createOrUpdate(app);
      } catch (SQLException e) {
        Log.e(TAG, "error to query", e);
      }
    }

    OpenHelperManager.releaseHelper();
  }

  public static void forceToUpdateApp(Context context, App app) {

    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return;

    Dao<App, String> appDao = null;
    try {
      appDao = helper.getAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (appDao == null) {
      OpenHelperManager.releaseHelper();
      return;
    }

    try {
      appDao.update(app);
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }

    OpenHelperManager.releaseHelper();
  }

  /** @return the name */
  public String getName() {
    return name;
  }

  /** @param name the name to set */
  public void setName(String name) {
    this.name = name;
  }

  /** @return the procname */
  public String getProcname() {
    return procname;
  }

  /** @param procname the procname to set */
  public void setProcname(String procname) {
    this.procname = procname;
  }

  /** @return the uid */
  public int getUid() {
    return uid;
  }

  /** @param uid the uid to set */
  public void setUid(int uid) {
    this.uid = uid;
  }

  /** @return the username */
  public String getUsername() {
    return username;
  }

  /** @param username the username to set */
  public void setUsername(String username) {
    this.username = username;
  }

  /** @return the enabled */
  public boolean isEnabled() {
    return enabled;
  }

  /** @param enabled the enabled to set */
  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  /** @return the proxied */
  public boolean isProxied() {
    return proxied;
  }

  /** @param proxied the proxied to set */
  public void setProxied(boolean proxied) {
    this.proxied = proxied;
  }

  @Override
  public int compareTo(App that) {
    if (that == null || that.getName() == null || that.getName() == null) return 1;
    if (this.isProxied() == that.isProxied()) return this.getName().compareTo(that.getName());
    if (this.isProxied()) return -1;
    return 1;
  }
}