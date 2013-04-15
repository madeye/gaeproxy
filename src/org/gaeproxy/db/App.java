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
import java.util.*;

@DatabaseTable(tableName = "proxiedapp")
public class App implements Comparable<App> {

  private static final String TAG = "GAEProxy.App";

  @DatabaseField(columnName = "username", id = true)
  private String username;
  @DatabaseField(columnName = "uid")
  private int uid;
  @DatabaseField(columnName = "name")
  private String name;
  @DatabaseField(columnName = "procname")
  private String procname;
  @DatabaseField(columnName = "enabled")
  private boolean enabled;
  @DatabaseField(columnName = "proxied")
  private boolean proxied = false;

  /**
   * @return the name
   */
  public String getName() {
    return name;
  }

  /**
   * @return the procname
   */
  public String getProcname() {
    return procname;
  }

  /**
   * @return the uid
   */
  public int getUid() {
    return uid;
  }

  /**
   * @return the username
   */
  public String getUsername() {
    return username;
  }

  /**
   * @return the enabled
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * @return the proxied
   */
  public boolean isProxied() {
    return proxied;
  }

  /**
   * @param enabled the enabled to set
   */
  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  /**
   * @param name the name to set
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * @param procname the procname to set
   */
  public void setProcname(String procname) {
    this.procname = procname;
  }

  /**
   * @param proxied the proxied to set
   */
  public void setProxied(boolean proxied) {
    this.proxied = proxied;
  }

  /**
   * @param uid the uid to set
   */
  public void setUid(int uid) {
    this.uid = uid;
  }

  /**
   * @param username the username to set
   */
  public void setUsername(String username) {
    this.username = username;
  }

  @Override
  public int compareTo(App that) {
    if (that == null || that.getName() == null || that.getName() == null)
      return 1;
    if (this.isProxied() == that.isProxied())
      return this.getName().compareTo(that.getName());
    if (this.isProxied())
      return -1;
    return 1;
  }


  public static Map<String, App> getProxiedApps(Context context) {
    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return null;

    Dao<App, String> proxiedAppDao = null;
    try {
      proxiedAppDao = helper.getProxiedAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (proxiedAppDao == null) {
      OpenHelperManager.releaseHelper();
      return null;
    }

    List<App> proxiedApps = null;
    try {
      proxiedApps = proxiedAppDao.queryForAll();
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }
    if (proxiedApps == null) {
      OpenHelperManager.releaseHelper();
      return null;
    }

    Map<String, App> proxiedAppMap = new HashMap<String, App>();
    for (App app : proxiedApps) {
      proxiedAppMap.put(app.getUsername(), app);
    }

    OpenHelperManager.releaseHelper();

    return proxiedAppMap;
  }

  public static void updateProxiedApps(Context context, Set<String> ids) {

    // else load the apps up
    PackageManager pMgr = context.getPackageManager();
    List<ApplicationInfo> lAppInfo = pMgr.getInstalledApplications(0);
    Iterator<ApplicationInfo> itAppInfo = lAppInfo.iterator();
    ApplicationInfo aInfo = null;

    List<App> proxiedApps = new ArrayList<App>();

    while (itAppInfo.hasNext()) {
      aInfo = itAppInfo.next();

      // ignore system apps
      if (aInfo.uid < 10000)
        continue;

      if (aInfo.processName == null)
        continue;
      if (pMgr.getApplicationLabel(aInfo) == null
          || pMgr.getApplicationLabel(aInfo).toString().equals(""))
        continue;
      if (pMgr.getApplicationIcon(aInfo) == null)
        continue;

      App app = new App();
      app.setEnabled(aInfo.enabled);
      app.setUid(aInfo.uid);
      app.setUsername(pMgr.getNameForUid(app.getUid()));
      app.setProcname(aInfo.processName);
      app.setName(pMgr.getApplicationLabel(aInfo).toString());
      app.setProxied(true);

      if (ids.contains(app.getUsername())) {
        proxiedApps.add(app);
      }
    }

    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return;

    Dao<App, String> proxiedAppDao = null;
    try {
      proxiedAppDao = helper.getProxiedAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (proxiedAppDao == null) {
      OpenHelperManager.releaseHelper();
      return;
    }

    try {
      proxiedAppDao.executeRaw("DELETE FROM proxiedapp");
      for (App app : proxiedApps) {
        proxiedAppDao.create(app);
      }
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }

    OpenHelperManager.releaseHelper();

  }

  public static void forceToUpdateProxiedApps(Context context, Set<App> proxiedApps) {

    OpenHelperManager.setOpenHelperClass(DatabaseHelper.class);
    DatabaseHelper helper = OpenHelperManager.getHelper(context, DatabaseHelper.class);

    if (helper == null) return;

    Dao<App, String> proxiedAppDao = null;
    try {
      proxiedAppDao = helper.getProxiedAppDao();
    } catch (SQLException e) {
      Log.e(TAG, "error to open database", e);
    }
    if (proxiedAppDao == null) {
      OpenHelperManager.releaseHelper();
      return;
    }

    try {
      proxiedAppDao.executeRaw("DELETE FROM proxiedapp");
      for (App app : proxiedApps) {
        proxiedAppDao.create(app);
      }
    } catch (SQLException e) {
      Log.e(TAG, "error to query", e);
    }

    OpenHelperManager.releaseHelper();

  }

}