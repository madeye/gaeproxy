/* Copyright (c) 2009, Nathan Freitas, Orbot / The Guardian Project - http://openideals.com/guardian */
/* See LICENSE for licensing information */

package org.gaeproxy;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.PixelFormat;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.WindowManager;
import android.widget.*;
import android.widget.AbsListView.OnScrollListener;
import android.widget.CompoundButton.OnCheckedChangeListener;
import org.gaeproxy.db.App;

import java.util.*;

public class ProxiedAppActivity extends Activity implements OnCheckedChangeListener {

  private class UpdateDatabaseTask extends AsyncTask<Void, Void, Void> {

    private void saveAppSettings() {
      if (mAppList == null) return;

      Set<App> proxiedApps = new HashSet<App>();
      for (App app : mAppList) {
        if (app.isProxied()) {
          proxiedApps.add(app);
        }
      }

      App.forceToUpdateProxiedApps(getApplicationContext(), proxiedApps);

    }

    @Override
    protected Void doInBackground(Void... voids) {
      saveAppSettings();
      return null;
    }
  }

  private static final int MSG_LOAD_START = 1;
  private static final int MSG_LOAD_FINISH = 2;
  final Handler handler = new Handler() {
    @Override
    public void handleMessage(Message msg) {
      switch (msg.what) {
        case MSG_LOAD_START:
          mProgressDialog = ProgressDialog.show(ProxiedAppActivity.this, "",
              getString(R.string.loading), true, true);
          break;
        case MSG_LOAD_FINISH:

          mAppListView.setAdapter(mListAdapter);

          mAppListView.setOnScrollListener(new OnScrollListener() {

            boolean visible;

            @Override
            public void onScroll(AbsListView view,
                                 int firstVisibleItem, int visibleItemCount,
                                 int totalItemCount) {
              if (visible) {
                String name = mAppList.get(firstVisibleItem).getName();
                if (name != null && name.length() > 1)
                  mOverlay.setText(mAppList.get(firstVisibleItem)
                      .getName().substring(0, 1));
                else
                  mOverlay.setText("*");
                mOverlay.setVisibility(View.VISIBLE);
              }
            }

            @Override
            public void onScrollStateChanged(AbsListView view,
                                             int scrollState) {
              visible = true;
              if (scrollState == ListView.OnScrollListener.SCROLL_STATE_IDLE) {
                mOverlay.setVisibility(View.INVISIBLE);
              }
            }
          });

          if (mProgressDialog != null) {
            mProgressDialog.dismiss();
            mProgressDialog = null;
          }
          break;
      }
      super.handleMessage(msg);
    }
  };
  ListView mAppListView;
  TextView mOverlay;
  ListAdapter mListAdapter;
  ImageLoader mImageLoader;
  ProgressDialog mProgressDialog = null;
  boolean mIsAppsLoaded = false;
  List<App> mAppList = null;

  @Override
  protected void onDestroy() {
    super.onDestroy();
    if (mOverlay != null && mOverlay.getParent() != null) {
      getWindowManager().removeView(mOverlay);
    }
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.layout_apps);

    mImageLoader = ImageLoaderFactory.getImageLoader(this);
    mAppListView = (ListView) findViewById(R.id.applistview);
    mOverlay = (TextView) View.inflate(this, R.layout.overlay, null);
    getWindowManager()
        .addView(
            mOverlay,
            new WindowManager.LayoutParams(
                LayoutParams.WRAP_CONTENT,
                LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_APPLICATION,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                    | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                PixelFormat.TRANSLUCENT));

  }

  public void getApps() {

    mAppList = new ArrayList<App>();

    // else load the apps up
    PackageManager pMgr = getPackageManager();
    List<ApplicationInfo> lAppInfo = pMgr.getInstalledApplications(0);
    Iterator<ApplicationInfo> itAppInfo = lAppInfo.iterator();
    ApplicationInfo aInfo = null;

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
      app.setProxied(false);

      mAppList.add(app);
    }

    Map<String, App> proxiedApps = App.getProxiedApps(this);
    if (proxiedApps != null) {
      for (App app : mAppList) {
        if (proxiedApps.containsKey(app.getUsername())) {
          app.setProxied(true);
        }
      }
    }

    Collections.sort(mAppList);
  }

  private void loadApps() {
    getApps();

    final LayoutInflater inflater = getLayoutInflater();

    mListAdapter = new ArrayAdapter<App>(this, R.layout.layout_apps_item,
        R.id.itemtext, mAppList) {
      @Override
      public View getView(int position, View convertView, ViewGroup parent) {
        ListEntry entry;
        if (convertView == null) {
          // Inflate a new view
          convertView = inflater.inflate(R.layout.layout_apps_item,
              parent, false);
          entry = new ListEntry();
          entry.icon = (ImageView) convertView
              .findViewById(R.id.itemicon);
          entry.box = (CheckBox) convertView
              .findViewById(R.id.itemcheck);
          entry.text = (TextView) convertView
              .findViewById(R.id.itemtext);

          convertView.setTag(entry);

          entry.box.setOnCheckedChangeListener(ProxiedAppActivity.this);
        } else {
          // Convert an existing view
          entry = (ListEntry) convertView.getTag();
        }

        final App app = mAppList.get(position);

        entry.icon.setTag(app.getUid());

        mImageLoader.DisplayImage(app.getUid(),
            (Activity) convertView.getContext(), entry.icon);

        entry.text.setText(app.getName());

        final CheckBox box = entry.box;
        box.setTag(app);
        box.setChecked(app.isProxied());

        entry.text.setTag(box);

        return convertView;
      }
    };

    mIsAppsLoaded = true;

  }

  /**
   * Called an application is check/unchecked
   */
  @Override
  public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
    final App app = (App) buttonView.getTag();
    if (app != null) {
      app.setProxied(isChecked);
      new UpdateDatabaseTask().execute();
    }
  }

  @Override
  protected void onResume() {
    super.onResume();

    new Thread() {

      @Override
      public void run() {
        handler.sendEmptyMessage(MSG_LOAD_START);
        if (!mIsAppsLoaded)
          loadApps();
        handler.sendEmptyMessage(MSG_LOAD_FINISH);
      }
    }.start();

  }

  @Override
  protected void onPause() {
    super.onPause();
  }

  /*
    * (non-Javadoc)
    *
    * @see android.app.Activity#onStop()
    */
  @Override
  protected void onStop() {
    super.onStop();
    // Log.d(getClass().getName(),"Exiting Preferences");
  }

  private static class ListEntry {
    private CheckBox box;
    private TextView text;
    private ImageView icon;
  }

}
