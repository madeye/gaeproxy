package org.gaeproxy;

import android.app.Application;
import com.google.analytics.tracking.android.EasyTracker;

public class GAEProxyApplication extends Application {

  @Override
  public void onCreate() {
    EasyTracker.getInstance().setContext(this);
  }

}
