package org.gaeproxy;

import android.app.Application;
import com.google.analytics.tracking.android.EasyTracker;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GAEProxyApplication extends Application {

  public ExecutorService UpdatePool = Executors.newSingleThreadExecutor();

  @Override
  public void onCreate() {
    EasyTracker.getInstance().setContext(this);
  }
}
