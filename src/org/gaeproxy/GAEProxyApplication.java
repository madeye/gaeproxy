package org.gaeproxy;

import com.google.analytics.tracking.android.EasyTracker;

import android.app.Application;

public class GAEProxyApplication extends Application {

	@Override
	public void onCreate() {
		EasyTracker.getInstance().setContext(this);
	}

}
