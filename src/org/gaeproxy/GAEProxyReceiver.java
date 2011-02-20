package org.gaeproxy;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;

public class GAEProxyReceiver extends BroadcastReceiver {

	public static final String PREFS_NAME = "GAEProxy";

	private String proxy;
	private int port;
	private boolean isSaved = false;
	private boolean isAutoStart = false;
	private boolean isAutoSetProxy = false;

	@Override
	public void onReceive(Context context, Intent intent) {
 
		SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(context);

		isSaved = settings.getBoolean("isSaved", false);
		isAutoStart = settings.getBoolean("isAutoStart", false);

		if (isSaved && isAutoStart) {
			proxy = settings.getString("proxy", "");
			String portText = settings.getString("port", "");
			if (portText != null && portText.length() > 0) {
				port = Integer.valueOf(portText);
				if (port <= 1024)
					port = 1984;
			}
			else 
				port = 1984;
			
			isAutoSetProxy = settings.getBoolean("isAutoSetProxy", false);

			Intent it = new Intent(context, GAEProxyService.class);
			Bundle bundle = new Bundle();
			bundle.putString("proxy", proxy);
			bundle.putInt("port", port);
			bundle.putBoolean("isAutoSetProxy", isAutoSetProxy);

			it.putExtras(bundle);
			context.startService(it);
		}
	}

}
