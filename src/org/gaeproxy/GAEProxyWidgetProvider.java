package org.gaeproxy;

import java.util.ArrayList;

import android.app.ActivityManager;
import android.app.PendingIntent;
import android.app.ActivityManager.RunningServiceInfo;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.RemoteViews;

public class GAEProxyWidgetProvider extends AppWidgetProvider {

	public static final String PROXY_SWITCH_ACTION = "org.gaeproxy.GAEProxyWidgetProvider.PROXY_SWITCH_ACTION";
	public static final String SERVICE_NAME = "org.gaeproxy.GAEProxyService";
	public static final String TAG = "GAEProxyWidgetProvider";
	public static int[] widgets;

	private String proxy;
	private int port;

	public void onUpdate(Context context, AppWidgetManager appWidgetManager,
			int[] appWidgetIds) {
		final int N = appWidgetIds.length;
		widgets = appWidgetIds.clone();

		// Perform this loop procedure for each App Widget that belongs to this
		// provider
		for (int i = 0; i < N; i++) {
			int appWidgetId = appWidgetIds[i];

			// Create an Intent to launch ExampleActivity
			Intent intent = new Intent(context, GAEProxyWidgetProvider.class);
			intent.setAction(PROXY_SWITCH_ACTION);
			PendingIntent pendingIntent = PendingIntent.getBroadcast(context,
					0, intent, 0);

			// Get the layout for the App Widget and attach an on-click listener
			// to the button
			RemoteViews views = new RemoteViews(context.getPackageName(),
					R.layout.gaeproxy_appwidget);
			views.setOnClickPendingIntent(R.id.serviceToggle, pendingIntent);

			if (isWorked(context, SERVICE_NAME)) {
				views.setImageViewResource(R.id.serviceToggle, R.drawable.on);
				Log.d(TAG, "Service running");
			} else {
				views.setImageViewResource(R.id.serviceToggle, R.drawable.off);
				Log.d(TAG, "Service stopped");
			}

			// Tell the AppWidgetManager to perform an update on the current App
			// Widget
			appWidgetManager.updateAppWidget(appWidgetId, views);
		}
	}

	public boolean isWorked(Context context, String service) {
		ActivityManager myManager = (ActivityManager) context
				.getSystemService(Context.ACTIVITY_SERVICE);
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

	@Override
	public void onReceive(Context context, Intent intent) {
		super.onReceive(context, intent);

		if (intent.getAction().equals(PROXY_SWITCH_ACTION)) {

			RemoteViews views = new RemoteViews(context.getPackageName(),
					R.layout.gaeproxy_appwidget);
			views.setImageViewResource(R.id.serviceToggle, R.drawable.ing);
			AppWidgetManager.getInstance(context).updateAppWidget(widgets,
					views);

			Log.d(TAG, "Proxy switch action");
			// do some really cool stuff here
			if (isWorked(context, SERVICE_NAME)) {
				// Service is working, so stop it
				try {
					context.stopService(new Intent(context,
							GAEProxyService.class));
				} catch (Exception e) {
					// Nothing
				}

			} else {

				// Service is not working, then start it
				SharedPreferences settings = PreferenceManager
						.getDefaultSharedPreferences(context);

				boolean isInstalled = settings.getBoolean("isInstalled", false);

				if (isInstalled) {
					proxy = settings.getString("proxy", "");
					String portText = settings.getString("port", "");
					if (portText != null && portText.length() > 0) {
						port = Integer.valueOf(portText);
						if (port <= 1024)
							port = 1984;
					} else {
						port = 1984;
					}

					Intent it = new Intent(context, GAEProxyService.class);
					Bundle bundle = new Bundle();
					bundle.putString("proxy", proxy);
					bundle.putInt("port", port);

					it.putExtras(bundle);
					context.startService(it);
				} else {
					try {
						Thread.sleep(500);
					} catch (InterruptedException ignore) {
						//Nothing
					}
					views.setImageViewResource(R.id.serviceToggle,
							R.drawable.off);
					AppWidgetManager.getInstance(context).updateAppWidget(
							widgets, views);
				}

			}

		}
	}
}
