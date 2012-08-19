/* gaeproxy - GAppProxy / WallProxy client App for Android
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

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.os.Vibrator;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.RemoteViews;
import android.widget.Toast;

public class GAEProxyWidgetProvider extends AppWidgetProvider {

	public static final String PROXY_SWITCH_ACTION = "org.gaeproxy.GAEProxyWidgetProvider.PROXY_SWITCH_ACTION";
	public static final String SERVICE_NAME = "org.gaeproxy.GAEProxyService";
	public static final String TAG = "GAEProxyWidgetProvider";

	private String proxy;
	private String proxyType;
	private int port;
	private String sitekey;
	private boolean isGlobalProxy;
	private boolean isHTTPSProxy;
	private boolean isGFWList;

	@Override
	public synchronized void onReceive(Context context, Intent intent) {
		super.onReceive(context, intent);

		if (intent.getAction().equals(PROXY_SWITCH_ACTION)) {

			SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(context);

			if (GAEProxyService.statusLock) {
				// only one request a time
				return;
			}

			// Get instance of Vibrator from current Context
			Vibrator v = (Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);

			// Vibrate for 10 milliseconds
			v.vibrate(10);

			RemoteViews views = new RemoteViews(context.getPackageName(),
					R.layout.gaeproxy_appwidget);
			try {
				views.setImageViewResource(R.id.serviceToggle, R.drawable.ing);

				AppWidgetManager awm = AppWidgetManager.getInstance(context);
				awm.updateAppWidget(awm.getAppWidgetIds(new ComponentName(context,
						GAEProxyWidgetProvider.class)), views);
			} catch (Exception ignore) {
				// Nothing
			}

			Log.d(TAG, "Proxy switch action");

			// do some really cool stuff here
			if (GAEProxyService.isServiceStarted()) {
				// Service is working, so stop it
				try {
					context.stopService(new Intent(context, GAEProxyService.class));
				} catch (Exception e) {
					// Nothing
				}

			} else {

				// Service is not working, then start it
				String versionName;
				try {
					versionName = context.getPackageManager().getPackageInfo(
							context.getPackageName(), 0).versionName;
				} catch (NameNotFoundException e) {
					versionName = "NONE";
				}
				boolean isInstalled = settings.getBoolean(versionName, false);

				if (isInstalled) {
					Toast.makeText(context, context.getString(R.string.toast_start),
							Toast.LENGTH_LONG).show();

					proxy = settings.getString("proxy", "");
					proxyType = settings.getString("proxyType", "GoAgent");
					String portText = settings.getString("port", "");
					if (portText != null && portText.length() > 0) {
						port = Integer.valueOf(portText);
						if (port <= 1024)
							port = 1984;
					} else {
						port = 1984;
					}
					sitekey = settings.getString("sitekey", "");
					isGlobalProxy = settings.getBoolean("isGlobalProxy", false);
					isHTTPSProxy = settings.getBoolean("isHTTPSProxy", false);
					isGFWList = settings.getBoolean("isGFWList", false);

					Intent it = new Intent(context, GAEProxyService.class);
					Bundle bundle = new Bundle();
					bundle.putString("proxy", proxy);
					bundle.putInt("port", port);
					bundle.putString("proxyType", proxyType);
					bundle.putString("sitekey", sitekey);
					bundle.putBoolean("isGlobalProxy", isGlobalProxy);
					bundle.putBoolean("isHTTPSProxy", isHTTPSProxy);
					bundle.putBoolean("isGFWList", isGFWList);

					it.putExtras(bundle);
					context.startService(it);
				} else {
					try {
						Thread.sleep(500);
					} catch (InterruptedException ignore) {
						// Nothing
					}
					try {
						views.setImageViewResource(R.id.serviceToggle, R.drawable.off);

						AppWidgetManager awm = AppWidgetManager.getInstance(context);
						awm.updateAppWidget(awm.getAppWidgetIds(new ComponentName(context,
								GAEProxyWidgetProvider.class)), views);
					} catch (Exception ignore) {
						// Nothing
					}
				}

			}

		}
	}

	@Override
	public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
		final int N = appWidgetIds.length;

		// Perform this loop procedure for each App Widget that belongs to this
		// provider
		for (int i = 0; i < N; i++) {
			int appWidgetId = appWidgetIds[i];

			// Create an Intent to launch ExampleActivity
			Intent intent = new Intent(context, GAEProxyWidgetProvider.class);
			intent.setAction(PROXY_SWITCH_ACTION);
			PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, intent, 0);

			// Get the layout for the App Widget and attach an on-click listener
			// to the button
			RemoteViews views = new RemoteViews(context.getPackageName(),
					R.layout.gaeproxy_appwidget);
			views.setOnClickPendingIntent(R.id.serviceToggle, pendingIntent);

			if (GAEProxyService.isServiceStarted()) {
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
}
