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

import java.util.ArrayList;
import java.util.List;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.util.Log;

public class APNManager {

	/**
	 * Selection of few interesting columns from APN table
	 */
	private static final class ApnInfo {

		final long id;
		final String apn;
		final String type;
		final String proxy;
		final String port;

		public ApnInfo(long id, String apn, String type, String proxy,
				String port) {
			this.id = id;
			this.apn = apn;
			this.type = type;
			this.proxy = proxy;
			this.port = port;
		}
	}
	private static final String ID = "_id";
	private static final String APN = "apn";
	private static final String TYPE = "type";
	private static final String PROXY = "proxy";
	private static final String PORT = "port";

	private static final String TAG = "GAEProxyAPNManager";

	private static final Uri CONTENT_URI = Uri
			.parse("content://telephony/carriers");

	public static void clearAPNProxy(String proxy, String port, Context context) {
		Cursor cursor = null;
		ContentResolver resolver = context.getContentResolver();
		List<ApnInfo> apns = null;
		try {
			cursor = resolver.query(CONTENT_URI, new String[] { ID, APN, TYPE,
					PROXY, PORT }, "proxy is not null", null, null);

			if (cursor == null)
				return;

			apns = createApnList(cursor);

		} catch (Exception ignore) {
			// Nothing
		}

		if (cursor != null) {
			cursor.close();
		}

		for (ApnInfo apnInfo : apns) {
			if (apnInfo.proxy.equals(proxy) && apnInfo.port.equals(port)) {
				ContentValues values = new ContentValues();

				values.put(PROXY, "");
				values.put(PORT, "");

				resolver.update(CONTENT_URI, values, ID + "=?",
						new String[] { String.valueOf(apnInfo.id) });
			}

		}
	}

	/**
	 * Creates list of apn dtos from a DB cursor
	 * 
	 * @param mCursor
	 *            db cursor with select result set
	 * @return list of APN dtos
	 */
	private static List<ApnInfo> createApnList(Cursor mCursor) {
		List<ApnInfo> result = new ArrayList<ApnInfo>();
		mCursor.moveToFirst();
		while (!mCursor.isAfterLast()) {
			long id = mCursor.getLong(0);
			String apn = mCursor.getString(1);
			String type = mCursor.getString(2);
			String proxy = mCursor.getString(3);
			String port = mCursor.getString(4);
			result.add(new ApnInfo(id, apn, type, proxy, port));
			mCursor.moveToNext();
		}
		return result;
	}

	public static boolean isCMWap(Context context) {
		ConnectivityManager manager = (ConnectivityManager) context
				.getSystemService(Context.CONNECTIVITY_SERVICE);
		NetworkInfo networkInfo = manager.getActiveNetworkInfo();
		if (networkInfo == null)
			return false;
		if (!networkInfo.getTypeName().equals("WIFI")) {
			Log.d(TAG, networkInfo.getExtraInfo());
			if (networkInfo.getExtraInfo() != null
					&& networkInfo.getExtraInfo().toLowerCase().equals("cmwap"))
				return true;
		}
		return false;
	}

	public static void setAPNProxy(String proxy, String port, Context context) {
		Cursor cursor = null;
		ContentResolver resolver = context.getContentResolver();
		List<ApnInfo> apns = null;
		try {
			cursor = resolver
					.query(CONTENT_URI,
							new String[] { ID, APN, TYPE, PROXY, PORT },
							"current is not null and (not lower(type)='mms' or type is null) and proxy is null",
							null, null);

			if (cursor == null)
				return;

			apns = createApnList(cursor);

		} catch (Exception ignore) {
			// Nothing
		}

		if (cursor != null) {
			cursor.close();
		}

		for (ApnInfo apnInfo : apns) {
			ContentValues values = new ContentValues();

			values.put(PROXY, proxy);
			values.put(PORT, port);

			resolver.update(CONTENT_URI, values, ID + "=?",
					new String[] { String.valueOf(apnInfo.id) });

		}

	}
}
