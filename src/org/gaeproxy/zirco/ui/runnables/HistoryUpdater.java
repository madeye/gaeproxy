/*
 * Zirco Browser for Android
 * 
 * Copyright (C) 2010 J. Devauchelle and contributors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package org.gaeproxy.zirco.ui.runnables;

import org.gaeproxy.zirco.providers.BookmarksProviderWrapper;
import org.gaeproxy.zirco.utils.Constants;

import android.content.Context;
import android.preference.PreferenceManager;

/**
 * Runnable to update and truncate the history in background.
 */
public class HistoryUpdater implements Runnable {

	private Context mContext;
	private String mTitle;
	private String mUrl;
	private String mOriginalUrl;

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The current context.
	 * @param title
	 *            The title.
	 * @param url
	 *            The url.
	 */
	public HistoryUpdater(Context context, String title, String url,
			String originalUrl) {
		mContext = context;
		mTitle = title;
		mUrl = url;
		mOriginalUrl = originalUrl;

		if (mUrl.startsWith(Constants.URL_GOOGLE_MOBILE_VIEW_NO_FORMAT)) {
			mUrl = mUrl.substring(Constants.URL_GOOGLE_MOBILE_VIEW_NO_FORMAT
					.length());
		}
	}

	@Override
	public void run() {
		BookmarksProviderWrapper.updateHistory(mContext.getContentResolver(),
				mTitle, mUrl, mOriginalUrl);
		BookmarksProviderWrapper.truncateHistory(
				mContext.getContentResolver(),
				PreferenceManager.getDefaultSharedPreferences(mContext)
						.getString(Constants.PREFERENCES_BROWSER_HISTORY_SIZE,
								"90"));
	}

}
