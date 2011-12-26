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

package org.gaeproxy.zirco.model.items;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

/**
 * Represent an history element.
 */
public class HistoryItem {

	private long mId;
	private String mTitle;
	private String mUrl;
	private Bitmap mFavicon;

	/**
	 * Constructor.
	 * 
	 * @param id
	 *            The element id.
	 * @param title
	 *            The title.
	 * @param url
	 *            The url.
	 * @param faviconData
	 *            The favicon.
	 */
	public HistoryItem(long id, String title, String url, byte[] faviconData) {
		mId = id;
		mTitle = title;
		mUrl = url;
		if (faviconData != null) {
			mFavicon = BitmapFactory.decodeByteArray(faviconData, 0,
					faviconData.length);
		} else {
			mFavicon = null;
		}
	}

	/**
	 * Get the favicon.
	 * 
	 * @return The favicon.
	 */
	public Bitmap getFavicon() {
		return mFavicon;
	}

	/**
	 * Get the id.
	 * 
	 * @return The id.
	 */
	public long getId() {
		return mId;
	}

	/**
	 * Get the title.
	 * 
	 * @return The title.
	 */
	public String getTitle() {
		return mTitle;
	}

	/**
	 * Get the url.
	 * 
	 * @return The url.
	 */
	public String getUrl() {
		return mUrl;
	}

}
