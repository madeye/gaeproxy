/*
 * Zirco Browser for Android
 * 
 * Copyright (C) 2010 - 2011 J. Devauchelle and contributors.
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

package org.gaeproxy.zirco.providers;

import android.net.Uri;
import android.provider.BaseColumns;

public class WeaveColumns implements BaseColumns {

	public static final Uri CONTENT_URI = Uri.parse("content://"
			+ WeaveContentProvider.AUTHORITY + "/"
			+ WeaveContentProvider.WEAVE_BOOKMARKS_TABLE);

	public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.zirco.weave";

	public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.zirco.weave";
	public static final String WEAVE_BOOKMARKS_ID = "_id";

	public static final String WEAVE_BOOKMARKS_WEAVE_ID = "weave_id";
	public static final String WEAVE_BOOKMARKS_WEAVE_PARENT_ID = "weave_parent_id";
	public static final String WEAVE_BOOKMARKS_TITLE = "title";
	public static final String WEAVE_BOOKMARKS_URL = "url";
	public static final String WEAVE_BOOKMARKS_FOLDER = "folder";
	public static final String[] WEAVE_BOOKMARKS_PROJECTION = {
			WEAVE_BOOKMARKS_ID, WEAVE_BOOKMARKS_WEAVE_ID,
			WEAVE_BOOKMARKS_WEAVE_PARENT_ID, WEAVE_BOOKMARKS_TITLE,
			WEAVE_BOOKMARKS_URL, WEAVE_BOOKMARKS_FOLDER };

	private WeaveColumns() {
	}
}
