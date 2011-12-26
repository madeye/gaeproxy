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

package org.gaeproxy.zirco.model.adapters;

import org.gaeproxy.R;
import org.gaeproxy.zirco.providers.WeaveColumns;

import android.content.Context;
import android.database.Cursor;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;

public class WeaveBookmarksCursorAdapter extends SimpleCursorAdapter {

	public WeaveBookmarksCursorAdapter(Context context, int layout, Cursor c,
			String[] from, int[] to) {
		super(context, layout, c, from, to);
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
		View superView = super.getView(position, convertView, parent);

		Cursor c = getCursor();

		boolean isFolder = c.getInt(c
				.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_FOLDER)) > 0 ? true
				: false;

		ImageView iconView = (ImageView) superView
				.findViewById(R.id.BookmarkRow_Thumbnail);
		TextView urlView = (TextView) superView
				.findViewById(R.id.BookmarkRow_Url);

		if (isFolder) {
			urlView.setVisibility(View.GONE);
			iconView.setImageResource(R.drawable.folder_icon);
		} else {
			urlView.setVisibility(View.VISIBLE);
			iconView.setImageResource(R.drawable.fav_icn_default);
		}

		return superView;
	}

}
