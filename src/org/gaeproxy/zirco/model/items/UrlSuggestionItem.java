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

/**
 * Store a suggestion item.
 */
public class UrlSuggestionItem {

	private static final float TITLE_COEFFICIENT = 2;
	private static final float URL_COEFFICIENT = 1;

	private static final float BOOKMARK_COEFFICIENT = 3;
	private static final float WEAVE_COEFFICIENT = 1;
	private static final float HISTORY_COEFFICIENT = 1;

	private String mPattern;
	private String mTitle;
	private String mUrl;
	private int mType;

	private float mNote;
	private boolean mNoteComputed = false;

	/**
	 * Constructor.
	 * 
	 * @param pattern
	 *            The parent pattern.
	 * @param title
	 *            The item's title.
	 * @param url
	 *            The item's url.
	 * @param type
	 *            The item's type (1 -> history, 2 -> bookmark).
	 */
	public UrlSuggestionItem(String pattern, String title, String url, int type) {
		mPattern = pattern;
		mTitle = title;
		mUrl = url;
		mType = type;
	}

	/**
	 * Compute the note of the current item. The principle is to count the
	 * number of occurence of the pattern in the title and in the url, and to do
	 * a weighted sum. A match in title weight more than a match in url, and a
	 * match in bookmark weight more than a match in history.
	 */
	private void computeNote() {
		String pattern = mPattern.toLowerCase();

		// Count the number of match in a string, did not find a cleaner way.
		int titleMatchCount;
		String title = mTitle.toLowerCase();
		if (title.equals(pattern)) {
			titleMatchCount = 1;
		} else {
			titleMatchCount = title.split(pattern).length - 1;
		}

		String url = mUrl.toLowerCase();
		int urlMatchCount = url.split("\\Q" + pattern + "\\E").length - 1;

		mNote = (titleMatchCount * TITLE_COEFFICIENT)
				+ (urlMatchCount * URL_COEFFICIENT);

		switch (mType) {
		case 1:
			mNote = mNote * HISTORY_COEFFICIENT;
			break;
		case 2:
			mNote = mNote * BOOKMARK_COEFFICIENT;
			break;
		case 3:
			mNote = mNote * WEAVE_COEFFICIENT;
			break;
		default:
			break;
		}

	}

	/**
	 * Get the note of this item. Compute it if not already done.
	 * 
	 * @return The note.
	 */
	public float getNote() {
		if (!mNoteComputed) {
			computeNote();
			mNoteComputed = true;
		}
		return mNote;
	}

	/**
	 * Get the item's title.
	 * 
	 * @return The title.
	 */
	public String getTitle() {
		return mTitle;
	}

	/**
	 * Get the item's type.
	 * 
	 * @return The type.
	 */
	public int getType() {
		return mType;
	}

	/**
	 * Get the item's url.
	 * 
	 * @return The url.
	 */
	public String getUrl() {
		return mUrl;
	}

}
