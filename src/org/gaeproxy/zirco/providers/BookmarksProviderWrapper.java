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

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.gaeproxy.zirco.model.UrlSuggestionItemComparator;
import org.gaeproxy.zirco.model.adapters.UrlSuggestionCursorAdapter;
import org.gaeproxy.zirco.model.items.BookmarkItem;
import org.gaeproxy.zirco.model.items.HistoryItem;
import org.gaeproxy.zirco.model.items.UrlSuggestionItem;
import org.gaeproxy.zirco.model.items.WeaveBookmarkItem;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.provider.BaseColumns;
import android.provider.Browser;
import android.util.Log;

public class BookmarksProviderWrapper {

	private static String[] sHistoryBookmarksProjection = new String[] {
			Browser.BookmarkColumns._ID, Browser.BookmarkColumns.TITLE,
			Browser.BookmarkColumns.URL, Browser.BookmarkColumns.VISITS,
			Browser.BookmarkColumns.DATE, Browser.BookmarkColumns.CREATED,
			Browser.BookmarkColumns.BOOKMARK, Browser.BookmarkColumns.FAVICON };

	/**
	 * Clear the history/bookmarks table.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param clearHistory
	 *            If true, history items will be cleared.
	 * @param clearBookmarks
	 *            If true, bookmarked items will be cleared.
	 */
	public static void clearHistoryAndOrBookmarks(
			ContentResolver contentResolver, boolean clearHistory,
			boolean clearBookmarks) {

		if (!clearHistory && !clearBookmarks) {
			return;
		}

		String whereClause = null;
		if (clearHistory && clearBookmarks) {
			whereClause = null;
		} else if (clearHistory) {
			whereClause = "(" + Browser.BookmarkColumns.BOOKMARK + " = 0) OR ("
					+ Browser.BookmarkColumns.BOOKMARK + " IS NULL)";
		} else if (clearBookmarks) {
			whereClause = Browser.BookmarkColumns.BOOKMARK + " = 1";
		}

		contentResolver.delete(Browser.BOOKMARKS_URI, whereClause, null);
	}

	public static void clearWeaveBookmarks(ContentResolver contentResolver) {
		contentResolver.delete(WeaveColumns.CONTENT_URI, null, null);
	}

	/**
	 * Delete an history record, e.g. reset the visited count and visited date
	 * if its a bookmark, or delete it if not.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param id
	 *            The history id.
	 */
	public static void deleteHistoryRecord(ContentResolver contentResolver,
			long id) {
		String whereClause = BaseColumns._ID + " = " + id;

		Cursor cursor = contentResolver.query(
				android.provider.Browser.BOOKMARKS_URI,
				sHistoryBookmarksProjection, whereClause, null, null);
		if (cursor != null) {
			if (cursor.moveToFirst()) {
				if (cursor.getInt(cursor
						.getColumnIndex(Browser.BookmarkColumns.BOOKMARK)) == 1) {
					// The record is a bookmark, so we cannot delete it.
					// Instead, reset its visited count and last visited date.
					ContentValues values = new ContentValues();
					values.put(Browser.BookmarkColumns.VISITS, 0);
					values.putNull(Browser.BookmarkColumns.DATE);

					contentResolver.update(Browser.BOOKMARKS_URI, values,
							whereClause, null);
				} else {
					// The record is not a bookmark, we can delete it.
					contentResolver.delete(Browser.BOOKMARKS_URI, whereClause,
							null);
				}
			}

			cursor.close();
		}
	}

	public static void deleteStockBookmark(ContentResolver contentResolver,
			long id) {
		String whereClause = BaseColumns._ID + " = " + id;

		Cursor c = contentResolver.query(Browser.BOOKMARKS_URI,
				sHistoryBookmarksProjection, whereClause, null, null);
		if (c != null) {
			if (c.moveToFirst()) {
				if (c.getInt(c.getColumnIndex(Browser.BookmarkColumns.BOOKMARK)) == 1) {
					if (c.getInt(c
							.getColumnIndex(Browser.BookmarkColumns.VISITS)) > 0) {

						// If this record has been visited, keep it in history,
						// but remove its bookmark flag.
						ContentValues values = new ContentValues();
						values.put(Browser.BookmarkColumns.BOOKMARK, 0);
						values.putNull(Browser.BookmarkColumns.CREATED);

						contentResolver.update(Browser.BOOKMARKS_URI, values,
								whereClause, null);

					} else {
						// never visited, it can be deleted.
						contentResolver.delete(Browser.BOOKMARKS_URI,
								whereClause, null);
					}
				}
			}

			c.close();
		}
	}

	public static void deleteWeaveBookmarkByWeaveId(
			ContentResolver contentResolver, String weaveId) {
		String whereClause = WeaveColumns.WEAVE_BOOKMARKS_WEAVE_ID + " = \""
				+ weaveId + "\"";
		contentResolver.delete(WeaveColumns.CONTENT_URI, whereClause, null);
	}

	/**
	 * Stock History/Bookmarks management.
	 */
	/**
	 * Get a Cursor on the whole content of the history/bookmarks database.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @return A Cursor.
	 * @see Cursor
	 */
	public static Cursor getAllStockRecords(ContentResolver contentResolver) {
		return contentResolver.query(Browser.BOOKMARKS_URI,
				sHistoryBookmarksProjection, null, null, null);
	}

	public static BookmarkItem getStockBookmarkById(
			ContentResolver contentResolver, long id) {
		BookmarkItem result = null;
		String whereClause = BaseColumns._ID + " = " + id;

		Cursor c = contentResolver.query(Browser.BOOKMARKS_URI,
				sHistoryBookmarksProjection, whereClause, null, null);
		if (c != null) {
			if (c.moveToFirst()) {
				String title = c.getString(c
						.getColumnIndex(Browser.BookmarkColumns.TITLE));
				String url = c.getString(c
						.getColumnIndex(Browser.BookmarkColumns.URL));
				result = new BookmarkItem(title, url);
			}

			c.close();
		}

		return result;
	}

	public static Cursor getStockBookmarks(ContentResolver contentResolver,
			int sortMode) {
		String whereClause = Browser.BookmarkColumns.BOOKMARK + " = 1";

		String orderClause;
		switch (sortMode) {
		case 0:
			orderClause = Browser.BookmarkColumns.VISITS + " DESC, "
					+ Browser.BookmarkColumns.TITLE + " COLLATE NOCASE";
			break;
		case 1:
			orderClause = Browser.BookmarkColumns.TITLE + " COLLATE NOCASE";
			break;
		case 2:
			orderClause = Browser.BookmarkColumns.CREATED + " DESC";
			break;
		default:
			orderClause = Browser.BookmarkColumns.TITLE + " COLLATE NOCASE";
			break;
		}

		return contentResolver.query(Browser.BOOKMARKS_URI,
				sHistoryBookmarksProjection, whereClause, null, orderClause);
	}

	/**
	 * Get a list of most visited bookmarks items, limited in size.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param limit
	 *            The size limit.
	 * @return A list of BookmarkItem.
	 */
	public static List<BookmarkItem> getStockBookmarksWithLimit(
			ContentResolver contentResolver, int limit) {
		List<BookmarkItem> result = new ArrayList<BookmarkItem>();

		String whereClause = Browser.BookmarkColumns.BOOKMARK + " = 1";
		String orderClause = Browser.BookmarkColumns.VISITS + " DESC";
		String[] colums = new String[] { BaseColumns._ID,
				Browser.BookmarkColumns.TITLE, Browser.BookmarkColumns.URL,
				Browser.BookmarkColumns.FAVICON };

		Cursor cursor = contentResolver.query(
				android.provider.Browser.BOOKMARKS_URI, colums, whereClause,
				null, orderClause);

		if (cursor != null) {
			if (cursor.moveToFirst()) {

				int columnTitle = cursor
						.getColumnIndex(Browser.BookmarkColumns.TITLE);
				int columnUrl = cursor
						.getColumnIndex(Browser.BookmarkColumns.URL);

				int count = 0;
				while (!cursor.isAfterLast() && (count < limit)) {

					BookmarkItem item = new BookmarkItem(
							cursor.getString(columnTitle),
							cursor.getString(columnUrl));

					result.add(item);

					count++;
					cursor.moveToNext();
				}
			}

			cursor.close();
		}

		return result;
	}

	public static Cursor getStockHistory(ContentResolver contentResolver) {
		String whereClause = Browser.BookmarkColumns.VISITS + " > 0";
		String orderClause = Browser.BookmarkColumns.DATE + " DESC";

		return contentResolver.query(Browser.BOOKMARKS_URI,
				Browser.HISTORY_PROJECTION, whereClause, null, orderClause);
	}

	/**
	 * Get a list of most recent history items, limited in size.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param limit
	 *            The size limit.
	 * @return A list of HistoryItem.
	 */
	public static List<HistoryItem> getStockHistoryWithLimit(
			ContentResolver contentResolver, int limit) {
		List<HistoryItem> result = new ArrayList<HistoryItem>();

		String whereClause = Browser.BookmarkColumns.VISITS + " > 0";
		String orderClause = Browser.BookmarkColumns.DATE + " DESC";

		Cursor cursor = contentResolver.query(
				android.provider.Browser.BOOKMARKS_URI,
				Browser.HISTORY_PROJECTION, whereClause, null, orderClause);

		if (cursor != null) {
			if (cursor.moveToFirst()) {

				int columnId = cursor.getColumnIndex(BaseColumns._ID);
				int columnTitle = cursor
						.getColumnIndex(Browser.BookmarkColumns.TITLE);
				int columnUrl = cursor
						.getColumnIndex(Browser.BookmarkColumns.URL);

				int count = 0;
				while (!cursor.isAfterLast() && (count < limit)) {

					HistoryItem item = new HistoryItem(
							cursor.getLong(columnId),
							cursor.getString(columnTitle),
							cursor.getString(columnUrl), null);

					result.add(item);

					count++;
					cursor.moveToNext();
				}
			}

			cursor.close();
		}

		return result;
	}

	/**
	 * Suggestions.
	 */
	/**
	 * Get a cursor for suggestions, given a search pattern. Search on history
	 * and bookmarks, on title and url. The result list is sorted based on each
	 * result note.
	 * 
	 * @see UrlSuggestionItem for how a note is computed.
	 * @param contentResolver
	 *            The content resolver.
	 * @param pattern
	 *            The pattern to search for.
	 * @param lookInWeaveBookmarks
	 *            If true, suggestions will include bookmarks from weave.
	 * @return A cursor of suggections.
	 */
	public static Cursor getUrlSuggestions(ContentResolver contentResolver,
			String pattern, boolean lookInWeaveBookmarks) {
		MatrixCursor cursor = new MatrixCursor(new String[] {
				UrlSuggestionCursorAdapter.URL_SUGGESTION_ID,
				UrlSuggestionCursorAdapter.URL_SUGGESTION_TITLE,
				UrlSuggestionCursorAdapter.URL_SUGGESTION_URL,
				UrlSuggestionCursorAdapter.URL_SUGGESTION_TYPE });

		if ((pattern != null) && (pattern.length() > 0)) {

			String sqlPattern = "%" + pattern + "%";

			List<UrlSuggestionItem> results = new ArrayList<UrlSuggestionItem>();

			Cursor stockCursor = contentResolver.query(Browser.BOOKMARKS_URI,
					sHistoryBookmarksProjection, Browser.BookmarkColumns.TITLE
							+ " LIKE '" + sqlPattern + "' OR "
							+ Browser.BookmarkColumns.URL + " LIKE '"
							+ sqlPattern + "'", null, null);

			if (stockCursor != null) {
				if (stockCursor.moveToFirst()) {
					int titleId = stockCursor
							.getColumnIndex(Browser.BookmarkColumns.TITLE);
					int urlId = stockCursor
							.getColumnIndex(Browser.BookmarkColumns.URL);
					int bookmarkId = stockCursor
							.getColumnIndex(Browser.BookmarkColumns.BOOKMARK);

					do {
						boolean isFolder = stockCursor.getInt(bookmarkId) > 0 ? true
								: false;
						results.add(new UrlSuggestionItem(pattern, stockCursor
								.getString(titleId), stockCursor
								.getString(urlId), isFolder ? 2 : 1));

					} while (stockCursor.moveToNext());
				}

				stockCursor.close();
			}

			if (lookInWeaveBookmarks) {
				Cursor weaveCursor = contentResolver.query(
						WeaveColumns.CONTENT_URI, null,
						WeaveColumns.WEAVE_BOOKMARKS_FOLDER + " = 0 AND ("
								+ WeaveColumns.WEAVE_BOOKMARKS_TITLE
								+ " LIKE '" + sqlPattern + "' OR "
								+ WeaveColumns.WEAVE_BOOKMARKS_URL + " LIKE '"
								+ sqlPattern + "')", null, null);

				if (weaveCursor != null) {
					if (weaveCursor.moveToFirst()) {

						int weaveTitleId = weaveCursor
								.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_TITLE);
						int weaveUrlId = weaveCursor
								.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_URL);

						do {
							results.add(new UrlSuggestionItem(pattern,
									weaveCursor.getString(weaveTitleId),
									weaveCursor.getString(weaveUrlId), 3));
						} while (weaveCursor.moveToNext());
					}

					weaveCursor.close();
				}
			}

			// Sort results.
			Collections.sort(results, new UrlSuggestionItemComparator());

			// Log.d("Results", Integer.toString(results.size()));

			// Copy results to the output MatrixCursor.
			int idCounter = -1;
			for (UrlSuggestionItem item : results) {
				idCounter++;

				String[] row = new String[4];
				row[0] = Integer.toString(idCounter);
				row[1] = item.getTitle();
				row[2] = item.getUrl();
				row[3] = Integer.toString(item.getType());

				cursor.addRow(row);
			}
		}

		return cursor;
	}

	public static WeaveBookmarkItem getWeaveBookmarkById(
			ContentResolver contentResolver, long id) {
		WeaveBookmarkItem result = null;

		Uri uri = ContentUris.withAppendedId(WeaveColumns.CONTENT_URI, id);
		Cursor c = contentResolver.query(uri, null, null, null, null);

		if (c != null) {
			if (c.moveToFirst()) {
				String title = c.getString(c
						.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_TITLE));
				String url = c.getString(c
						.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_URL));
				String weaveId = c.getString(c
						.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_WEAVE_ID));
				boolean isFolder = c.getInt(c
						.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_FOLDER)) > 0 ? true
						: false;

				result = new WeaveBookmarkItem(title, url, weaveId, isFolder);
			}

			c.close();
		}

		return result;
	}

	public static long getWeaveBookmarkIdByWeaveId(
			ContentResolver contentResolver, String weaveId) {
		long result = -1;
		String whereClause = WeaveColumns.WEAVE_BOOKMARKS_WEAVE_ID + " = \""
				+ weaveId + "\"";

		Cursor c = contentResolver.query(WeaveColumns.CONTENT_URI, null,
				whereClause, null, null);
		if (c != null) {
			if (c.moveToFirst()) {
				result = c.getLong(c
						.getColumnIndex(WeaveColumns.WEAVE_BOOKMARKS_ID));
			}

			c.close();
		}

		return result;
	}

	/**
	 * Weave bookmarks management.
	 */

	public static Cursor getWeaveBookmarksByParentId(
			ContentResolver contentResolver, String parentId) {
		String whereClause = WeaveColumns.WEAVE_BOOKMARKS_WEAVE_PARENT_ID
				+ " = \"" + parentId + "\"";
		String orderClause = WeaveColumns.WEAVE_BOOKMARKS_FOLDER + " DESC, "
				+ WeaveColumns.WEAVE_BOOKMARKS_TITLE + " COLLATE NOCASE";

		return contentResolver.query(WeaveColumns.CONTENT_URI,
				WeaveColumns.WEAVE_BOOKMARKS_PROJECTION, whereClause, null,
				orderClause);
	}

	/**
	 * Insert a full record in history/bookmarks database.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param title
	 *            The record title.
	 * @param url
	 *            The record url.
	 * @param visits
	 *            The record visit count.
	 * @param date
	 *            The record last visit date.
	 * @param created
	 *            The record bookmark creation date.
	 * @param bookmark
	 *            The bookmark flag.
	 */
	public static void insertRawRecord(ContentResolver contentResolver,
			String title, String url, int visits, long date, long created,
			int bookmark) {
		ContentValues values = new ContentValues();
		values.put(Browser.BookmarkColumns.TITLE, title);
		values.put(Browser.BookmarkColumns.URL, url);
		values.put(Browser.BookmarkColumns.VISITS, visits);

		if (date > 0) {
			values.put(Browser.BookmarkColumns.DATE, date);
		} else {
			values.putNull(Browser.BookmarkColumns.DATE);
		}

		if (created > 0) {
			values.put(Browser.BookmarkColumns.CREATED, created);
		} else {
			values.putNull(Browser.BookmarkColumns.CREATED);
		}

		if (bookmark > 0) {
			values.put(Browser.BookmarkColumns.BOOKMARK, 1);
		} else {
			values.put(Browser.BookmarkColumns.BOOKMARK, 0);
		}

		contentResolver.insert(Browser.BOOKMARKS_URI, values);
	}

	public static void insertWeaveBookmark(ContentResolver contentResolver,
			ContentValues values) {
		contentResolver.insert(WeaveColumns.CONTENT_URI, values);
	}

	/**
	 * Modify a bookmark/history record. If an id is provided, it look for it
	 * and update its values. If not, values will be inserted. If no id is
	 * provided, it look for a record with the given url. It found, its values
	 * are updated. If not, values will be inserted.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param id
	 *            The record id to look for.
	 * @param title
	 *            The record title.
	 * @param url
	 *            The record url.
	 * @param isBookmark
	 *            If True, the record will be a bookmark.
	 */
	public static void setAsBookmark(ContentResolver contentResolver, long id,
			String title, String url, boolean isBookmark) {

		boolean bookmarkExist = false;

		if (id != -1) {
			String[] colums = new String[] { BaseColumns._ID };
			String whereClause = BaseColumns._ID + " = " + id;

			Cursor cursor = contentResolver.query(
					android.provider.Browser.BOOKMARKS_URI, colums,
					whereClause, null, null);
			bookmarkExist = (cursor != null) && (cursor.moveToFirst());
		} else {
			String[] colums = new String[] { BaseColumns._ID };
			String whereClause = Browser.BookmarkColumns.URL + " = \"" + url
					+ "\"";

			Cursor cursor = contentResolver.query(
					android.provider.Browser.BOOKMARKS_URI, colums,
					whereClause, null, null);
			bookmarkExist = (cursor != null) && (cursor.moveToFirst());
			if (bookmarkExist) {
				id = cursor.getLong(cursor.getColumnIndex(BaseColumns._ID));
			}
		}

		ContentValues values = new ContentValues();
		if (title != null) {
			values.put(Browser.BookmarkColumns.TITLE, title);
		}

		if (url != null) {
			values.put(Browser.BookmarkColumns.URL, url);
		}

		if (isBookmark) {
			values.put(Browser.BookmarkColumns.BOOKMARK, 1);
			values.put(Browser.BookmarkColumns.CREATED, new Date().getTime());
		} else {
			values.put(Browser.BookmarkColumns.BOOKMARK, 0);
		}

		if (bookmarkExist) {
			contentResolver.update(android.provider.Browser.BOOKMARKS_URI,
					values, BaseColumns._ID + " = " + id, null);
		} else {
			contentResolver.insert(android.provider.Browser.BOOKMARKS_URI,
					values);
		}
	}

	/**
	 * Remove from history values prior to now minus the number of days defined
	 * in preferences. Only delete history items, not bookmarks.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 */
	public static void truncateHistory(ContentResolver contentResolver,
			String prefHistorySize) {
		int historySize;
		try {
			historySize = Integer.parseInt(prefHistorySize);
		} catch (NumberFormatException e) {
			historySize = 90;
		}

		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		c.add(Calendar.DAY_OF_YEAR, -historySize);

		String whereClause = "(" + Browser.BookmarkColumns.BOOKMARK
				+ " = 0 OR " + Browser.BookmarkColumns.BOOKMARK
				+ " IS NULL) AND " + Browser.BookmarkColumns.DATE + " < "
				+ c.getTimeInMillis();

		try {
			contentResolver.delete(Browser.BOOKMARKS_URI, whereClause, null);
		} catch (Exception e) {
			e.printStackTrace();
			Log.w("BookmarksProviderWrapper", "Unable to truncate history: "
					+ e.getMessage());
		}
	}

	/**
	 * Update the favicon in history/bookmarks database.
	 * 
	 * @param currentActivity
	 *            The current acitivity.
	 * @param url
	 *            The url.
	 * @param originalUrl
	 *            The original url.
	 * @param favicon
	 *            The favicon.
	 */
	public static void updateFavicon(Activity currentActivity, String url,
			String originalUrl, Bitmap favicon) {
		String whereClause;

		if (!url.equals(originalUrl)) {
			whereClause = Browser.BookmarkColumns.URL + " = \"" + url
					+ "\" OR " + Browser.BookmarkColumns.URL + " = \""
					+ originalUrl + "\"";
		} else {
			whereClause = Browser.BookmarkColumns.URL + " = \"" + url + "\"";
		}

		// BitmapDrawable icon =
		// ApplicationUtils.getNormalizedFaviconForBookmarks(currentActivity,
		// favicon);
		BitmapDrawable icon = new BitmapDrawable(favicon);

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		icon.getBitmap().compress(Bitmap.CompressFormat.PNG, 100, os);

		ContentValues values = new ContentValues();
		values.put(Browser.BookmarkColumns.FAVICON, os.toByteArray());

		try {
			currentActivity.getContentResolver().update(
					android.provider.Browser.BOOKMARKS_URI, values,
					whereClause, null);
		} catch (Exception e) {
			e.printStackTrace();
			Log.w("BookmarksProviderWrapper",
					"Unable to update favicon: " + e.getMessage());
		}
	}

	/**
	 * Update the history: visit count and last visited date.
	 * 
	 * @param contentResolver
	 *            The content resolver.
	 * @param title
	 *            The title.
	 * @param url
	 *            The url.
	 * @param originalUrl
	 *            The original url
	 */
	public static void updateHistory(ContentResolver contentResolver,
			String title, String url, String originalUrl) {
		String[] colums = new String[] { BaseColumns._ID,
				Browser.BookmarkColumns.URL, Browser.BookmarkColumns.BOOKMARK,
				Browser.BookmarkColumns.VISITS };
		String whereClause = Browser.BookmarkColumns.URL + " = \"" + url
				+ "\" OR " + Browser.BookmarkColumns.URL + " = \""
				+ originalUrl + "\"";

		Cursor cursor = contentResolver.query(Browser.BOOKMARKS_URI, colums,
				whereClause, null, null);

		if (cursor != null) {
			if (cursor.moveToFirst()) {

				long id = cursor
						.getLong(cursor.getColumnIndex(BaseColumns._ID));
				int visits = cursor.getInt(cursor
						.getColumnIndex(Browser.BookmarkColumns.VISITS)) + 1;

				ContentValues values = new ContentValues();

				// If its not a bookmark, we can update the title. If we were
				// doing it on bookmarks, we would override the title choosen by
				// the user.
				if (cursor.getInt(cursor
						.getColumnIndex(Browser.BookmarkColumns.BOOKMARK)) != 1) {
					values.put(Browser.BookmarkColumns.TITLE, title);
				}

				values.put(Browser.BookmarkColumns.DATE, new Date().getTime());
				values.put(Browser.BookmarkColumns.VISITS, visits);

				contentResolver.update(android.provider.Browser.BOOKMARKS_URI,
						values, BaseColumns._ID + " = " + id, null);

			} else {
				ContentValues values = new ContentValues();
				values.put(Browser.BookmarkColumns.TITLE, title);
				values.put(Browser.BookmarkColumns.URL, url);
				values.put(Browser.BookmarkColumns.DATE, new Date().getTime());
				values.put(Browser.BookmarkColumns.VISITS, 1);
				values.put(Browser.BookmarkColumns.BOOKMARK, 0);

				contentResolver.insert(android.provider.Browser.BOOKMARKS_URI,
						values);
			}

			cursor.close();
		}
	}

	public static void updateWeaveBookmark(ContentResolver contentResolver,
			long id, ContentValues values) {
		String whereClause = WeaveColumns.WEAVE_BOOKMARKS_ID + " = " + id;
		contentResolver.update(WeaveColumns.CONTENT_URI, values, whereClause,
				null);

	}

}
