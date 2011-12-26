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

package org.gaeproxy.zirco.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.gaeproxy.zirco.ui.runnables.XmlHistoryBookmarksExporter;
import org.gaeproxy.zirco.utils.ApplicationUtils;
import org.gaeproxy.zirco.utils.DateUtils;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.Browser;
import android.util.Log;

/**
 * Implementation of the database adapter.
 */
public class DbAdapter {

	/**
	 * DatabaseHelper.
	 */
	private static class DatabaseHelper extends SQLiteOpenHelper {

		private DbAdapter mParent;

		/**
		 * Constructor.
		 * 
		 * @param context
		 *            The current context.
		 * @param parent
		 *            The DbAdapter parent.
		 */
		public DatabaseHelper(Context context, DbAdapter parent) {
			super(context, DATABASE_NAME, null, DATABASE_VERSION);
			mParent = parent;
		}

		/**
		 * Export bookmarks from the old database. Transform the query result
		 * into a MatrixCursor following the stock bookmarks database, so it can
		 * be exported with the XmlHistoryBookmarksExporter without any change
		 * on it.
		 * 
		 * @param db
		 *            The database.
		 */
		private void exportOldBookmarks(SQLiteDatabase db) {

			Log.i("DbAdapter", "Start export of old bookmarks.");

			try {
				if (ApplicationUtils.checkCardState(mParent.mContext, false)) {

					Log.i("DbAdapter",
							"Export of old bookmarks: SDCard checked.");

					MatrixCursor cursor = null;

					Cursor c = db.query("BOOKMARKS", new String[] { "_id",
							"title", "url", "creation_date", "count" }, null,
							null, null, null, null);

					if (c != null) {
						if (c.moveToFirst()) {

							cursor = new MatrixCursor(new String[] {
									Browser.BookmarkColumns.TITLE,
									Browser.BookmarkColumns.URL,
									Browser.BookmarkColumns.VISITS,
									Browser.BookmarkColumns.DATE,
									Browser.BookmarkColumns.CREATED,
									Browser.BookmarkColumns.BOOKMARK });

							int titleColumn = c.getColumnIndex("title");
							int urlColumn = c.getColumnIndex("url");
							int creationDateColumn = c
									.getColumnIndex("creation_date");
							int countColumn = c.getColumnIndex("count");

							while (!c.isAfterLast()) {

								Date date = DateUtils.convertFromDatabase(
										mParent.mContext,
										c.getString(creationDateColumn));

								Object[] data = new Object[6];
								data[0] = c.getString(titleColumn);
								data[1] = c.getString(urlColumn);
								data[2] = c.getInt(countColumn);
								data[3] = date.getTime();
								data[4] = date.getTime();
								data[5] = 1;

								cursor.addRow(data);

								c.moveToNext();
							}
						}

						c.close();
					}

					if (cursor != null) {
						Log.i("DbAdapter",
								"Export of old bookmarks: Writing file.");
						new Thread(new XmlHistoryBookmarksExporter(null,
								"auto-export.xml", cursor, null)).start();
					}
				}
			} catch (Exception e) {
				Log.i("DbAdapter",
						"Export of old bookmarks failed: " + e.getMessage());
			}

			Log.i("DbAdapter", "End of export of old bookmarks.");
		}

		@Override
		public void onCreate(SQLiteDatabase db) {
			// db.execSQL(BOOKMARKS_DATABASE_CREATE);
			// db.execSQL(HISTORY_DATABASE_CREATE);
			db.execSQL(ADBLOCK_WHITELIST_DATABASE_CREATE);
			db.execSQL(MOBILE_VIEW_DATABASE_CREATE);
			mParent.mAdBlockListNeedPopulate = true;
		}

		@Override
		public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {

			Log.d(TAG, "Upgrading database.");

			switch (oldVersion) {
			case 1: // db.execSQL("ALTER TABLE " + BOOKMARKS_DATABASE_TABLE +
					// " ADD " + BOOKMARKS_THUMBNAIL + " BLOB;");
			case 2: // db.execSQL("ALTER TABLE " + BOOKMARKS_DATABASE_TABLE +
					// " ADD " + BOOKMARKS_COUNT +
					// " INTEGER NOT NULL DEFAULT 0;");
			case 3:
				db.execSQL(ADBLOCK_WHITELIST_DATABASE_CREATE);
				mParent.mAdBlockListNeedPopulate = true;
			case 4:
				db.execSQL(MOBILE_VIEW_DATABASE_CREATE);
			case 5:
				// Export old bookmarks before dropping table.
				exportOldBookmarks(db);
				db.execSQL("DROP TABLE IF EXISTS BOOKMARKS;");
				db.execSQL("DROP TABLE IF EXISTS HISTORY;");
			default:
				break;
			}
		}

	}

	private static final String TAG = "DbAdapter";
	private static final String DATABASE_NAME = "ZIRCO";

	private static final int DATABASE_VERSION = 6;
	/**
	 * Adblock white list table.
	 */
	public static final String ADBLOCK_ROWID = "_id";

	public static final String ADBLOCK_URL = "url";

	private static final String ADBLOCK_WHITELIST_DATABASE_TABLE = "ADBLOCK_WHITELIST";

	private static final String ADBLOCK_WHITELIST_DATABASE_CREATE = "CREATE TABLE "
			+ ADBLOCK_WHITELIST_DATABASE_TABLE
			+ " ("
			+ ADBLOCK_ROWID
			+ " INTEGER PRIMARY KEY AUTOINCREMENT, "
			+ ADBLOCK_URL
			+ " TEXT NOT NULL);";
	/**
	 * Mobile view url table.
	 */
	public static final String MOBILE_VIEW_URL_ROWID = "_id";

	public static final String MOBILE_VIEW_URL_URL = "url";

	private static final String MOBILE_VIEW_DATABASE_TABLE = "MOBILE_VIEW_URL";

	private static final String MOBILE_VIEW_DATABASE_CREATE = "CREATE TABLE "
			+ MOBILE_VIEW_DATABASE_TABLE + " (" + MOBILE_VIEW_URL_ROWID
			+ " INTEGER PRIMARY KEY AUTOINCREMENT, " + MOBILE_VIEW_URL_URL
			+ " TEXT NOT NULL);";

	protected boolean mAdBlockListNeedPopulate = false;
	private DatabaseHelper mDbHelper;

	private SQLiteDatabase mDb;

	private final Context mContext;

	/**
	 * Constructor.
	 * 
	 * @param ctx
	 *            The current context.
	 */
	public DbAdapter(Context ctx) {
		this.mContext = ctx;
	}

	/**
	 * Clear the mobile view url list.
	 */
	public void clearMobileViewUrlList() {
		mDb.execSQL("DELETE FROM " + MOBILE_VIEW_DATABASE_TABLE + ";");
	}

	/**
	 * Delete all records from the white list.
	 */
	public void clearWhiteList() {
		mDb.execSQL("DELETE FROM " + ADBLOCK_WHITELIST_DATABASE_TABLE + ";");
	}

	/*******************************************************************************************************************************************************
	 * Adblock white list.
	 */

	/**
	 * Close the database helper.
	 */
	public void close() {
		mDbHelper.close();
	}

	/**
	 * Delete an url from the mobile view url list.
	 * 
	 * @param id
	 *            The id of the url to delete.
	 */
	public void deleteFromMobileViewUrlList(long id) {
		mDb.execSQL("DELETE FROM " + MOBILE_VIEW_DATABASE_TABLE + " WHERE "
				+ MOBILE_VIEW_URL_ROWID + " = " + id + ";");
	}

	/**
	 * Delete an item in white list given its id.
	 * 
	 * @param id
	 *            The id to delete.
	 */
	public void deleteFromWhiteList(long id) {
		mDb.execSQL("DELETE FROM " + ADBLOCK_WHITELIST_DATABASE_TABLE
				+ " WHERE " + ADBLOCK_ROWID + " = " + id + ";");
	}

	public SQLiteDatabase getDatabase() {
		return mDb;
	}

	/**
	 * Get a Cursor to the mobile view url list.
	 * 
	 * @return A Cursor to the mobile view url list.
	 */
	public Cursor getMobileViewUrlCursor() {
		return mDb.query(MOBILE_VIEW_DATABASE_TABLE, new String[] {
				MOBILE_VIEW_URL_ROWID, MOBILE_VIEW_URL_URL }, null, null, null,
				null, null);
	}

	/**
	 * Get an url from the mobile view list from its id.
	 * 
	 * @param rowId
	 *            The id.
	 * @return The url.
	 */
	public String getMobileViewUrlItemById(long rowId) {
		Cursor cursor = mDb.query(true, MOBILE_VIEW_DATABASE_TABLE,
				new String[] { MOBILE_VIEW_URL_ROWID, MOBILE_VIEW_URL_URL },
				MOBILE_VIEW_URL_ROWID + "=" + rowId, null, null, null, null,
				null);

		if (cursor.moveToFirst()) {

			String result;
			result = cursor.getString(cursor
					.getColumnIndex(MOBILE_VIEW_URL_URL));

			cursor.close();

			return result;

		} else {
			cursor.close();
			return null;
		}
	}

	/*******************************************************************************************************************************************************
	 * Mobile view list.
	 */

	/**
	 * Get a list of all urls in mobile view list.
	 * 
	 * @return A list of url.
	 */
	public List<String> getMobileViewUrlList() {
		List<String> result = new ArrayList<String>();

		Cursor cursor = getMobileViewUrlCursor();

		if (cursor.moveToFirst()) {
			do {

				result.add(cursor.getString(cursor
						.getColumnIndex(MOBILE_VIEW_URL_URL)));

			} while (cursor.moveToNext());
		}

		cursor.close();

		return result;
	}

	/**
	 * Get the list of url presents in white list.
	 * 
	 * @return The list of url presents in white list.
	 */
	public List<String> getWhiteList() {
		List<String> result = new ArrayList<String>();

		Cursor cursor = getWhiteListCursor();

		if (cursor.moveToFirst()) {
			do {

				result.add(cursor.getString(cursor.getColumnIndex(ADBLOCK_URL)));

			} while (cursor.moveToNext());
		}

		cursor.close();

		return result;
	}

	/**
	 * Get a cursor to the list of url presents in white list.
	 * 
	 * @return A cursor to the list of url presents in white list.
	 */
	public Cursor getWhiteListCursor() {
		return mDb.query(ADBLOCK_WHITELIST_DATABASE_TABLE, new String[] {
				ADBLOCK_ROWID, ADBLOCK_URL }, null, null, null, null, null);
	}

	/**
	 * Get the white list url given its id.
	 * 
	 * @param rowId
	 *            The id.
	 * @return The white list url.
	 */
	public String getWhiteListItemById(long rowId) {
		Cursor cursor = mDb.query(true, ADBLOCK_WHITELIST_DATABASE_TABLE,
				new String[] { ADBLOCK_ROWID, ADBLOCK_URL }, ADBLOCK_ROWID
						+ "=" + rowId, null, null, null, null, null);

		if (cursor.moveToFirst()) {

			String result;
			result = cursor.getString(cursor.getColumnIndex(ADBLOCK_URL));

			cursor.close();

			return result;

		} else {
			cursor.close();
			return null;
		}
	}

	/**
	 * Insert an url in the mobile view url list.
	 * 
	 * @param url
	 *            The new url.
	 */
	public void insertInMobileViewUrlList(String url) {
		ContentValues initialValues = new ContentValues();
		initialValues.put(MOBILE_VIEW_URL_URL, url);

		mDb.insert(MOBILE_VIEW_DATABASE_TABLE, null, initialValues);
	}

	/**
	 * Insert an item in the white list.
	 * 
	 * @param url
	 *            The url to insert.
	 */
	public void insertInWhiteList(String url) {
		ContentValues initialValues = new ContentValues();
		initialValues.put(ADBLOCK_URL, url);

		mDb.insert(ADBLOCK_WHITELIST_DATABASE_TABLE, null, initialValues);
	}

	/**
	 * Open the database helper.
	 * 
	 * @return The current database adapter.
	 */
	public DbAdapter open() {
		mDbHelper = new DatabaseHelper(mContext, this);
		mDb = mDbHelper.getWritableDatabase();

		if (mAdBlockListNeedPopulate) {
			populateDefaultWhiteList();
			mAdBlockListNeedPopulate = false;
		}

		return this;
	}

	/**
	 * Populate the white list with default values.
	 */
	private void populateDefaultWhiteList() {
		insertInWhiteList("google.com/reader");
	}

}
