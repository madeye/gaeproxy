package org.gaeproxy.zirco.sync;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.emergent.android.weave.client.QueryParams;
import org.emergent.android.weave.client.QueryResult;
import org.emergent.android.weave.client.UserWeave;
import org.emergent.android.weave.client.WeaveAccountInfo;
import org.emergent.android.weave.client.WeaveBasicObject;
import org.emergent.android.weave.client.WeaveException;
import org.emergent.android.weave.client.WeaveFactory;
import org.gaeproxy.zirco.providers.BookmarksProviderWrapper;
import org.gaeproxy.zirco.providers.WeaveColumns;
import org.gaeproxy.zirco.utils.Constants;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.os.AsyncTask;
import android.preference.PreferenceManager;

public class WeaveSyncTask extends
		AsyncTask<WeaveAccountInfo, Integer, Throwable> {

	private static final String WEAVE_PATH = "/storage/bookmarks";

	private static final String WEAVE_HEADER_TYPE = "type";

	private static final String WEAVE_VALUE_BOOKMARK = "bookmark";
	private static final String WEAVE_VALUE_FOLDER = "folder";
	private static final String WEAVE_VALUE_ITEM = "item";
	private static final String WEAVE_VALUE_ID = "id";
	private static final String WEAVE_VALUE_PARENT_ID = "parentid";
	private static final String WEAVE_VALUE_TITLE = "title";
	private static final String WEAVE_VALUE_URI = "bmkUri";
	private static final String WEAVE_VALUE_DELETED = "deleted";

	private static WeaveFactory mWeaveFactory = null;

	private static WeaveFactory getWeaveFactory() {
		if (mWeaveFactory == null) {
			mWeaveFactory = new WeaveFactory(true);
		}

		return mWeaveFactory;
	}

	private Context mContext;
	private ContentResolver mContentResolver;
	private ISyncListener mListener;

	private boolean mFullSync = false;

	public WeaveSyncTask(Context context, ISyncListener listener) {
		mContext = context;
		mContentResolver = context.getContentResolver();
		mListener = listener;
	}

	@Override
	protected Throwable doInBackground(WeaveAccountInfo... arg0) {
		Throwable result = null;

		try {
			publishProgress(0, 0, 0);

			WeaveAccountInfo accountInfo = arg0[0];
			UserWeave userWeave = getWeaveFactory().createUserWeave(
					accountInfo.getServer(), accountInfo.getUsername(),
					accountInfo.getPassword());

			long lastModifiedDate = getLastModified(userWeave).getTime();
			long lastSyncDate = PreferenceManager.getDefaultSharedPreferences(
					mContext).getLong(
					Constants.PREFERENCE_WEAVE_LAST_SYNC_DATE, -1);

			if (lastModifiedDate > lastSyncDate) {

				publishProgress(1, 0, 0);

				mFullSync = lastSyncDate <= 0;

				QueryResult<List<WeaveBasicObject>> queryResult;

				QueryParams parms = null;
				if (!mFullSync) {
					parms = new QueryParams();
					parms.setFull(false);
					parms.setNewer(new Date(lastSyncDate));
				} else {
					BookmarksProviderWrapper
							.clearWeaveBookmarks(mContentResolver);
				}

				queryResult = getCollection(userWeave, WEAVE_PATH, parms);
				List<WeaveBasicObject> wboList = queryResult.getValue();

				if (mFullSync) {
					doSync(accountInfo, userWeave, wboList);
				} else {
					doSyncByDelta(accountInfo, userWeave, wboList);
				}
			}

		} catch (WeaveException e) {
			e.printStackTrace();
			result = e;
		} catch (JSONException e) {
			e.printStackTrace();
			result = e;
		} catch (IOException e) {
			e.printStackTrace();
			result = e;
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			result = e;
		}

		return result;
	}

	private void doSync(WeaveAccountInfo accountInfo, UserWeave userWeave,
			List<WeaveBasicObject> wboList) throws WeaveException,
			JSONException, IOException, GeneralSecurityException {

		int i = 0;
		int count = wboList.size();

		List<ContentValues> values = new ArrayList<ContentValues>();

		mContext.getContentResolver().delete(WeaveColumns.CONTENT_URI, null,
				null);

		for (WeaveBasicObject wbo : wboList) {
			JSONObject decryptedPayload = wbo.getEncryptedPayload(userWeave,
					accountInfo.getSecret());

			i++;

			// if (i > 30) break;
			// Log.d("Decrypted:", decryptedPayload.toString());

			if (decryptedPayload.has(WEAVE_HEADER_TYPE)
					&& ((decryptedPayload.getString(WEAVE_HEADER_TYPE)
							.equals(WEAVE_VALUE_BOOKMARK)) || (decryptedPayload
							.getString(WEAVE_HEADER_TYPE)
							.equals(WEAVE_VALUE_FOLDER)))) {

				if (decryptedPayload.has(WEAVE_VALUE_TITLE)) {

					boolean isFolder = decryptedPayload.getString(
							WEAVE_HEADER_TYPE).equals(WEAVE_VALUE_FOLDER);

					String title = decryptedPayload
							.getString(WEAVE_VALUE_TITLE);
					String weaveId = decryptedPayload.has(WEAVE_VALUE_ID) ? decryptedPayload
							.getString(WEAVE_VALUE_ID) : null;
					String parentId = decryptedPayload
							.has(WEAVE_VALUE_PARENT_ID) ? decryptedPayload
							.getString(WEAVE_VALUE_PARENT_ID) : null;

					if ((title != null) && (title.length() > 0)) {

						ContentValues value = new ContentValues();
						value.put(WeaveColumns.WEAVE_BOOKMARKS_TITLE, title);
						value.put(WeaveColumns.WEAVE_BOOKMARKS_WEAVE_ID,
								weaveId);
						value.put(WeaveColumns.WEAVE_BOOKMARKS_WEAVE_PARENT_ID,
								parentId);

						if (isFolder) {
							value.put(WeaveColumns.WEAVE_BOOKMARKS_FOLDER, true);
						} else {
							String url = decryptedPayload
									.getString(WEAVE_VALUE_URI);

							value.put(WeaveColumns.WEAVE_BOOKMARKS_FOLDER,
									false);
							value.put(WeaveColumns.WEAVE_BOOKMARKS_URL, url);
						}

						values.add(value);
					}
				}
			}

			publishProgress(2, i, count);

			if (isCancelled()) {
				break;
			}
		}

		int j = 0;
		ContentValues[] valuesArray = new ContentValues[values.size()];
		for (ContentValues value : values) {
			valuesArray[j++] = value;
		}

		publishProgress(3, 0, 0);
		mContext.getContentResolver().bulkInsert(WeaveColumns.CONTENT_URI,
				valuesArray);
	}

	private void doSyncByDelta(WeaveAccountInfo accountInfo,
			UserWeave userWeave, List<WeaveBasicObject> wboList)
			throws WeaveException, JSONException, IOException,
			GeneralSecurityException {

		int i = 0;
		int count = wboList.size();

		for (WeaveBasicObject wbo : wboList) {
			JSONObject decryptedPayload = wbo.getEncryptedPayload(userWeave,
					accountInfo.getSecret());

			i++;

			if (decryptedPayload.has(WEAVE_HEADER_TYPE)) {

				if (decryptedPayload.getString(WEAVE_HEADER_TYPE).equals(
						WEAVE_VALUE_ITEM)
						&& decryptedPayload.has(WEAVE_VALUE_DELETED)
						&& decryptedPayload.getBoolean(WEAVE_VALUE_DELETED)) {

					String weaveId = decryptedPayload.has(WEAVE_VALUE_ID) ? decryptedPayload
							.getString(WEAVE_VALUE_ID) : null;
					if ((weaveId != null) && (weaveId.length() > 0)) {
						// mDbAdapter.deleteWeaveBookmarkByWeaveId(weaveId);
						BookmarksProviderWrapper.deleteWeaveBookmarkByWeaveId(
								mContentResolver, weaveId);
					}
				} else if (decryptedPayload.getString(WEAVE_HEADER_TYPE)
						.equals(WEAVE_VALUE_BOOKMARK)
						|| decryptedPayload.getString(WEAVE_HEADER_TYPE)
								.equals(WEAVE_VALUE_FOLDER)) {

					String weaveId = decryptedPayload.has(WEAVE_VALUE_ID) ? decryptedPayload
							.getString(WEAVE_VALUE_ID) : null;
					if ((weaveId != null) && (weaveId.length() > 0)) {

						boolean isFolder = decryptedPayload.getString(
								WEAVE_HEADER_TYPE).equals(WEAVE_VALUE_FOLDER);

						String title = decryptedPayload
								.getString(WEAVE_VALUE_TITLE);
						String parentId = decryptedPayload
								.has(WEAVE_VALUE_PARENT_ID) ? decryptedPayload
								.getString(WEAVE_VALUE_PARENT_ID) : null;

						ContentValues values = new ContentValues();
						values.put(WeaveColumns.WEAVE_BOOKMARKS_WEAVE_ID,
								weaveId);
						values.put(
								WeaveColumns.WEAVE_BOOKMARKS_WEAVE_PARENT_ID,
								parentId);
						values.put(WeaveColumns.WEAVE_BOOKMARKS_TITLE, title);

						if (isFolder) {
							values.put(WeaveColumns.WEAVE_BOOKMARKS_FOLDER,
									true);
						} else {
							String url = decryptedPayload
									.getString(WEAVE_VALUE_URI);

							values.put(WeaveColumns.WEAVE_BOOKMARKS_FOLDER,
									false);
							values.put(WeaveColumns.WEAVE_BOOKMARKS_URL, url);
						}

						long id = BookmarksProviderWrapper
								.getWeaveBookmarkIdByWeaveId(mContentResolver,
										weaveId);// mDbAdapter.getIdByWeaveId(weaveId);
						if (id == -1) {
							// Insert.
							BookmarksProviderWrapper.insertWeaveBookmark(
									mContentResolver, values);
						} else {
							// Update.
							BookmarksProviderWrapper.updateWeaveBookmark(
									mContentResolver, id, values);
						}

					}
				}
			}

			// Log.d("Decrypted:", decryptedPayload.toString());

			publishProgress(2, i, count);

			if (isCancelled()) {
				break;
			}
		}
	}

	private QueryResult<List<WeaveBasicObject>> getCollection(UserWeave weave,
			String name, QueryParams params) throws WeaveException {
		if (params == null)
			params = new QueryParams();
		URI uri = weave.buildSyncUriFromSubpath(name + params.toQueryString());
		return weave.getWboCollection(uri);
	}

	private Date getLastModified(UserWeave userWeave) throws WeaveException {
		try {
			JSONObject infoCol = userWeave.getNode(
					UserWeave.HashNode.INFO_COLLECTIONS).getValue();

			if (infoCol.has("bookmarks")) {
				long modLong = infoCol.getLong("bookmarks");
				return new Date(modLong * 1000);
			}

			return null;
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	public boolean isFullSync() {
		return mFullSync;
	}

	@Override
	protected void onCancelled() {
		mListener.onSyncCancelled();
		super.onCancelled();
	}

	@Override
	protected void onPostExecute(Throwable result) {
		mListener.onSyncEnd(result);
	}

	@Override
	protected void onProgressUpdate(Integer... values) {
		mListener.onSyncProgress(values[0], values[1], values[2]);
	}

}
