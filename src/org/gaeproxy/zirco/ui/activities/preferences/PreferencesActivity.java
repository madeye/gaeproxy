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

package org.gaeproxy.zirco.ui.activities.preferences;

import java.util.List;

import org.gaeproxy.R;
import org.gaeproxy.zirco.controllers.Controller;
import org.gaeproxy.zirco.providers.BookmarksProviderWrapper;
import org.gaeproxy.zirco.ui.activities.AboutActivity;
import org.gaeproxy.zirco.ui.activities.AdBlockerWhiteListActivity;
import org.gaeproxy.zirco.ui.activities.ChangelogActivity;
import org.gaeproxy.zirco.ui.activities.MainActivity;
import org.gaeproxy.zirco.ui.activities.MobileViewListActivity;
import org.gaeproxy.zirco.ui.components.CustomWebView;
import org.gaeproxy.zirco.ui.runnables.XmlHistoryBookmarksExporter;
import org.gaeproxy.zirco.ui.runnables.XmlHistoryBookmarksImporter;
import org.gaeproxy.zirco.utils.ApplicationUtils;
import org.gaeproxy.zirco.utils.Constants;
import org.gaeproxy.zirco.utils.DateUtils;
import org.gaeproxy.zirco.utils.IOUtils;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.Preference;
import android.preference.Preference.OnPreferenceClickListener;
import android.preference.PreferenceActivity;
import android.preference.PreferenceCategory;
import android.preference.PreferenceManager;
import android.webkit.CookieManager;

/**
 * Preferences activity.
 */
public class PreferencesActivity extends PreferenceActivity {

	/**
	 * Base class for all clear operations launched as Runnable.
	 */
	private abstract class AbstractClearer implements Runnable {

		protected Handler mHandler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				mProgressDialog.dismiss();
			}
		};

		/**
		 * Constructor. Launch itself as a Thread.
		 */
		public AbstractClearer() {
			new Thread(this).start();
		}
	}

	/**
	 * Cache clearer thread.
	 */
	private class CacheClearer implements Runnable {
		private Handler handler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				mProgressDialog.dismiss();
			}
		};

		/**
		 * Constructor.
		 */
		public CacheClearer() {
			new Thread(this).start();
		}

		@Override
		public void run() {
			// Only need to clear the cache from one WebView, as it is
			// application-based.
			CustomWebView webView = Controller.getInstance().getWebViewList()
					.get(0);
			webView.clearCache(true);

			handler.sendEmptyMessage(0);
		}
	}

	/**
	 * Cookies clearer thread.
	 */
	private class CookiesClearer implements Runnable {
		private Handler handler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				mProgressDialog.dismiss();
			}
		};

		/**
		 * Constructor.
		 */
		public CookiesClearer() {
			new Thread(this).start();
		}

		@Override
		public void run() {
			CookieManager.getInstance().removeAllCookie();
			handler.sendEmptyMessage(0);
		}
	}

	/**
	 * Form data clearer thread.
	 */
	private class FormDataClearer implements Runnable {
		private Handler handler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				mProgressDialog.dismiss();
			}
		};

		/**
		 * Constructor.
		 */
		public FormDataClearer() {
			new Thread(this).start();
		}

		@Override
		public void run() {
			for (CustomWebView webView : Controller.getInstance()
					.getWebViewList()) {
				webView.clearFormData();
			}

			handler.sendEmptyMessage(0);
		}
	}

	private class HistoryBookmarksClearer extends AbstractClearer {

		private int mChoice;

		public HistoryBookmarksClearer(int choice) {
			mChoice = choice;
		}

		@Override
		public void run() {

			switch (mChoice) {
			case 0:
				BookmarksProviderWrapper.clearHistoryAndOrBookmarks(
						PreferencesActivity.this.getContentResolver(), true,
						false);
				break;
			case 1:
				BookmarksProviderWrapper.clearHistoryAndOrBookmarks(
						PreferencesActivity.this.getContentResolver(), false,
						true);
				break;
			case 2:
				BookmarksProviderWrapper.clearHistoryAndOrBookmarks(
						PreferencesActivity.this.getContentResolver(), true,
						true);
				break;
			default:
				break;
			}

			mHandler.sendEmptyMessage(0);
		}
	}

	/**
	 * History clearer thread.
	 */
	private class HistoryClearer implements Runnable {

		private Handler handler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				mProgressDialog.dismiss();
			}
		};

		/**
		 * Constructor.
		 */
		public HistoryClearer() {
			new Thread(this).start();
		}

		@Override
		public void run() {
			// Clear DB History
			BookmarksProviderWrapper.clearHistoryAndOrBookmarks(
					getContentResolver(), true, false);

			// Clear WebViews history
			for (CustomWebView webView : Controller.getInstance()
					.getWebViewList()) {
				webView.clearHistory();
			}

			handler.sendEmptyMessage(0);
		}
	}

	private ProgressDialog mProgressDialog;

	private OnSharedPreferenceChangeListener mPreferenceChangeListener;

	/**
	 * Ask user to restart the app. Do it if click on "Yes".
	 */
	private void askForRestart() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_alert,
				R.string.PreferencesActivity_RestartDialogTitle,
				R.string.PreferencesActivity_RestartDialogMessage,
				new DialogInterface.OnClickListener() {

					@Override
					public void onClick(DialogInterface dialog, int which) {
						MainActivity.INSTANCE.restartApplication();
					}

				});
	}

	/**
	 * Display confirmation and clear the cache.
	 */
	private void clearCache() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_alert,
				R.string.Commons_ClearCache, R.string.Commons_NoUndoMessage,
				new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						doClearCache();
					}
				});
	}

	/**
	 * Display confirmation and clear cookies.
	 */
	private void clearCookies() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_alert,
				R.string.Commons_ClearCookies, R.string.Commons_NoUndoMessage,
				new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						doClearCookies();
					}
				});
	}

	/**
	 * Display confirmation and clear form data.
	 */
	private void clearFormData() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_alert,
				R.string.Commons_ClearFormData, R.string.Commons_NoUndoMessage,
				new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						doClearFormData();
					}
				});
	}

	/**
	 * Display confirmation and clear the history.
	 */
	private void clearHistory() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_alert,
				R.string.Commons_ClearHistory, R.string.Commons_NoUndoMessage,
				new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						doClearHistory();
					}
				});
	}

	/**
	 * Clear the history.
	 */
	private void clearHistoryBookmarks() {

		final String[] choices = new String[] {
				getString(R.string.Commons_History),
				getString(R.string.Commons_Bookmarks),
				getString(R.string.Commons_All) };

		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setInverseBackgroundForced(true);
		builder.setIcon(android.R.drawable.ic_dialog_info);
		builder.setTitle(R.string.Commons_ClearHistoryBookmarks);
		builder.setSingleChoiceItems(choices, 0, new OnClickListener() {
			@Override
			public void onClick(DialogInterface dialog, int which) {
				doClearHistoryBookmarks(which);
				dialog.dismiss();
			}
		});

		builder.setCancelable(true);
		builder.setNegativeButton(R.string.Commons_Cancel, null);

		AlertDialog alert = builder.create();
		alert.show();
	}

	/**
	 * Clear the cache.
	 */
	private void doClearCache() {
		mProgressDialog = ProgressDialog.show(this, this.getResources()
				.getString(R.string.Commons_PleaseWait), this.getResources()
				.getString(R.string.Commons_ClearingCache));

		new CacheClearer();
	}

	/**
	 * Clear cookies.
	 */
	private void doClearCookies() {
		mProgressDialog = ProgressDialog.show(this, this.getResources()
				.getString(R.string.Commons_PleaseWait), this.getResources()
				.getString(R.string.Commons_ClearingCookies));

		new CookiesClearer();
	}

	/**
	 * Clear form data.
	 */
	private void doClearFormData() {
		mProgressDialog = ProgressDialog.show(this, this.getResources()
				.getString(R.string.Commons_PleaseWait), this.getResources()
				.getString(R.string.Commons_ClearingFormData));

		new FormDataClearer();
	}

	/**
	 * Clear the history.
	 */
	private void doClearHistory() {
		mProgressDialog = ProgressDialog.show(this, this.getResources()
				.getString(R.string.Commons_PleaseWait), this.getResources()
				.getString(R.string.Commons_ClearingHistory));

		new HistoryClearer();
	}

	private void doClearHistoryBookmarks(int choice) {
		mProgressDialog = ProgressDialog.show(this, this.getResources()
				.getString(R.string.Commons_PleaseWait), this.getResources()
				.getString(R.string.Commons_ClearingHistoryBookmarks));

		new HistoryBookmarksClearer(choice);
	}

	/**
	 * Export the bookmarks and history.
	 */
	private void doExportHistoryBookmarks() {
		if (ApplicationUtils.checkCardState(this, true)) {
			mProgressDialog = ProgressDialog.show(
					this,
					this.getResources().getString(R.string.Commons_PleaseWait),
					this.getResources().getString(
							R.string.Commons_ExportingHistoryBookmarks));

			XmlHistoryBookmarksExporter exporter = new XmlHistoryBookmarksExporter(
					this, DateUtils.getNowForFileName() + ".xml",
					BookmarksProviderWrapper.getAllStockRecords(this
							.getContentResolver()), mProgressDialog);

			new Thread(exporter).start();
		}
	}

	/**
	 * Import the given file to bookmarks and history.
	 * 
	 * @param fileName
	 *            The file to import.
	 */
	private void doImportHistoryBookmarks(String fileName) {

		if (ApplicationUtils.checkCardState(this, true)) {
			mProgressDialog = ProgressDialog.show(
					this,
					this.getResources().getString(R.string.Commons_PleaseWait),
					this.getResources().getString(
							R.string.Commons_ImportingHistoryBookmarks));

			XmlHistoryBookmarksImporter importer = new XmlHistoryBookmarksImporter(
					this, fileName, mProgressDialog);
			new Thread(importer).start();
		}

	}

	/**
	 * Ask the user to confirm the export. Launch it if confirmed.
	 */
	private void exportHistoryBookmarks() {
		ApplicationUtils.showYesNoDialog(this,
				android.R.drawable.ic_dialog_info,
				R.string.Commons_HistoryBookmarksExportSDCardConfirmation,
				R.string.Commons_OperationCanBeLongMessage,
				new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						doExportHistoryBookmarks();
					}
				});
	}

	/**
	 * Ask the user the file to import to bookmarks and history, and launch the
	 * import.
	 */
	private void importHistoryBookmarks() {
		List<String> exportedFiles = IOUtils.getExportedBookmarksFileList();

		final String[] choices = exportedFiles.toArray(new String[exportedFiles
				.size()]);

		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setInverseBackgroundForced(true);
		builder.setIcon(android.R.drawable.ic_dialog_info);
		builder.setTitle(getResources().getString(
				R.string.Commons_ImportHistoryBookmarksSource));
		builder.setSingleChoiceItems(choices, 0, new OnClickListener() {
			@Override
			public void onClick(DialogInterface dialog, int which) {

				doImportHistoryBookmarks(choices[which]);

				dialog.dismiss();
			}
		});

		builder.setCancelable(true);
		builder.setNegativeButton(R.string.Commons_Cancel, null);

		AlertDialog alert = builder.create();
		alert.show();
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		addPreferencesFromResource(R.layout.preferences_activity);

		PreferenceCategory browserPreferenceCategory = (PreferenceCategory) findPreference("BrowserPreferenceCategory");
		Preference enablePluginsEclair = findPreference(Constants.PREFERENCES_BROWSER_ENABLE_PLUGINS_ECLAIR);
		Preference enablePlugins = findPreference(Constants.PREFERENCES_BROWSER_ENABLE_PLUGINS);

		if (Build.VERSION.SDK_INT <= 7) {
			browserPreferenceCategory.removePreference(enablePlugins);
		} else {
			browserPreferenceCategory.removePreference(enablePluginsEclair);
		}

		Preference userAgentPref = findPreference(Constants.PREFERENCES_BROWSER_USER_AGENT);
		userAgentPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openUserAgentActivity();
						return true;
					}
				});

		Preference fullScreenPref = findPreference(Constants.PREFERENCES_SHOW_FULL_SCREEN);
		fullScreenPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {

					@Override
					public boolean onPreferenceClick(Preference preference) {
						askForRestart();
						return true;
					}
				});

		Preference hideTitleBarPref = findPreference(Constants.PREFERENCES_GENERAL_HIDE_TITLE_BARS);
		hideTitleBarPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {

					@Override
					public boolean onPreferenceClick(Preference preference) {
						askForRestart();
						return true;
					}
				});

		Preference searchUrlPref = findPreference(Constants.PREFERENCES_GENERAL_SEARCH_URL);
		searchUrlPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openSearchUrlActivity();
						return true;
					}
				});

		Preference homepagePref = findPreference(Constants.PREFERENCES_GENERAL_HOME_PAGE);
		homepagePref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openHomepageActivity();
						return true;
					}
				});

		Preference weaveServerPref = findPreference(Constants.PREFERENCE_WEAVE_SERVER);
		weaveServerPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openWeaveServerActivity();
						return true;
					}
				});

		Preference aboutPref = findPreference("About");
		aboutPref.setOnPreferenceClickListener(new OnPreferenceClickListener() {
			@Override
			public boolean onPreferenceClick(Preference preference) {
				openAboutActivity();
				return true;
			}
		});

		Preference changelogPref = findPreference("Changelog");
		changelogPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openChangelogActivity();
						return true;
					}
				});

		Preference mobileViewPref = findPreference("MobileViewList");
		mobileViewPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openMobileViewListActivity();
						return true;
					}
				});

		Preference whiteListPref = findPreference("AdBlockerWhiteList");
		whiteListPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						openWhiteListActivity();
						return true;
					}
				});

		Preference clearHistoryPref = findPreference("PrivacyClearHistory");
		clearHistoryPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						clearHistory();
						return true;
					}
				});

		Preference clearformDataPref = findPreference("PrivacyClearFormData");
		clearformDataPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						clearFormData();
						return true;
					}
				});

		Preference clearCachePref = findPreference("PrivacyClearCache");
		clearCachePref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						clearCache();
						return true;
					}
				});

		Preference clearCookiesPref = findPreference("PrivacyClearCookies");
		clearCookiesPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						clearCookies();
						return true;
					}
				});

		Preference exportHistoryBookmarksPref = findPreference("ExportHistoryBookmarks");
		exportHistoryBookmarksPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						exportHistoryBookmarks();
						return true;
					}
				});

		Preference importHistoryBookmarksPref = findPreference("ImportHistoryBookmarks");
		importHistoryBookmarksPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						importHistoryBookmarks();
						return true;
					}
				});

		Preference clearHistoryBookmarksPref = findPreference("ClearHistoryBookmarks");
		clearHistoryBookmarksPref
				.setOnPreferenceClickListener(new OnPreferenceClickListener() {
					@Override
					public boolean onPreferenceClick(Preference preference) {
						clearHistoryBookmarks();
						return true;
					}
				});

		mPreferenceChangeListener = new OnSharedPreferenceChangeListener() {
			@Override
			public void onSharedPreferenceChanged(
					SharedPreferences sharedPreferences, String key) {
				MainActivity.INSTANCE.applyPreferences();
			}
		};

		PreferenceManager.getDefaultSharedPreferences(this)
				.registerOnSharedPreferenceChangeListener(
						mPreferenceChangeListener);
	}

	/**
	 * Display the about dialog.
	 */
	private void openAboutActivity() {
		Intent i = new Intent(this, AboutActivity.class);
		startActivity(i);
	}

	/**
	 * Display the changelog dialog.
	 */
	private void openChangelogActivity() {
		Intent i = new Intent(this, ChangelogActivity.class);
		startActivity(i);
	}

	/**
	 * Display the homepage preference dialog.
	 */
	private void openHomepageActivity() {
		Intent i = new Intent(this, HomepagePreferenceActivity.class);
		startActivity(i);
	}

	/**
	 * Display the mobile view list activity.
	 */
	private void openMobileViewListActivity() {
		Intent i = new Intent(this, MobileViewListActivity.class);
		startActivity(i);
	}

	/**
	 * Display the search url preference dialog.
	 */
	private void openSearchUrlActivity() {
		Intent i = new Intent(this, SearchUrlPreferenceActivity.class);
		startActivity(i);
	}

	/**
	 * Display the user agent preference dialog.
	 */
	private void openUserAgentActivity() {
		Intent i = new Intent(this, UserAgentPreferenceActivity.class);
		startActivity(i);
	}

	private void openWeaveServerActivity() {
		Intent i = new Intent(this, WeaveServerPreferenceActivity.class);
		startActivity(i);
	}

	/**
	 * Display the ad blocker white list activity.
	 */
	private void openWhiteListActivity() {
		Intent i = new Intent(this, AdBlockerWhiteListActivity.class);
		startActivity(i);
	}

}
