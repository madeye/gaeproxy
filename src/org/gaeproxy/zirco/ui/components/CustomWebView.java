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

package org.gaeproxy.zirco.ui.components;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.gaeproxy.ProxySettings;
import org.gaeproxy.zirco.controllers.Controller;
import org.gaeproxy.zirco.utils.ApplicationUtils;
import org.gaeproxy.zirco.utils.Constants;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.WebSettings;
import android.webkit.WebSettings.PluginState;
import android.webkit.WebSettings.ZoomDensity;
import android.webkit.WebView;

/**
 * A convenient extension of WebView.
 */
public class CustomWebView extends WebView {

	private Context mContext;

	private int mProgress = 100;

	private boolean mIsLoading = false;

	private String mLoadedUrl;

	private static boolean mBoMethodsLoaded = false;

	private static Method mOnPauseMethod = null;
	private static Method mOnResumeMethod = null;
	private static Method mSetFindIsUp = null;
	private static Method mNotifyFindDialogDismissed = null;

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The current context.
	 */
	public CustomWebView(Context context) {
		super(context);

		mContext = context;

		initializeOptions();
		loadMethods();
	}

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The current context.
	 * @param attrs
	 *            The attribute set.
	 */
	public CustomWebView(Context context, AttributeSet attrs) {
		super(context, attrs);

		mContext = context;

		initializeOptions();
		loadMethods();
	}

	public void doNotifyFindDialogDismissed() {
		if (mNotifyFindDialogDismissed != null) {
			try {

				mNotifyFindDialogDismissed.invoke(this);

			} catch (IllegalArgumentException e) {
				Log.e("CustomWebView",
						"doNotifyFindDialogDismissed(): " + e.getMessage());
			} catch (IllegalAccessException e) {
				Log.e("CustomWebView",
						"doNotifyFindDialogDismissed(): " + e.getMessage());
			} catch (InvocationTargetException e) {
				Log.e("CustomWebView",
						"doNotifyFindDialogDismissed(): " + e.getMessage());
			}
		}
	}

	/**
	 * Perform an 'onPause' on this WebView through reflexion.
	 */
	public void doOnPause() {
		if (mOnPauseMethod != null) {
			try {

				mOnPauseMethod.invoke(this);

			} catch (IllegalArgumentException e) {
				Log.e("CustomWebView", "doOnPause(): " + e.getMessage());
			} catch (IllegalAccessException e) {
				Log.e("CustomWebView", "doOnPause(): " + e.getMessage());
			} catch (InvocationTargetException e) {
				Log.e("CustomWebView", "doOnPause(): " + e.getMessage());
			}
		}
	}

	/**
	 * Perform an 'onResume' on this WebView through reflexion.
	 */
	public void doOnResume() {
		if (mOnResumeMethod != null) {
			try {

				mOnResumeMethod.invoke(this);

			} catch (IllegalArgumentException e) {
				Log.e("CustomWebView", "doOnResume(): " + e.getMessage());
			} catch (IllegalAccessException e) {
				Log.e("CustomWebView", "doOnResume(): " + e.getMessage());
			} catch (InvocationTargetException e) {
				Log.e("CustomWebView", "doOnResume(): " + e.getMessage());
			}
		}
	}

	public void doSetFindIsUp(boolean value) {
		if (mSetFindIsUp != null) {
			try {

				mSetFindIsUp.invoke(this, value);

			} catch (IllegalArgumentException e) {
				Log.e("CustomWebView", "doSetFindIsUp(): " + e.getMessage());
			} catch (IllegalAccessException e) {
				Log.e("CustomWebView", "doSetFindIsUp(): " + e.getMessage());
			} catch (InvocationTargetException e) {
				Log.e("CustomWebView", "doSetFindIsUp(): " + e.getMessage());
			}
		}
	}

	/**
	 * Get the loaded url, e.g. the one asked by the user, without redirections.
	 * 
	 * @return The loaded url.
	 */
	public String getLoadedUrl() {
		return mLoadedUrl;
	}

	/**
	 * Get the current loading progress of the view.
	 * 
	 * @return The current loading progress of the view.
	 */
	@Override
	public int getProgress() {
		return mProgress;
	}
	
	private void initializeProxy() {

		SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(mContext);

		int port = 1984;
		try {
			port = Integer.valueOf(settings.getString("port", "1984"));
		} catch (NumberFormatException ignore) {

		}

		ProxySettings.setProxy(mContext, "127.0.0.1", port);

	}

	/**
	 * Initialize the WebView with the options set by the user through
	 * preferences.
	 */
	public void initializeOptions() {

		initializeProxy();
		
		WebSettings settings = getSettings();

		// User settings
		settings.setJavaScriptEnabled(Controller
				.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_ENABLE_JAVASCRIPT,
						true));
		settings.setLoadsImagesAutomatically(Controller.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_ENABLE_IMAGES, true));
		settings.setUseWideViewPort(Controller
				.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_USE_WIDE_VIEWPORT,
						true));
		settings.setLoadWithOverviewMode(Controller
				.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_LOAD_WITH_OVERVIEW,
						false));
		settings.setSaveFormData(Controller
				.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_ENABLE_FORM_DATA,
						true));
		settings.setSavePassword(Controller
				.getInstance()
				.getPreferences()
				.getBoolean(Constants.PREFERENCES_BROWSER_ENABLE_PASSWORDS,
						true));
		settings.setDefaultZoom(ZoomDensity.valueOf(Controller
				.getInstance()
				.getPreferences()
				.getString(Constants.PREFERENCES_DEFAULT_ZOOM_LEVEL,
						ZoomDensity.MEDIUM.toString())));
		settings.setUserAgentString(Controller
				.getInstance()
				.getPreferences()
				.getString(Constants.PREFERENCES_BROWSER_USER_AGENT,
						Constants.USER_AGENT_DEFAULT));

		CookieManager.getInstance().setAcceptCookie(
				Controller
						.getInstance()
						.getPreferences()
						.getBoolean(
								Constants.PREFERENCES_BROWSER_ENABLE_COOKIES,
								true));

		if (Build.VERSION.SDK_INT <= 7) {
			settings.setPluginsEnabled(Controller
					.getInstance()
					.getPreferences()
					.getBoolean(
							Constants.PREFERENCES_BROWSER_ENABLE_PLUGINS_ECLAIR,
							true));
		} else {
			settings.setPluginState(PluginState.valueOf(Controller
					.getInstance()
					.getPreferences()
					.getString(Constants.PREFERENCES_BROWSER_ENABLE_PLUGINS,
							PluginState.ON_DEMAND.toString())));
		}

		settings.setSupportZoom(true);

		// Technical settings
		settings.setSupportMultipleWindows(true);
		setLongClickable(true);
		setScrollbarFadingEnabled(true);
		setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);
		setDrawingCacheEnabled(true);

		settings.setAppCacheEnabled(true);
		settings.setDatabaseEnabled(true);
		settings.setDomStorageEnabled(true);
	}

	/**
	 * Check if the view is currently loading.
	 * 
	 * @return True if the view is currently loading.
	 */
	public boolean isLoading() {
		return mIsLoading;
	}

	public boolean isSameUrl(String url) {
		if (url != null) {
			return url.equalsIgnoreCase(this.getUrl());
		}

		return false;
	}

	/**
	 * Inject the AdSweep javascript.
	 */
	public void loadAdSweep() {
		super.loadUrl(ApplicationUtils.getAdSweepString(mContext));
	}

	/**
	 * Load static reflected methods.
	 */
	private void loadMethods() {

		if (!mBoMethodsLoaded) {

			try {

				mOnPauseMethod = WebView.class.getMethod("onPause");
				mOnResumeMethod = WebView.class.getMethod("onResume");

			} catch (SecurityException e) {
				Log.e("CustomWebView", "loadMethods(): " + e.getMessage());
				mOnPauseMethod = null;
				mOnResumeMethod = null;
			} catch (NoSuchMethodException e) {
				Log.e("CustomWebView", "loadMethods(): " + e.getMessage());
				mOnPauseMethod = null;
				mOnResumeMethod = null;
			}

			try {

				mSetFindIsUp = WebView.class.getMethod("setFindIsUp",
						Boolean.TYPE);
				mNotifyFindDialogDismissed = WebView.class
						.getMethod("notifyFindDialogDismissed");

			} catch (SecurityException e) {
				Log.e("CustomWebView", "loadMethods(): " + e.getMessage());
				mSetFindIsUp = null;
				mNotifyFindDialogDismissed = null;
			} catch (NoSuchMethodException e) {
				Log.e("CustomWebView", "loadMethods(): " + e.getMessage());
				mSetFindIsUp = null;
				mNotifyFindDialogDismissed = null;
			}

			mBoMethodsLoaded = true;
		}
	}

	@Override
	public void loadUrl(String url) {
		mLoadedUrl = url;
		super.loadUrl(url);
	}

	/**
	 * Triggered when the page has finished loading.
	 */
	public void notifyPageFinished() {
		mProgress = 100;
		mIsLoading = false;
	}

	/**
	 * Triggered when a new page loading is requested.
	 */
	public void notifyPageStarted() {
		mIsLoading = true;
	}

	@Override
	public boolean onTouchEvent(MotionEvent ev) {

		final int action = ev.getAction();

		// Enable / disable zoom support in case of multiple pointer, e.g.
		// enable zoom when we have two down pointers, disable with one pointer
		// or when pointer up.
		// We do this to prevent the display of zoom controls, which are not
		// useful and override over the right bubble.
		if ((action == MotionEvent.ACTION_DOWN)
				|| (action == MotionEvent.ACTION_POINTER_DOWN)
				|| (action == MotionEvent.ACTION_POINTER_1_DOWN)
				|| (action == MotionEvent.ACTION_POINTER_2_DOWN)
				|| (action == MotionEvent.ACTION_POINTER_3_DOWN)) {
			if (ev.getPointerCount() > 1) {
				this.getSettings().setBuiltInZoomControls(true);
				this.getSettings().setSupportZoom(true);
			} else {
				this.getSettings().setBuiltInZoomControls(false);
				this.getSettings().setSupportZoom(false);
			}
		} else if ((action == MotionEvent.ACTION_UP)
				|| (action == MotionEvent.ACTION_POINTER_UP)
				|| (action == MotionEvent.ACTION_POINTER_1_UP)
				|| (action == MotionEvent.ACTION_POINTER_2_UP)
				|| (action == MotionEvent.ACTION_POINTER_3_UP)) {
			this.getSettings().setBuiltInZoomControls(false);
			this.getSettings().setSupportZoom(false);
		}

		return super.onTouchEvent(ev);
	}

	/**
	 * Reset the loaded url.
	 */
	public void resetLoadedUrl() {
		mLoadedUrl = null;
	}

	/**
	 * Set the current loading progress of this view.
	 * 
	 * @param progress
	 *            The current loading progress.
	 */
	public void setProgress(int progress) {
		mProgress = progress;
	}

}
