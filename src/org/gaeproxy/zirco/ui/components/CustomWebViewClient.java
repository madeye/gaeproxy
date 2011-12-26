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

import org.gaeproxy.zirco.controllers.Controller;
import org.gaeproxy.zirco.ui.activities.MainActivity;
import org.gaeproxy.zirco.utils.ApplicationUtils;
import org.gaeproxy.zirco.utils.Constants;
import org.gaeproxy.zirco.utils.UrlUtils;

import android.graphics.Bitmap;
import android.net.http.SslError;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebView.HitTestResult;
import android.webkit.WebViewClient;

/**
 * Convenient extension of WebViewClient.
 */
public class CustomWebViewClient extends WebViewClient {

	private MainActivity mMainActivity;

	public CustomWebViewClient(MainActivity mainActivity) {
		super();
		mMainActivity = mainActivity;
	}

	@Override
	public void onLoadResource(WebView view, String url) {
		// Some dirty stuff for handling m.youtube.com. May break in the future
		// ?
		if (url.startsWith("http://s.youtube.com/s?ns=yt&ps=blazer&playback=1&el=detailpage&app=youtube_mobile")) {

			try {
				int startIndex = url.indexOf("&docid=") + 7;
				int endIndex = url.indexOf("&", startIndex);

				String videoId = url.substring(startIndex, endIndex);

				mMainActivity.onVndUrl("vnd.youtube:" + videoId);

			} catch (Exception e) {
				Log.e("onLoadResource", "Unable to parse YouTube url: " + url);
			}
		}

		super.onLoadResource(view, url);
	}

	@Override
	public void onPageFinished(WebView view, String url) {
		((CustomWebView) view).notifyPageFinished();
		mMainActivity.onPageFinished(url);

		super.onPageFinished(view, url);
	}

	@Override
	public void onPageStarted(WebView view, String url, Bitmap favicon) {

		// Some magic here: when performing WebView.loadDataWithBaseURL, the url
		// is "file:///android_asset/startpage,
		// whereas when the doing a "previous" or "next", the url is
		// "about:start", and we need to perform the
		// loadDataWithBaseURL here, otherwise it won't load.
		if (url.equals(Constants.URL_ABOUT_START)) {
			view.loadDataWithBaseURL("file:///android_asset/startpage/",
					ApplicationUtils.getStartPage(view.getContext()),
					"text/html", "UTF-8", "about:start");
		}

		((CustomWebView) view).notifyPageStarted();
		mMainActivity.onPageStarted(url);

		super.onPageStarted(view, url, favicon);
	}

	@Override
	public void onReceivedSslError(WebView view, final SslErrorHandler handler,
			SslError error) {
		handler.proceed();
	}

	@Override
	public boolean shouldOverrideUrlLoading(WebView view, String url) {

		if (url.startsWith("vnd.")) {
			mMainActivity.onVndUrl(url);
			return true;
		} else if (url.startsWith(Constants.URL_ACTION_SEARCH)) {
			String searchTerm = url.replace(Constants.URL_ACTION_SEARCH, "");

			String searchUrl = Controller
					.getInstance()
					.getPreferences()
					.getString(Constants.PREFERENCES_GENERAL_SEARCH_URL,
							Constants.URL_SEARCH_GOOGLE);
			String newUrl = String.format(searchUrl, searchTerm);

			view.loadUrl(newUrl);
			return true;

		} else if (view.getHitTestResult().getType() == HitTestResult.EMAIL_TYPE) {
			mMainActivity.onMailTo(url);
			return true;

		} else {

			// If the url is not from GWT mobile view, and is in the mobile view
			// url list, then load it with GWT.
			if ((!url.startsWith(Constants.URL_GOOGLE_MOBILE_VIEW_NO_FORMAT))
					&& (UrlUtils.checkInMobileViewUrlList(view.getContext(),
							url))) {

				String newUrl = String.format(Constants.URL_GOOGLE_MOBILE_VIEW,
						url);
				view.loadUrl(newUrl);
				return true;

			} else {
				((CustomWebView) view).resetLoadedUrl();
				mMainActivity.onUrlLoading(url);
				return false;
			}
		}
	}

}
