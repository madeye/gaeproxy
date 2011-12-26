package org.gaeproxy.zirco.ui.runnables;

import org.gaeproxy.zirco.providers.BookmarksProviderWrapper;

import android.app.Activity;
import android.graphics.Bitmap;

/**
 * Runnable to update database favicon.
 */
public class FaviconUpdaterRunnable implements Runnable {

	private Activity mActivity;
	private String mUrl;
	private String mOriginalUrl;
	private Bitmap mFavIcon;

	/**
	 * Constructor.
	 * 
	 * @param activity
	 *            The parent activity.
	 * @param url
	 *            The page url.
	 * @param originalUrl
	 *            The page original url.
	 * @param favicon
	 *            The favicon.
	 */
	public FaviconUpdaterRunnable(Activity activity, String url,
			String originalUrl, Bitmap favicon) {
		mActivity = activity;
		mUrl = url;
		mOriginalUrl = originalUrl;
		mFavIcon = favicon;
	}

	@Override
	public void run() {
		BookmarksProviderWrapper.updateFavicon(mActivity, mUrl, mOriginalUrl,
				mFavIcon);
	}

}
