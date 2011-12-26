package org.gaeproxy.zirco.model.items;

/**
 * Represent a bookmark.
 */
public class BookmarkItem {

	private String mTitle;
	private String mUrl;

	/**
	 * Constructor.
	 * 
	 * @param title
	 *            The bookmark title.
	 * @param url
	 *            The bookmark url.
	 */
	public BookmarkItem(String title, String url) {
		mTitle = title;
		mUrl = url;
	}

	/**
	 * Get the bookmark title.
	 * 
	 * @return The bookmark title.
	 */
	public String getTitle() {
		return mTitle;
	}

	/**
	 * Get the bookmark url.
	 * 
	 * @return The bookmark url.
	 */
	public String getUrl() {
		return mUrl;
	}

}
