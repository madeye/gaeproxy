package org.gaeproxy.zirco.model.items;

public class WeaveBookmarkItem {

	private String mTitle;
	private String mUrl;
	private boolean mIsFolder;
	private String mWeaveId;

	public WeaveBookmarkItem(String title, String url, String weaveId,
			boolean isFolder) {
		mTitle = title;
		mUrl = url;
		mWeaveId = weaveId;
		mIsFolder = isFolder;
	}

	public String getTitle() {
		return mTitle;
	}

	public String getUrl() {
		return mUrl;
	}

	public String getWeaveId() {
		return mWeaveId;
	}

	public boolean isFolder() {
		return mIsFolder;
	}

}
