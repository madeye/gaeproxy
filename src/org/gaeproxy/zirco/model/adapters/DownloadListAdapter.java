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

package org.gaeproxy.zirco.model.adapters;

import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.gaeproxy.R;
import org.gaeproxy.zirco.model.items.DownloadItem;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.TextView;

/**
 * The adapter for the download UI list.
 */
public class DownloadListAdapter extends BaseAdapter {

	private Context mContext;
	private List<DownloadItem> mDownloads;

	private Map<DownloadItem, TextView> mTitleMap;
	private Map<DownloadItem, ProgressBar> mBarMap;
	private Map<DownloadItem, ImageButton> mButtonMap;

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The current context.
	 * @param downloads
	 *            The download list.
	 */
	public DownloadListAdapter(Context context, List<DownloadItem> downloads) {
		mContext = context;
		mDownloads = downloads;
		mTitleMap = new Hashtable<DownloadItem, TextView>();
		mBarMap = new Hashtable<DownloadItem, ProgressBar>();
		mButtonMap = new Hashtable<DownloadItem, ImageButton>();
	}

	/**
	 * Get a map of download item related to the UI progress bar component.
	 * 
	 * @return A Map<DownloadItem, ProgressBar>.
	 */
	public Map<DownloadItem, ProgressBar> getBarMap() {
		return mBarMap;
	}

	/**
	 * Get a map of download item related to the UI cancel button component.
	 * 
	 * @return A Map<DownloadItem, ImageButton>.
	 */
	public Map<DownloadItem, ImageButton> getButtonMap() {
		return mButtonMap;
	}

	@Override
	public int getCount() {
		return mDownloads.size();
	}

	@Override
	public Object getItem(int position) {
		return mDownloads.get(position);
	}

	@Override
	public long getItemId(int position) {
		return position;
	}

	/**
	 * Get a map of download item related to the UI text component representing
	 * the download title.
	 * 
	 * @return A Map<DownloadItem, TextView>.
	 */
	public Map<DownloadItem, TextView> getTitleMap() {
		return mTitleMap;
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
		if (convertView == null) {
			LayoutInflater inflater = (LayoutInflater) mContext
					.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
			convertView = inflater.inflate(R.layout.download_row, null);
		}

		final DownloadItem item = mDownloads.get(position);

		final ProgressBar progressBar = (ProgressBar) convertView
				.findViewById(R.id.DownloadRow_ProgressBar);
		final TextView fileNameView = (TextView) convertView
				.findViewById(R.id.DownloadRow_FileName);
		TextView urlView = (TextView) convertView
				.findViewById(R.id.DownloadRow_Url);
		final ImageButton stopButton = (ImageButton) convertView
				.findViewById(R.id.DownloadRow_StopBtn);

		progressBar.setIndeterminate(false);
		progressBar.setMax(100);
		progressBar.setProgress(item.getProgress());

		if (item.isAborted()) {
			fileNameView.setText(String.format(mContext.getResources()
					.getString(R.string.DownloadListActivity_Aborted), item
					.getFileName()));
			stopButton.setEnabled(false);
		} else if (item.isFinished()) {
			fileNameView.setText(String.format(mContext.getResources()
					.getString(R.string.DownloadListActivity_Finished), item
					.getFileName()));
			stopButton.setEnabled(false);
		} else {
			fileNameView.setText(item.getFileName());
		}
		urlView.setText(item.getUrl());

		stopButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				item.abortDownload();
				stopButton.setEnabled(false);
				fileNameView.setText(String.format(mContext.getResources()
						.getString(R.string.DownloadListActivity_Aborted), item
						.getFileName()));
				progressBar.setProgress(progressBar.getMax());
			}

		});

		mTitleMap.put(item, fileNameView);
		mBarMap.put(item, progressBar);
		mButtonMap.put(item, stopButton);

		return convertView;
	}

}
