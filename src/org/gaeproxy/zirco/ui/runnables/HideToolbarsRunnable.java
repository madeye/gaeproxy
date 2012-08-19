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

package org.gaeproxy.zirco.ui.runnables;

import org.gaeproxy.zirco.ui.activities.IToolbarsContainer;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

/**
 * A runnable to hide tool bars after the given delay.
 */
public class HideToolbarsRunnable implements Runnable {

	private static final String TAG = "HideToolbarsRunnable";

	private IToolbarsContainer mParent;
	private boolean mDisabled;
	private int mDelay;

	private Handler mHandler = new Handler() {

		@Override
		public void handleMessage(Message msg) {
			if ((mParent != null) && (!mDisabled)) {
				mParent.hideToolbars();
			}
		}
	};

	/**
	 * Constructor.
	 * 
	 * @param parent
	 *            The parent tool bar container.
	 * @param delay
	 *            The delay before hiding, in milliseconds.
	 */
	public HideToolbarsRunnable(IToolbarsContainer parent, int delay) {
		mParent = parent;
		mDisabled = false;
		mDelay = delay;
	}

	@Override
	public void run() {
		try {

			Thread.sleep(mDelay);

			mHandler.sendEmptyMessage(0);

		} catch (InterruptedException e) {
			Log.w(TAG, "Exception in thread: " + e.getMessage());

			mHandler.sendEmptyMessage(0);
		}
	}

	/**
	 * Disable this runnable.
	 */
	public void setDisabled() {
		mDisabled = true;
	}

}
