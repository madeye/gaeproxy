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

package org.gaeproxy.zirco.events;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Implementation of the EventController.
 */
public final class EventController {

	/**
	 * Holder for singleton implementation.
	 */
	private static class EventControllerHolder {
		private static final EventController INSTANCE = new EventController();
	}

	/**
	 * Get the unique instance of the Controller.
	 * 
	 * @return The instance of the Controller
	 */
	public static EventController getInstance() {
		return EventControllerHolder.INSTANCE;
	}

	private List<IDownloadEventsListener> mDownloadListeners;

	/**
	 * Private Constructor.
	 */
	private EventController() {
		mDownloadListeners = new ArrayList<IDownloadEventsListener>();
	}

	/**
	 * Add a listener for download events.
	 * 
	 * @param listener
	 *            The listener to add.
	 */
	public synchronized void addDownloadListener(
			IDownloadEventsListener listener) {

		if (!mDownloadListeners.contains(listener)) {
			mDownloadListeners.add(listener);
		}
	}

	/**
	 * Trigger a download event.
	 * 
	 * @param event
	 *            The event.
	 * @param data
	 *            Additional data.
	 */
	public synchronized void fireDownloadEvent(String event, Object data) {
		Iterator<IDownloadEventsListener> iter = mDownloadListeners.iterator();
		while (iter.hasNext()) {
			iter.next().onDownloadEvent(event, data);
		}
	}

	/**
	 * Remove a listener for download events.
	 * 
	 * @param listener
	 *            The listener to remove.
	 */
	public synchronized void removeDownloadListener(
			IDownloadEventsListener listener) {
		mDownloadListeners.remove(listener);
	}

}
