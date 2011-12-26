/*
 * Zirco Browser for Android
 * 
 * Copyright (C) 2010 - 2011 J. Devauchelle and contributors.
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

package org.gaeproxy.zirco.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.gaeproxy.R;

import android.content.Context;
import android.util.Log;

/**
 * Utilities for date / time management.
 */
public class DateUtils {

	/**
	 * Parse a string representation of a date in default format to a Date
	 * object.
	 * 
	 * @param context
	 *            The current context.
	 * @param date
	 *            The date to convert.
	 * @return The converted date. If an error occurs during conversion, will be
	 *         the current date.
	 */
	public static Date convertFromDatabase(Context context, String date) {
		SimpleDateFormat sdf = new SimpleDateFormat(getDefaultFormat(context));

		try {

			return sdf.parse(date);

		} catch (ParseException e) {
			Log.w(DateUtils.class.toString(), "Error parsing date (" + date
					+ "): " + e.getMessage());

			return new Date();
		}
	}

	/**
	 * Get the default date format.
	 * 
	 * @param context
	 *            The current context.
	 * @return The default date format.
	 */
	private static String getDefaultFormat(Context context) {
		return context.getResources().getString(R.string.DATE_FORMAT_ISO8601);
	}

	/**
	 * Get a string representation of the current date / time in a format
	 * suitable for a file name.
	 * 
	 * @return A string representation of the current date / time.
	 */
	public static String getNowForFileName() {
		Calendar c = Calendar.getInstance();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd-HHmmss");

		return sdf.format(c.getTime());
	}

}
