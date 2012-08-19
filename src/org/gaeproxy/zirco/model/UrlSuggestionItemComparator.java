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

package org.gaeproxy.zirco.model;

import java.util.Comparator;

import org.gaeproxy.zirco.model.items.UrlSuggestionItem;

/**
 * Comparator for UrlSuggestionItem.
 */
public class UrlSuggestionItemComparator implements
		Comparator<UrlSuggestionItem> {

	@Override
	public int compare(UrlSuggestionItem object1, UrlSuggestionItem object2) {
		Float value1 = new Float(object1.getNote());
		Float value2 = new Float(object2.getNote());
		return value2.compareTo(value1);
	}

}
