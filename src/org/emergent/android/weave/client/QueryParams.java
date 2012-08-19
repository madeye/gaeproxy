/*
 * Copyright 2010 Patrick Woodworth
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.emergent.android.weave.client;

import java.util.Date;

/**
 * @author Patrick Woodworth
 */
public class QueryParams {

	private Date m_older;

	private Date m_newer;

	private boolean m_full = true;

	private String m_sort = "newest";

	public QueryParams() {
	}

	public Date getNewer() {
		return m_newer;
	}

	public Date getOlder() {
		return m_older;
	}

	public String getSort() {
		return m_sort;
	}

	public boolean isFull() {
		return m_full;
	}

	public QueryParams setFull(boolean full) {
		m_full = full;
		return this;
	}

	public QueryParams setNewer(Date newer) {
		m_newer = newer;
		return this;
	}

	public QueryParams setOlder(Date older) {
		m_older = older;
		return this;
	}

	public QueryParams setSort(String sort) {
		m_sort = sort;
		return this;
	}

	public String toQueryString() {
		StringBuffer retval = new StringBuffer();
		retval.append("?full=").append(m_full ? "1" : "0");
		if (m_sort != null)
			retval.append("&sort=").append(m_sort);
		if (m_older != null)
			retval.append("&older=").append(
					WeaveUtil.toModifiedTimeString(m_older));
		if (m_newer != null)
			retval.append("&newer=").append(
					WeaveUtil.toModifiedTimeString(m_newer));
		return retval.toString();
	}

	@Override
	public String toString() {
		return toQueryString();
	}
}
