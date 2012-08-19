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

import java.net.URI;
import java.util.Date;

/**
 * @author Patrick Woodworth
 */
public class QueryResult<T> {

	private final URI m_uri;

	private Date m_serverTimestamp;

	private T m_value;

	QueryResult(WeaveResponse response) {
		this(response, null);
	}

	QueryResult(WeaveResponse response, T value) {
		m_uri = response.getUri();
		m_serverTimestamp = response.getServerTimestamp();
		m_value = value;
	}

	public Date getServerTimestamp() {
		return m_serverTimestamp;
	}

	public long getServerTimestampInSeconds() {
		if (m_serverTimestamp != null)
			return m_serverTimestamp.getTime();
		return 0;
	}

	public URI getUri() {
		return m_uri;
	}

	public T getValue() {
		return m_value;
	}

	void setValue(T value) {
		m_value = value;
	}
}
