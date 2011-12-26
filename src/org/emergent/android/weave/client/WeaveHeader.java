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

/**
 * @author Patrick Woodworth
 */
enum WeaveHeader {

	X_WEAVE_BACKOFF("X-Weave-Backoff"), X_WEAVE_ALERT("X-Weave-Alert"), X_WEAVE_TIMESTAMP(
			"X-Weave-Timestamp"), X_WEAVE_RECORDS("X-Weave-Records"), X_WEAVE_IF_UNMODIFIED_SINCE(
			"X-If-Unmodified-Since"), ;

	private final String m_name;

	WeaveHeader(String name) {
		m_name = name;
	}

	public String getName() {
		return m_name;
	}
}
