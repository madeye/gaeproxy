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

import org.apache.http.client.HttpResponseException;

/**
 * @author Patrick Woodworth
 */
@SuppressWarnings("serial")
public class WeaveException extends Exception {

	public enum ExceptionType {
		GENERAL, BACKOFF, ;
	}

	public static boolean isAuthFailure(HttpResponseException e) {
		int statusCode = e.getStatusCode();
		if (WeaveConstants.UNAUTHORIZED_HTTP_STATUS_CODE == statusCode)
			return true;
		return false;
	}

	private final WeaveException.ExceptionType m_type;

	public WeaveException() {
		this(WeaveException.ExceptionType.GENERAL);
	}

	public WeaveException(String message) {
		this(WeaveException.ExceptionType.GENERAL, message);
	}

	public WeaveException(String message, Throwable cause) {
		this(WeaveException.ExceptionType.GENERAL, message, cause);
	}

	public WeaveException(Throwable cause) {
		this(WeaveException.ExceptionType.GENERAL, cause);
	}

	public WeaveException(WeaveException.ExceptionType type) {
		m_type = type;
	}

	public WeaveException(WeaveException.ExceptionType type, String message) {
		super(message);
		m_type = type;
	}

	public WeaveException(WeaveException.ExceptionType type, String message,
			Throwable cause) {
		super(message, cause);
		m_type = type;
	}

	public WeaveException(WeaveException.ExceptionType type, Throwable cause) {
		super(cause);
		m_type = type;
	}

	public WeaveException.ExceptionType getType() {
		return m_type;
	}
}
