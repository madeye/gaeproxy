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
public class WeaveConstants {

	private static final String PACKAGE_NAME = WeaveConstants.class
			.getPackage().getName();

	private static final String APP_NAME = "EmergentWeave";

	private static final double APP_VERSION = 0.9;

	private static final String APP_VERSION_STRING = String.format("%1.1f",
			APP_VERSION);

	private static final String USER_AGENT_DEFAULT = APP_NAME + "/"
			+ APP_VERSION_STRING;

	private static final String LOGGER_NAME_DEFAULT = APP_NAME; // maps to
																// android log
																// tag

	private static final String LOGGER_NAME = getProperty("logger_name",
			LOGGER_NAME_DEFAULT);

	static final String WEAVE_API_VERSION = "1.0";

	static final int UNAUTHORIZED_HTTP_STATUS_CODE = 401;

	public static final boolean ALLOW_INVALID_CERTS_DEFAULT = true; // todo this
																	// should be
																	// false

	static final boolean CONNECTION_POOL_ENABLED_DEFAULT = true;

	public static final String LOGGER_NAME_FULL = getProperty(
			"logger_name_full", PACKAGE_NAME + "." + LOGGER_NAME);

	public static final String USER_AGENT = getProperty("user_agent",
			USER_AGENT_DEFAULT);

	private static String getFullyQualifiedKey(String key) {
		return PACKAGE_NAME + "." + key;
	}

	private static String getProperty(String key, String def) {
		return System.getProperty(getFullyQualifiedKey(key), def);
	}

	private WeaveConstants() {
		// no instantiation
	}
}
