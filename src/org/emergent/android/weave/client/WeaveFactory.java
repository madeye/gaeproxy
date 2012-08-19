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

/**
 * @author Patrick Woodworth
 */
public class WeaveFactory {

	private WeaveTransport m_transport;
	private final boolean m_acceptInvalidCerts;
	private final boolean m_useConnectionPool;

	public WeaveFactory(boolean acceptInvalidCerts) {
		m_acceptInvalidCerts = acceptInvalidCerts;
		m_useConnectionPool = WeaveConstants.CONNECTION_POOL_ENABLED_DEFAULT;
	}

	public UserWeave createUserWeave(URI server, String username,
			String password) {
		return new UserWeave(getWeaveTransport(), server, username, password);
	}

	protected WeaveTransport createWeaveTransport() {
		return new WeaveTransport(isConnectionPoolEnabled(),
				isInvalidCertsAccepted());
	}

	protected synchronized WeaveTransport getWeaveTransport() {
		if (m_transport == null) {
			m_transport = createWeaveTransport();
		}
		return m_transport;
	}

	public boolean isConnectionPoolEnabled() {
		return m_useConnectionPool;
	}

	public boolean isInvalidCertsAccepted() {
		return m_acceptInvalidCerts;
	}
}
