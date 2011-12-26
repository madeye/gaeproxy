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

import java.io.IOException;
import java.net.URI;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;

/**
 * @author Patrick Woodworth
 */
public class WeaveResponse {

	private final WeaveTransport.WeaveResponseHeaders m_responseHeaders;
	private final String m_body;
	private URI m_uri;

	public WeaveResponse(HttpResponse response) throws IOException {
		m_responseHeaders = new WeaveTransport.WeaveResponseHeaders(response);
		HttpEntity entity = response.getEntity();
		m_body = entity == null ? null : EntityUtils.toString(entity);
	}

	public long getBackoffSeconds() {
		return m_responseHeaders.getBackoffSeconds();
	}

	public String getBody() {
		return m_body;
	}

	public WeaveTransport.WeaveResponseHeaders getResponseHeaders() {
		return m_responseHeaders;
	}

	public Date getServerTimestamp() {
		return m_responseHeaders.getServerTimestamp();
	}

	public URI getUri() {
		return m_uri;
	}

	public void setUri(URI uri) {
		m_uri = uri;
	}
}
