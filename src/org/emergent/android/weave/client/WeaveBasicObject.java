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
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Date;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Patrick Woodworth
 */
public class WeaveBasicObject {

	public static class WeaveEncryptedObject {

		private final JSONObject m_nodeObj;

		public WeaveEncryptedObject(JSONObject nodeObj) {
			m_nodeObj = nodeObj;
		}

		public JSONObject decryptObject(BulkKeyCouplet keyPair)
				throws GeneralSecurityException, JSONException {
			return decryptObject(keyPair.cipherKey, keyPair.hmacKey);
		}

		public JSONObject decryptObject(Key key, Key hmacKey)
				throws GeneralSecurityException, JSONException {
			byte[] bytes = WeaveCryptoUtil.getInstance().decrypt(key, hmacKey,
					getCiphertext(), getIv(), getHmac());
			return new JSONObject(WeaveUtil.toUtf8String(bytes));
		}

		public String getCiphertext() throws JSONException {
			return m_nodeObj.getString("ciphertext");
		}

		public String getHmac() throws JSONException {
			return m_nodeObj.getString("hmac");
		}

		public String getIv() throws JSONException {
			return m_nodeObj.getString("IV");
		}
	}

	private URI m_uri = null;
	private final URI m_queryUri;

	private final JSONObject m_nodeObj;

	public WeaveBasicObject(URI queryUri, JSONObject nodeObj) {
		m_queryUri = queryUri;
		m_nodeObj = nodeObj;
	}

	public JSONObject getEncryptedPayload(Key bulkKey, Key hmacKey)
			throws JSONException, IOException, GeneralSecurityException,
			WeaveException {
		WeaveEncryptedObject weo = new WeaveEncryptedObject(getPayload());
		return weo.decryptObject(bulkKey, hmacKey);
	}

	public JSONObject getEncryptedPayload(UserWeave weave, char[] secret)
			throws JSONException, IOException, GeneralSecurityException,
			WeaveException {
		WeaveEncryptedObject weo = new WeaveEncryptedObject(getPayload());
		byte[] syncKey = Base32.decodeModified(new String(secret)); // todo
																	// don't
																	// convert
																	// to string
		BulkKeyCouplet bulkKeyPair = weave.getBulkKeyPair(syncKey);
		return weo.decryptObject(bulkKeyPair);
	}

	public String getId() throws JSONException {
		return m_nodeObj.getString("id");
	}

	public String getModified() throws JSONException {
		return m_nodeObj.getString("modified");
	}

	public Date getModifiedDate() throws JSONException {
		return WeaveUtil.toModifiedTimeDate(getModified());
	}

	public JSONObject getPayload() throws JSONException {
		return new JSONObject(m_nodeObj.getString("payload"));
	}

	public String getSortIndex() throws JSONException {
		return m_nodeObj.getString("sortindex");
	}

	public URI getUri() throws JSONException {
		if (m_uri == null) {
			try {
				String baseUriStr = m_queryUri.toASCIIString();
				String queryPart = m_queryUri.getRawQuery();
				if (queryPart != null)
					baseUriStr = baseUriStr.substring(0,
							baseUriStr.indexOf(queryPart) - 1);
				if (!baseUriStr.endsWith("/"))
					baseUriStr += "/";
				String nodeUriStr = baseUriStr
						+ new URI(null, null, getId(), null).toASCIIString();
				m_uri = new URI(nodeUriStr);
			} catch (URISyntaxException e) {
				throw new JSONException(e.getMessage());
			}
		}
		return m_uri;
	}

	public JSONObject toJSONObject() {
		return m_nodeObj;
	}

	public String toJSONObjectString() throws JSONException {
		return toJSONObject().toString(0);
	}
}
