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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

import org.apache.http.HttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HTTP;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Patrick Woodworth
 */
public class WeaveUtil {

	public static class UriBuilder {

		private String m_val;

		public UriBuilder(URI uri) {
			m_val = uri.toASCIIString();
		}

		public void appendEncodedPath(String s) {
			if (m_val.charAt(m_val.length() - 1) != '/')
				m_val += "/";
			m_val += s;
		}

		public URI build() {
			try {
				return URI.create(m_val);
			} catch (IllegalArgumentException e) {
				Dbg.w("BAD URI: %s", m_val);
				throw e;
			}
		}
	}
	private static final String JSON_STREAM_TYPE = "application/json";

	private static final String ENTITY_CHARSET_NAME = "UTF-8";

	public static UriBuilder buildUpon(URI serverUri) {
		return new UriBuilder(serverUri);
	}

	@SuppressWarnings({})
	public static void checkNull(String str) {
		if (str == null || str.trim().length() < 1) {
			Dbg.w(new IllegalArgumentException(
					"checkNull(String) had empty arg"));
		}
	}

	@SuppressWarnings({})
	public static void checkNull(URI uri) {
		if (uri == null) {
			Dbg.w(new IllegalArgumentException("checkNull(URI) had null arg"));
		} else if (uri.getHost() == null || uri.getHost().length() < 1) {
			Dbg.w(new IllegalArgumentException("checkNull(URI) had empty host"));
		}
	}

	public static void dump(JSONObject jsonObject) {
		try {
			String out = jsonObject.toString(2);
			System.out.println(out);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static String encodeUriSegment(String segment) {
		try {
			return URLEncoder.encode(segment, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static byte[] toAsciiBytes(String data) {
		try {
			return data == null ? null : data.getBytes("US-ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static String toAsciiString(byte[] data) {
		try {
			return data == null ? null : new String(data, "US-ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	@SuppressWarnings("unused")
	private static HttpEntity toHttpEntity(JSONArray jsonArray)
			throws JSONException {
		try {
			StringEntity entity = new StringEntity(jsonArray.toString(0),
					ENTITY_CHARSET_NAME);
			entity.setContentType(JSON_STREAM_TYPE + HTTP.CHARSET_PARAM
					+ ENTITY_CHARSET_NAME);
			return entity;
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	@SuppressWarnings("unused")
	private static HttpEntity toHttpEntity(WeaveBasicObject wbo)
			throws JSONException {
		try {
			StringEntity entity = new StringEntity(wbo.toJSONObjectString(),
					ENTITY_CHARSET_NAME);
			entity.setContentType(JSON_STREAM_TYPE + HTTP.CHARSET_PARAM
					+ ENTITY_CHARSET_NAME);
			return entity;
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static Date toModifiedTimeDate(double modDouble) {
		try {
			long mod = Math.round(modDouble * 1000);
			return new Date(mod);
		} catch (Exception e) {
			return null;
		}
	}

	public static Date toModifiedTimeDate(String modified) {
		@SuppressWarnings("unused")
		long now = System.currentTimeMillis();
		try {
			double modDouble = Double.parseDouble(modified) * 1000;
			long mod = Math.round(modDouble);
			// Dbg.printf("mod: %d ; cur : %d ; delta : %d\n", mod, now, now -
			// mod);
			return new Date(mod);
		} catch (Exception e) {
			return new Date(); // todo buggy ?
		}
	}

	public static String toModifiedTimeString(Date modified) {
		long time = modified.getTime();
		double timed = time / 1000.0;
		String retval = String.format(Locale.ENGLISH, "%.2f", timed);
		// Dbg.debug("TIME: " + retval);
		return retval;
	}

	public static String toString(URI uri) {
		checkNull(uri);
		String retval = uri == null ? null : uri.toString();
		checkNull(retval);
		return retval;
	}

	public static byte[] toUtf8Bytes(String data) {
		try {
			return data == null ? null : data.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static String toUtf8String(byte[] data) {
		try {
			return data == null ? null : new String(data, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static void zeroize(char[] secret) {
		if (secret != null)
			Arrays.fill(secret, '\0');
	}

	private WeaveUtil() {
		// no instantiation
	}
}
