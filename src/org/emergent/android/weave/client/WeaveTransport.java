package org.emergent.android.weave.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;

import javax.net.ssl.SSLException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpMessage;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerPNames;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.conn.ssl.AbstractVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.util.InetAddressUtils;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;

/**
 * @author Patrick Woodworth
 */
class WeaveTransport {

	private static class MyInterceptor implements HttpRequestInterceptor {

		@Override
		public void process(final HttpRequest request, final HttpContext context)
				throws HttpException, IOException {
			AuthState authState = (AuthState) context
					.getAttribute(ClientContext.TARGET_AUTH_STATE);
			CredentialsProvider credsProvider = (CredentialsProvider) context
					.getAttribute(ClientContext.CREDS_PROVIDER);
			HttpHost targetHost = (HttpHost) context
					.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
			if (authState.getAuthScheme() == null) {
				AuthScope authScope = new AuthScope(targetHost.getHostName(),
						targetHost.getPort());
				Credentials creds = credsProvider.getCredentials(authScope);
				if (creds != null) {
					authState.setAuthScheme(new BasicScheme());
					authState.setCredentials(creds);
				}
			}
		}
	}
	/**
	 * Based on BasicResponseHandler
	 */
	private static class MyResponseHandler implements
			ResponseHandler<WeaveResponse> {

		/**
		 * Returns the response body as a String if the response was successful
		 * (a 2xx status code). If no response body exists, this returns null.
		 * If the response was unsuccessful (>= 300 status code), throws an
		 * {@link org.apache.http.client.HttpResponseException}.
		 */
		@Override
		public WeaveResponse handleResponse(final HttpResponse response)
				throws HttpResponseException, IOException {
			StatusLine statusLine = response.getStatusLine();
			if (statusLine.getStatusCode() >= 300) {
				throw new WeaveResponseException(statusLine.getStatusCode(),
						statusLine.getReasonPhrase(), response);
			}
			return new WeaveResponse(response);
		}
	}

	/**
	 * @author Patrick Woodworth
	 */
	static class WeaveHostnameVerifier extends AbstractVerifier {

		private static boolean isIPAddress(final String hostname) {
			return hostname != null
					&& (InetAddressUtils.isIPv4Address(hostname) || InetAddressUtils
							.isIPv6Address(hostname));
		}

		private static void resolveHostAddresses(String cn,
				Collection<String> retval) {
			try {
				InetAddress[] addresses = InetAddress.getAllByName(cn);
				for (InetAddress address : addresses) {
					retval.add(address.getHostAddress());
				}
			} catch (UnknownHostException e) {
				Dbg.d(e);
			}
		}

		@Override
		public void verify(String host, String[] cns, String[] subjectAlts)
				throws SSLException {
			if (isIPAddress(host) && cns != null && cns.length > 0
					&& cns[0] != null) {
				HashSet<String> expandedAlts = new HashSet<String>();
				resolveHostAddresses(cns[0], expandedAlts);
				if (subjectAlts != null)
					expandedAlts.addAll(Arrays.asList(subjectAlts));
				subjectAlts = expandedAlts.toArray(new String[expandedAlts
						.size()]);
			}
			verify(host, cns, subjectAlts, false);
		}
	}
	@SuppressWarnings("serial")
	public static class WeaveResponseException extends HttpResponseException {

		private final WeaveResponseHeaders m_responseHeaders;

		public WeaveResponseException(int statusCode, String reasonPhrase,
				HttpResponse response) {
			// super(statusCode, String.format("statusCode = %s ; reason = %s",
			// statusCode, reasonPhrase));
			super(statusCode, reasonPhrase);
			m_responseHeaders = new WeaveResponseHeaders(response);
		}

		public WeaveResponseHeaders getResponseHeaders() {
			return m_responseHeaders;
		}

		@Override
		public String toString() {
			String s = getClass().getName();
			s += ": (statusCode=" + getStatusCode() + ")";
			String message = getLocalizedMessage();
			return (message != null) ? (s + " : " + message) : s;
		}
	}

	public static class WeaveResponseHeaders {
		private final Header[] m_headers;

		public WeaveResponseHeaders(HttpResponse response) {
			m_headers = response.getAllHeaders();
		}

		public long getBackoffSeconds() {
			long retval = 0;
			try {
				String valStr = getHeaderValue(WeaveHeader.X_WEAVE_BACKOFF);
				if (valStr != null)
					retval = Long.parseLong(valStr);
			} catch (Exception ignored) {
			}
			return retval;
		}

		public Header[] getHeaders() {
			return m_headers;
		}

		private String getHeaderValue(String headerName) {
			for (Header header : m_headers) {
				if (headerName.equals(header.getName()))
					return header.getValue();
			}
			return null;
		}

		private String getHeaderValue(WeaveHeader header) {
			return getHeaderValue(header.getName());
		}

		public Date getServerTimestamp() {
			Date retval = null;
			String ststamp = getHeaderValue(WeaveHeader.X_WEAVE_TIMESTAMP);
			if (ststamp != null)
				retval = WeaveUtil.toModifiedTimeDate(ststamp);
			return retval;
		}
	}

	private static final int HTTP_PORT_DEFAULT = 80;

	private static final int HTTPS_PORT_DEFAULT = 443;

	private static final HttpRequestInterceptor sm_preemptiveAuth = new MyInterceptor();

	private static final MyResponseHandler sm_responseHandler = new MyResponseHandler();

	private static final HttpParams sm_httpParams;

	static {
		HttpParams params = new BasicHttpParams();
		HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		HttpProtocolParams.setContentCharset(params, "UTF-8");
		HttpProtocolParams.setUserAgent(params, WeaveConstants.USER_AGENT);
		HttpProtocolParams.setUseExpectContinue(params, false);
		// params.setParameter(HttpProtocolParams.USE_EXPECT_CONTINUE, false);
		params.setParameter(ConnManagerPNames.MAX_TOTAL_CONNECTIONS, 30);
		params.setParameter(ConnManagerPNames.MAX_CONNECTIONS_PER_ROUTE,
				new ConnPerRouteBean(30));
		sm_httpParams = params;
	}

	private static SocketFactory createSocketFactory(boolean allowInvalidCerts) {
		SocketFactory sslSocketFactory;
		if (allowInvalidCerts) {
			sslSocketFactory = new WeaveSSLSocketFactory();
		} else {
			sslSocketFactory = SSLSocketFactory.getSocketFactory();
			((SSLSocketFactory) sslSocketFactory)
					.setHostnameVerifier(new WeaveHostnameVerifier());
		}
		return sslSocketFactory;
	}

	private final SocketFactory m_sslSocketFactory;

	private final ClientConnectionManager m_clientConMgr;

	public WeaveTransport() {
		this(WeaveConstants.CONNECTION_POOL_ENABLED_DEFAULT);
	}

	public WeaveTransport(boolean useConnectionPool) {
		this(useConnectionPool, WeaveConstants.ALLOW_INVALID_CERTS_DEFAULT);
	}

	public WeaveTransport(boolean useConnectionPool, boolean allowInvalidCerts) {
		m_sslSocketFactory = createSocketFactory(allowInvalidCerts);
		m_clientConMgr = useConnectionPool ? createClientConnectionManager(true)
				: null;
	}

	private ClientConnectionManager createClientConnectionManager(
			boolean threadSafe) {
		SchemeRegistry schemeRegistry = new SchemeRegistry();
		schemeRegistry.register(new Scheme("http", PlainSocketFactory
				.getSocketFactory(), HTTP_PORT_DEFAULT));
		schemeRegistry.register(new Scheme("https", m_sslSocketFactory,
				HTTPS_PORT_DEFAULT));
		if (threadSafe) {
			return new ThreadSafeClientConnManager(sm_httpParams,
					schemeRegistry);
		} else {
			return new SingleClientConnManager(sm_httpParams, schemeRegistry);
		}
	}

	private DefaultHttpClient createDefaultHttpClient() {
		ClientConnectionManager connectionManager;
		if (m_clientConMgr != null) {
			connectionManager = m_clientConMgr;
		} else {
			connectionManager = createClientConnectionManager(false);
		}
		return new DefaultHttpClient(connectionManager, sm_httpParams);
	}

	private HttpClient createHttpClient(String userId, String password) {
		DefaultHttpClient retval = createDefaultHttpClient();
		Credentials defaultcreds = new UsernamePasswordCredentials(userId,
				password);
		retval.getCredentialsProvider().setCredentials(AuthScope.ANY,
				defaultcreds);
		retval.addRequestInterceptor(sm_preemptiveAuth, 0);
		return retval;
	}

	public WeaveResponse execDeleteMethod(String username, String password,
			URI uri) throws IOException, WeaveException {
		HttpDelete method = new HttpDelete(uri);
		return execGenericMethod(username, password, uri, method);
	}

	private WeaveResponse execGenericMethod(HttpClient client, URI uri,
			HttpRequestBase method) throws IOException, WeaveException {
		setMethodHeaders(method);
		MyResponseHandler responseHandler = sm_responseHandler;
		String scheme = uri.getScheme();
		String hostname = uri.getHost();
		int port = uri.getPort();
		HttpHost httpHost = new HttpHost(hostname, port, scheme);
		WeaveResponseHeaders responseHeaders = null;
		try {
			WeaveResponse response = client.execute(httpHost, method,
					responseHandler);
			response.setUri(uri);
			responseHeaders = response.getResponseHeaders();
			return response;
		} catch (WeaveResponseException e) {
			responseHeaders = e.getResponseHeaders();
			throw e;
		} finally {
			if (responseHeaders != null) {
				// long backoff = responseHeaders.getBackoffSeconds();
				// if (backoff > 0) {
				// long newbackoff = System.currentTimeMillis() + backoff;
				// m_backoff.set(newbackoff);
				// }
			}
		}
	}

	private WeaveResponse execGenericMethod(String username, String password,
			URI uri, HttpRequestBase method) throws IOException, WeaveException {
		HttpClient client = null;
		try {
			client = createHttpClient(username, password);
			return execGenericMethod(client, uri, method);
			// } catch (IOException e) {
			// throw new
			// WeaveException("Unable to communicate with Weave server.", e);
		} finally {
			if (m_clientConMgr == null && client != null) {
				client.getConnectionManager().shutdown();
			}
		}
	}

	public WeaveResponse execGetMethod(String username, String password, URI uri)
			throws IOException, WeaveException {
		HttpGet method = new HttpGet(uri);
		return execGenericMethod(username, password, uri, method);
	}

	public WeaveResponse execPostMethod(String username, String password,
			URI uri, HttpEntity entity) throws IOException, WeaveException {
		HttpPost method = new HttpPost(uri);
		method.setEntity(entity);
		return execGenericMethod(username, password, uri, method);
	}

	public WeaveResponse execPutMethod(String username, String password,
			URI uri, HttpEntity entity) throws IOException, WeaveException {
		HttpPut method = new HttpPut(uri);
		method.setEntity(entity);
		return execGenericMethod(username, password, uri, method);
	}

	private void setMethodHeaders(HttpMessage method) {
		method.addHeader("Pragma", "no-cache");
		method.addHeader("Cache-Control", "no-cache");
	}

	public void shutdown() {
		// if (m_clientConMgr != null)
		// m_clientConMgr.shutdown();
	}
}
