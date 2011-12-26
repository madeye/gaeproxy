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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.scheme.LayeredSocketFactory;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

/**
 * This socket factory will create ssl socket that uses configurable validation
 * of certificates (e.g. allowing self-signed).
 */
class WeaveSSLSocketFactory implements SocketFactory, LayeredSocketFactory {

	private static class WeaveX509TrustManager implements X509TrustManager {

		private X509TrustManager m_standardTrustManager = null;

		// private static boolean sm_issued = false;

		public WeaveX509TrustManager(KeyStore keystore)
				throws NoSuchAlgorithmException, KeyStoreException {
			super();
			TrustManagerFactory factory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			factory.init(keystore);
			TrustManager[] trustmanagers = factory.getTrustManagers();
			if (trustmanagers.length == 0) {
				throw new NoSuchAlgorithmException("no trust manager found");
			}
			m_standardTrustManager = (X509TrustManager) trustmanagers[0];
		}

		/**
		 * @see X509TrustManager#checkClientTrusted(X509Certificate[],String)
		 */
		@Override
		public void checkClientTrusted(X509Certificate[] certificates,
				String authType) throws CertificateException {
			m_standardTrustManager.checkClientTrusted(certificates, authType);
		}

		/**
		 * @see X509TrustManager#checkServerTrusted(X509Certificate[],String)
		 */
		@Override
		public void checkServerTrusted(X509Certificate[] certificates,
				String authType) throws CertificateException {
			// if (ENUMERATE_TRUSTED_CAS && !sm_issued) {
			// Dbg.d("CA certs:");
			// X509Certificate[] cas = getAcceptedIssuers();
			// for (X509Certificate ca : cas) {
			// Dbg.d("  " + ca.getSubjectDN());
			// }
			// sm_issued = true;
			// }

			if (DISABLE_SERVER_CERT_CHECK)
				return;

			// if ((certificates != null) && (certificates.length == 1)) {
			// // self-signed check
			// certificates[0].checkValidity();
			// } else {
			// // normal check
			// m_standardTrustManager.checkServerTrusted(certificates,
			// authType);
			// }
		}

		/**
		 * @see X509TrustManager#getAcceptedIssuers()
		 */
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return this.m_standardTrustManager.getAcceptedIssuers();
		}
	}

	// private static final boolean ENUMERATE_TRUSTED_CAS = false;

	private static final boolean DISABLE_SERVER_CERT_CHECK = true; // todo look
																	// into this

	private static SSLContext createEasySSLContext() throws IOException {
		try {
			SSLContext context = SSLContext.getInstance("TLS");
			context.init(null, new TrustManager[] { new WeaveX509TrustManager(
					null) }, null);
			return context;
		} catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	private SSLContext m_sslcontext = null;

	/**
	 * @see SocketFactory#connectSocket(Socket, String, int, InetAddress, int,
	 *      HttpParams)
	 */
	@Override
	public Socket connectSocket(Socket sock, String host, int port,
			InetAddress localAddress, int localPort, HttpParams params)
			throws IOException {

		int connTimeout = HttpConnectionParams.getConnectionTimeout(params);
		int soTimeout = HttpConnectionParams.getSoTimeout(params);

		InetSocketAddress remoteAddress = new InetSocketAddress(host, port);
		SSLSocket sslsock = (SSLSocket) ((sock != null) ? sock : createSocket());

		if ((localAddress != null) || (localPort > 0)) {
			if (localPort < 0) {
				localPort = 0;
			}
			InetSocketAddress isa = new InetSocketAddress(localAddress,
					localPort);
			sslsock.bind(isa);
		}

		sslsock.connect(remoteAddress, connTimeout);
		sslsock.setSoTimeout(soTimeout);
		return sslsock;

	}

	/**
	 * @see SocketFactory#createSocket()
	 */
	@Override
	public Socket createSocket() throws IOException {
		return getSSLContext().getSocketFactory().createSocket();
	}

	/**
	 * @see LayeredSocketFactory#createSocket(Socket, String, int, boolean)
	 */
	@Override
	public Socket createSocket(Socket socket, String host, int port,
			boolean autoClose) throws IOException {
		return getSSLContext().getSocketFactory().createSocket(socket, host,
				port, autoClose);
	}

	@Override
	public boolean equals(Object obj) {
		return ((obj != null) && obj.getClass().equals(
				WeaveSSLSocketFactory.class));
	}

	private synchronized SSLContext getSSLContext() throws IOException {
		if (m_sslcontext == null) {
			m_sslcontext = createEasySSLContext();
		}
		return m_sslcontext;
	}

	@Override
	public int hashCode() {
		return WeaveSSLSocketFactory.class.hashCode();
	}

	/**
	 * @see SocketFactory#isSecure(Socket)
	 */
	@Override
	public boolean isSecure(Socket socket) throws IllegalArgumentException {
		return true;
	}
}
