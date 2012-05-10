package org.emergent.android.weave.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class UserWeave {

	public enum CollectionNode {
		STORAGE_BOOKMARKS("bookmarks"), STORAGE_PASSWORDS("passwords"), ;

		public final String engineName;
		public final String nodePath;

		CollectionNode(String engineName) {
			this.engineName = engineName;
			this.nodePath = "/storage/" + this.engineName;
		}
	}

	public enum HashNode {
		INFO_COLLECTIONS(false, "/info/collections"), META_GLOBAL(false,
				"/storage/meta/global"), ;

		public final boolean userServer;
		public final String nodePath;

		HashNode(boolean userServer, String path) {
			this.userServer = userServer;
			this.nodePath = path;
		}
	}

	protected static URI buildSyncUriFromSubpath(URI clusterUri, String userId,
			QueryParams params, String pathSection) {
		String subpath = pathSection;
		if (params != null)
			subpath = subpath + params.toQueryString();
		WeaveUtil.checkNull(clusterUri);
		WeaveUtil.UriBuilder builder = WeaveUtil.buildUpon(clusterUri);
		builder.appendEncodedPath(WeaveConstants.WEAVE_API_VERSION + "/"
				+ userId);
		while (subpath.startsWith("/")) {
			subpath = subpath.substring(1);
		}
		builder.appendEncodedPath(subpath);
		return builder.build();
	}

	protected static URI buildSyncUriFromSubpath(URI clusterUri, String userId,
			String subpath) {
		return buildSyncUriFromSubpath(clusterUri, userId, null, subpath);
	}

	protected static URI buildUserUriFromSubpath(URI authUri, String userId,
			String subpath) {
		WeaveUtil.checkNull(authUri);
		WeaveUtil.UriBuilder builder = WeaveUtil.buildUpon(authUri);
		builder.appendEncodedPath("user/" + WeaveConstants.WEAVE_API_VERSION
				+ "/" + userId);
		while (subpath.startsWith("/")) {
			subpath = subpath.substring(1);
		}
		builder.appendEncodedPath(subpath);
		return builder.build();
	}

	private final WeaveTransport m_transport;
	private final URI m_authUri;
	@SuppressWarnings("unused")
	private final String m_userId;

	private final String m_password;

	private final String m_legalUsername;

	private final AtomicReference<URI> m_clusterUri;

	UserWeave(WeaveTransport transport, URI authUri, String userId,
			String password) {
		this(transport, authUri, userId, password, null);
	}

	protected UserWeave(WeaveTransport transport, URI authUri, String userId,
			String password, URI clusterUri) {
		m_authUri = authUri;
		m_userId = userId;
		m_legalUsername = WeaveCryptoUtil.getInstance()
				.legalizeUsername(userId);
		m_password = password;
		m_transport = transport;
		m_clusterUri = new AtomicReference<URI>(clusterUri);
	}

	public void authenticate() throws WeaveException {
		JSONObject jsonObj = getNode(HashNode.INFO_COLLECTIONS).getValue();
		jsonObj.has("foo");
	}

	public void authenticateSecret(char[] secret) throws WeaveException {
		authenticate();
	}

	public URI buildSyncUriFromSubpath(String subpath) throws WeaveException {
		return buildSyncUriFromSubpath(getClusterUri(), getLegalUsername(),
				subpath);
	}

	public URI buildUserUriFromSubpath(String subpath) {
		return buildUserUriFromSubpath(m_authUri, getLegalUsername(), subpath);
	}

	public boolean checkUsernameAvailable() throws WeaveException {
		try {
			String nodePath = "/";
			String nodeStrVal = getUserNode(nodePath).getBody();
			return Integer.parseInt(nodeStrVal) == 0;
		} catch (NumberFormatException e) {
			throw new WeaveException(e);
		}
	}

	protected BulkKeyCouplet getBulkKeyPair(byte[] syncKey)
			throws GeneralSecurityException, WeaveException {
		try {
			byte[] keyBytes = WeaveCryptoUtil.deriveSyncKey(syncKey,
					getLegalUsername());
			Key bulkKey = new SecretKeySpec(keyBytes, "AES");

			byte[] hmkeyBytes = WeaveCryptoUtil.deriveSyncHmacKey(syncKey,
					keyBytes, getLegalUsername());
			Key hmbulkKey = new SecretKeySpec(hmkeyBytes, "AES");

			JSONObject ckwbojsonobj = getCryptoKeys();

			WeaveBasicObject.WeaveEncryptedObject weo = new WeaveBasicObject.WeaveEncryptedObject(
					ckwbojsonobj);
			JSONObject ckencPayload = weo.decryptObject(bulkKey, hmbulkKey);

			JSONArray jsonArray = ckencPayload.getJSONArray("default");
			String bkey2str = jsonArray.getString(0);
			String bhmac2str = jsonArray.getString(1);
			byte[] bkey2bytes = Base64.decode(bkey2str);

			Key bulkKey2 = new SecretKeySpec(bkey2bytes, "AES");

			byte[] bhmac2bytes = Base64.decode(bhmac2str);

			Key bulkHmacKey2 = new SecretKeySpec(bhmac2bytes, "AES");

			return new BulkKeyCouplet(bulkKey2, bulkHmacKey2);
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	public final URI getClusterUri() throws WeaveException {
		return getClusterUri(true);
	}

	public final URI getClusterUri(boolean useCache) throws WeaveException {
		URI cached = null;
		if (useCache && ((cached = m_clusterUri.get()) != null))
			return cached;

		URI retval = getClusterUriSafe();
		m_clusterUri.compareAndSet(cached, retval);
		return retval;
	}

	private URI getClusterUriSafe() {
		URI retval = m_authUri;
		try {
			URI unsafeResult = getClusterUriUnsafe();
			if (unsafeResult != null)
				retval = unsafeResult;
		} catch (Exception ignored) {
			// Dbg.v(e);
		}
		return retval;
	}

	private URI getClusterUriUnsafe() throws WeaveException {
		try {
			String nodePath = "/node/weave";
			String nodeWeaveVal = getUserNode(nodePath).getBody();
			return new URI(nodeWeaveVal);
		} catch (URISyntaxException e) {
			throw new WeaveException(e);
		}
	}

	protected JSONObject getCryptoKeys() throws WeaveException {
		try {
			URI nodeUri = buildSyncUriFromSubpath("/storage/crypto/keys");
			WeaveBasicObject nodeObj = new WeaveBasicObject(nodeUri,
					new JSONObject(getNode(nodeUri).getBody()));
			return nodeObj.getPayload();
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	public String getLegalUsername() {
		return m_legalUsername;
	}

	public QueryResult<JSONObject> getNode(HashNode node) throws WeaveException {
		try {
			URI nodeUri = node.userServer ? buildUserUriFromSubpath(node.nodePath)
					: buildSyncUriFromSubpath(node.nodePath);
			WeaveResponse result = getNode(nodeUri);
			return new QueryResult<JSONObject>(result, new JSONObject(
					result.getBody()));
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	protected final WeaveResponse getNode(URI nodeUri) throws WeaveException {
		try {
			return m_transport.execGetMethod(getLegalUsername(), m_password,
					nodeUri);
		} catch (IOException e) {
			throw new WeaveException(e);
		}
	}

	protected RSAPublicKey getPublicKey() throws WeaveException {
		try {
			URI nodeUri = buildSyncUriFromSubpath("/storage/keys/pubkey");
			WeaveBasicObject nodeObj = new WeaveBasicObject(nodeUri,
					new JSONObject(getNode(nodeUri).getBody()));
			JSONObject payloadObj = nodeObj.getPayload();
			String pubKey = payloadObj.getString("keyData");
			return WeaveCryptoUtil.getInstance().readCertificatePubKey(pubKey);
		} catch (GeneralSecurityException e) {
			throw new WeaveException(e);
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	protected final WeaveResponse getUserNode(String path)
			throws WeaveException {
		URI nodeUri = buildUserUriFromSubpath(path);
		return getNode(nodeUri);
	}

	public QueryResult<List<WeaveBasicObject>> getWboCollection(URI uri)
			throws WeaveException {
		try {
			WeaveResponse response = getNode(uri);
			QueryResult<List<WeaveBasicObject>> result = new QueryResult<List<WeaveBasicObject>>(
					response);
			JSONArray jsonPassArray = new JSONArray(response.getBody());
			List<WeaveBasicObject> records = new ArrayList<WeaveBasicObject>();
			for (int ii = 0; ii < jsonPassArray.length(); ii++) {
				JSONObject jsonObj = jsonPassArray.getJSONObject(ii);
				WeaveBasicObject wbo = new WeaveBasicObject(uri, jsonObj);
				records.add(wbo);
			}
			result.setValue(records);
			return result;
		} catch (JSONException e) {
			throw new WeaveException(e);
		}
	}

	public final URI setClusterUri(URI clusterUri) {
		return m_clusterUri.getAndSet(clusterUri);
	}

	public void shutdown() {
		m_transport.shutdown();
	}
}
