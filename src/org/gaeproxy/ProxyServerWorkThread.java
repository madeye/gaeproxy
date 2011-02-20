package org.gaeproxy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;

import com.jcraft.jzlib.ZInputStream;

import android.util.Log;

public class ProxyServerWorkThread implements Runnable {
	public static final String TAG = ProxyServerWorkThread.class
			.getSimpleName();
	Socket mClienSocket;

	SSLSocket mSSLSocket;

	String mGappProxyURL;
	
	//输入数据的最大长度
	 private static final int MAXLENGTH = 102400;
	 private static final int BUFFERSIZE = 1024;

	public static final String REQUEST_URL = "Request_URL";
	public static final String REQUEST_METHOD = "Request_METHOD";

	public ProxyServerWorkThread(Socket clientSocket, String fetchServerUrl) {
		// TODO Auto-generated constructor stub
		mClienSocket = clientSocket;
		mGappProxyURL = fetchServerUrl;
	}

	@Override
	public void run() {
		if (null == mClienSocket) {
			Log.d(TAG, "The socket is invalid");
			return;
		}

		Log.d(TAG, "A Client Connected:");
		String host = mClienSocket.getInetAddress().getHostAddress();
		String hostName = mClienSocket.getInetAddress().getHostName();
		Log.d(TAG, "Client Host:" + host);
		Log.d(TAG, "Client HostName:" + hostName);

		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(
					mClienSocket.getInputStream()));
			OutputStream os = mClienSocket.getOutputStream();
			PrintWriter pw = new PrintWriter(os, true);

			String line = null;
			StringBuffer stringBuffer = new StringBuffer();
			HashMap<String, String> hashMap = new HashMap<String, String>();

			int startGetPostData = 0;
			while (true) {
				line = br.readLine();

				Log.d(TAG, "Received:" + line);
				stringBuffer.append(line + '\n');

				if (line == null) {
					break;
				}
				Log.d(TAG, "Received:length=" + line.length());

				if (!hashMap.containsKey("METHOD")) {
					if (line.startsWith("GET")) {
						hashMap.put(REQUEST_METHOD, "GET");
						String getValue = line.split(" ")[1];
						hashMap.put(REQUEST_URL, getValue);
						hashMap = handleGET(br, hashMap, line);
						break;
					}

					if (line.startsWith("POST")) {
						Log.d(TAG, "It is post METHOD");
						hashMap.put(REQUEST_METHOD, "POST");
						String getValue = line.split(" ")[1];
						hashMap.put(REQUEST_URL, getValue);
						hashMap = handlePOST(br, hashMap, line);
						break;
					}

					if (line.startsWith("CONNECT")) {
						Log.d(TAG, "It is CONNECT METHOD");
						hashMap.put(REQUEST_METHOD, "CONNECT");
						String getValue = line.split(" ")[1];
						hashMap.put(REQUEST_URL, getValue);
						break;
					}
				}
				if (line.length() == 0) {
					if (null != hashMap.get(REQUEST_METHOD)) {
						if (hashMap.get(REQUEST_METHOD).equals("POST")) {
							Log.d(TAG, "get post data br.readLine");
							line = br.readLine();
							Log.d(TAG, "get post data line=" + line);

							int length = 0;
							if (hashMap.containsKey("Content-Length")) {
								length = Integer.valueOf(hashMap.get(
										"Content-Length").replace(" ", ""));
								Log.d(TAG, "Content-Length=" + length);
							}

							if (null == line) {
								line = br.readLine();
							}
							Log.d(TAG, "get post data line=" + line);

							Log.d(TAG, "get post data line=" + line);

							String postData = line;
							while (null != line) {
								postData += line + '\n';
								if (length == postData.length()) {
									line = null;
									break;
								}
								line = br.readLine();
							}

							hashMap.put("POST_DATA", postData);
							Log.d(TAG, "post data=" + postData);

							break;
						} else {
							break;
						}
					} else {
						break;
					}
				}

				if (startGetPostData == 0 && null != line) {
					int index = line.indexOf(":");
					if (index < 0) {
						continue;
					}

					// Log.d(TAG, "index="+index+" of "+line.length());
					String key = line.substring(0, index);
					String value = line.substring(index + 1, line.length());
					hashMap.put(key, value);
				}
			}

			List<NameValuePair> nvp = createParams(hashMap);

			HttpResponse httpResponse = doHttpPost(mGappProxyURL, nvp);

			Log.d(TAG,
					"**************print response********************");
			Log.d(TAG, "statusLine=" + httpResponse.getStatusLine());
			
			/* Construct the response */
			
			StringBuffer resp = new StringBuffer();
			boolean isText = false;
			
			InputStreamReader inrd = new InputStreamReader(httpResponse.getEntity().getContent());
			BufferedReader inbr = new BufferedReader(inrd);

	        line = inbr.readLine();
	        String [] words = line.split(" ");
	        if (words.length < 2)
	        	return;
	        String status = words[1].trim();
	
			if (status.equals(592) && hashMap.get("REQUEST_METHOD").equals("GET")) {
	            //processLargeResponse(path)
	            //connection.close()
	            return;
			}
			
			// write status to response
			resp.append(line);
			resp.append("\n");
	
			// do with headers
			while (true) {
				line = inbr.readLine().trim();
				if (line == null)
					break;
				if (line.equals(""))
					break;
				int index = line.indexOf(":");
				if (index < 0) {
					continue;
				}
	
				String key = line.substring(0, index);
				String value = line.substring(index + 1, line.length());
				
				if (key.toLowerCase().equals("accept-ranges"))
					continue;
				
				resp.append(line);
				
				if (key.toLowerCase().equals("content-type")) {
					if (value.toLowerCase().contains("text"))
						isText = true;
				}
			}
			
			// headers done
			resp.append("\n");
			
			StringBuffer content = new StringBuffer();

			if (isText) {
				while (true) {
					int t = inbr.read();
					if (t == -1)
						break;
					content.append(line);
				}
			}
			
			
			
			os.write(null);
			os.close();
			pw.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	  * 解压被压缩的数据
	  * @param object
	  * @return
	  * @throws IOException
	  */
	 public static byte[] UnCompress(byte[] object) throws IOException {

	  byte[] data = new byte[MAXLENGTH];
	  try {
	   ByteArrayInputStream in = new ByteArrayInputStream(object);
	   ZInputStream zIn = new ZInputStream(in);
	   DataInputStream objIn = new DataInputStream(zIn);

	   int len = 0;
	   int count = 0;
	   while ((count = objIn.read(data, len, len + BUFFERSIZE)) != -1) {
	    len = len + count;
	   }

	   byte[] trueData = new byte[len];
	   System.arraycopy(data, 0, trueData, 0, len);

	   objIn.close();
	   zIn.close();
	   in.close();

	   return trueData;

	  } catch (IOException e) {
	   e.printStackTrace();
	   throw e;
	  }
	 }
	
	List<NameValuePair> createParams(HashMap<String, String> hashmap) {
		Log.d(TAG, "************************printHeader*********************");
		String headers = "";
		List<NameValuePair> nvp = new ArrayList<NameValuePair>();
		nvp.add(new BasicNameValuePair("method", hashmap.get(REQUEST_METHOD)));
		nvp.add(new BasicNameValuePair("encoded_path", encode(hashmap
				.get(REQUEST_URL))));

		hashmap.remove(REQUEST_METHOD);
		hashmap.remove(REQUEST_URL);
		Iterator<String> iterator = hashmap.keySet().iterator();
		while (iterator.hasNext()) {
			String key = iterator.next();
			String value = (String) hashmap.get(key);
			Log.d(TAG, key + "=" + value);
			headers += key + ":" + value;
		}

		Log.d(TAG, "headers=" + headers);

		nvp.add(new BasicNameValuePair("headers", headers));
		nvp.add(new BasicNameValuePair("postdata", hashmap.get("POST_DATA")));
		nvp.add(new BasicNameValuePair("version", "2.0.0"));

		return nvp;
	}

	HttpResponse doHttpPost(String url, List<NameValuePair> nvp) {
		Log.d(TAG, "doHttpPost");
		DefaultHttpClient httpClient = new DefaultHttpClient();

		Log.e(TAG, "Proxy url: " + url);
		HttpPost httpPost = new HttpPost(url);
		HttpResponse response = null;
		try {
			httpPost.setEntity(new UrlEncodedFormEntity(nvp, HTTP.UTF_8));
			httpPost.addHeader("Accept-Encoding", "identity, *;q=0");
			httpPost.addHeader("Connection", "close");

			response = httpClient.execute(httpPost);

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// httpClient.getConnectionManager().shutdown();
		return response;
	}

	void connectToProxyServer(String url, List<NameValuePair> nvp) {
		try {
			URLConnection uc = new URL(url).openConnection();
			InputStream is = uc.getInputStream();

		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	void writeResultToClient(PrintWriter pw, String result) {
		// pw.println("HTTP/1.1 200 OK\r\n");
		// pw.println("\r\n");
		try {
			result.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		pw.write(result);
	}

	void writeResult(PrintWriter pw) {
		pw.println("HTTP/1.1 200 OK\r\n");
		pw.println("\r\n");
		// pw.write("Request received.");
		pw.println("<html>  <head>  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /> <title>GAppProxy已经在工作了</title>  </head><body>Say Hello</body></html> ");
		pw.flush();
	}

	String getMETHOD(StringBuffer stringBuffer) {
		if (null == stringBuffer) {
			return null;
		}

		return null;
	}

	public static String encode(String str) {
		Log.d(TAG, "str=" + str);

		if (null == str) {
			return null;
		}

		Base64 base64 = new Base64();
		String encodedStr = "";
		try {
			byte[] bytes = base64.encode(str.getBytes("UTF-8"));
			encodedStr = new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Log.d(TAG, "encoded str=" + encodedStr);

		return encodedStr;
	}

	HashMap<String, String> handleGET(BufferedReader br,
			HashMap<String, String> hashMap, String firstline) {
		Log.d(TAG, "handleGET");
		String line = firstline;
		int length = 0;

		while (true) {
			try {
				line = br.readLine();
				length = line.length();
				if (0 == length) {
					break;
				}

				if (null != line) {
					int index = line.indexOf(":");
					if (index < 0) {
						continue;
					}

					// Log.d(TAG, "index="+index+" of "+line.length());
					String key = line.substring(0, index);
					String value = line.substring(index + 1, line.length());
					hashMap.put(key, value);
				}

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return hashMap;
	}

	HashMap<String, String> handlePOST(BufferedReader br,
			HashMap<String, String> hashMap, String firstline) {
		Log.d(TAG, "handlePOST");
		String line = firstline;
		int length = 0;
		while (true) {
			try {
				line = br.readLine();
				length = line.length();

				Log.d(TAG, "line=" + line + ",length=" + length);

				if (0 == length) {
					int contentLength = Integer.valueOf(hashMap.get(
							"Content-Length").replace(" ", ""));
					int readLength = 0;
					String postData = "";
					Log.d(TAG, "Get Post data,contentLength=" + contentLength);
					while (readLength < contentLength) {
						line = br.readLine() + '\n';
						readLength += line.length();
						postData += line;
						Log.d(TAG, "line=" + line + ",readLength=" + readLength);
					}

					hashMap.put("POST_DATA", postData);
					Log.d(TAG, "post data=" + postData);
					break;
				}

				int index = line.indexOf(":");
				if (index < 0) {
					continue;
				}

				// Log.d(TAG, "index="+index+" of "+line.length());
				String key = line.substring(0, index);
				String value = line.substring(index + 1, line.length());
				hashMap.put(key, value);

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return hashMap;

	}

	void handleCONNECT() {
		Log.d(TAG, "handlePOST");

		SSLContext sslContext = null;
		try {
			sslContext = SSLContext.getInstance("SSLv3");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// sslContext.init(kmf.getKeyManagers(),null,null);

		SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

		SocketFactory SS = SSLSocketFactory.getDefault();

		try {
			SSLServerSocket s = (SSLServerSocket) factory
					.createServerSocket(9999);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
