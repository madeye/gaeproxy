package org.gaeproxy;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Hashtable;

import android.util.Log;

/**
 * 此类封装了一个Dns回应
 * 
 * @author biaji
 * 
 */
class DnsResponse implements Serializable {

	private static final long serialVersionUID = -6693216674221293274L;

	private String request = null;
	private long timestamp = System.currentTimeMillis();;
	private int reqTimes = 0;
	private byte[] dnsResponse = null;

	public DnsResponse(String request) {
		this.request = request;
	}

	/**
	 * @return the dnsResponse
	 */
	public byte[] getDnsResponse() {
		this.reqTimes++;
		return dnsResponse;
	}

	/**
	 * @return IP string
	 */
	public String getIPString() {
		String ip = null;
		int i;

		if (dnsResponse == null) {
			return null;
		}

		i = dnsResponse.length - 4;

		if (i < 0) {
			return null;
		}

		ip = "" + (dnsResponse[i] & 0xFF); /* Unsigned byte to int */

		for (i++; i < dnsResponse.length; i++) {
			ip += "." + (dnsResponse[i] & 0xFF);
		}

		return ip;
	}

	/**
	 * @return the reqTimes
	 */
	public int getReqTimes() {
		return reqTimes;
	}

	public String getRequest() {
		return this.request;
	}

	/**
	 * @return the timestamp
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * @param dnsResponse
	 *            the dnsResponse to set
	 */
	public void setDnsResponse(byte[] dnsResponse) {
		this.dnsResponse = dnsResponse;
	}
}

/**
 * 此类实现了DNS代理
 * 
 * @author biaji
 * 
 */
public class DNSServer implements WrapServer {

	public static byte[] int2byte(int res) {
		byte[] targets = new byte[4];

		targets[0] = (byte) (res & 0xff);// 最低位
		targets[1] = (byte) ((res >> 8) & 0xff);// 次低位
		targets[2] = (byte) ((res >> 16) & 0xff);// 次高位
		targets[3] = (byte) (res >>> 24);// 最高位,无符号右移。
		return targets;
	}

	private final String TAG = "CMWRAP->DNSServer";
	private String homePath;
	private final String CACHE_PATH = "cache/";

	private final String CACHE_FILE = "dnscache";

	private DatagramSocket srvSocket;

	private int srvPort = 8153;
	private String name;
	protected String dnsHost;
	protected int dnsPort;
	final protected int DNS_PKG_HEADER_LEN = 12;
	final private int[] DNS_HEADERS = { 0, 0, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0,
			0 };
	final private int[] DNS_PAYLOAD = { 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x3c, 0x00, 0x04 };

	final private int IP_SECTION_LEN = 4;

	private boolean inService = false;

	private Hashtable<String, DnsResponse> dnsCache = new Hashtable<String, DnsResponse>();

	/**
	 * 内建自定义缓存
	 * 
	 */
	private Hashtable<String, String> orgCache = new Hashtable<String, String>();

	private String target = "8.8.8.8:53";

	private String appHost = "203.208.39.99";

	public DNSServer(String name, int port, String dnsHost, int dnsPort,
			String appHost) {
		this.name = name;
		this.srvPort = port;
		this.dnsHost = dnsHost;
		this.dnsPort = dnsPort;
		this.appHost = appHost;

		if (dnsHost != null && !dnsHost.equals(""))
			target = dnsHost + ":" + dnsPort;

		try {
			srvSocket = new DatagramSocket(srvPort,
					InetAddress.getByName("127.0.0.1"));
			Log.e(TAG, this.name + "启动于端口： " + port);
			inService = true;
		} catch (SocketException e) {
			Log.e(TAG, "DNSServer初始化错误，端口号" + port, e);
		} catch (UnknownHostException e) {
			Log.e(TAG, "DNSServer初始化错误，端口号" + port, e);
		}
	}

	/**
	 * 在缓存中添加一个域名解析
	 * 
	 * @param questDomainName
	 *            域名
	 * @param answer
	 *            解析结果
	 */
	private void addToCache(String questDomainName, byte[] answer) {
		DnsResponse response = new DnsResponse(questDomainName);
		response.setDnsResponse(answer);
		dnsCache.put(questDomainName, response);
		saveCache();
	}

	@Override
	public void close() throws IOException {
		inService = false;
		srvSocket.close();
		saveCache();
		Log.i(TAG, "DNS服务关闭");
	}

	/*
	 * Create a DNS response packet, which will send back to application.
	 * 
	 * @author yanghong
	 * 
	 * Reference to:
	 * 
	 * Mini Fake DNS server (Python)
	 * http://code.activestate.com/recipes/491264-mini-fake-dns-server/
	 * 
	 * DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
	 * http://www.ietf.org/rfc/rfc1035.txt
	 */
	protected byte[] createDNSResponse(byte[] quest, byte[] ips) {
		byte[] response = null;
		int start = 0;

		response = new byte[128];

		for (int val : DNS_HEADERS) {
			response[start] = (byte) val;
			start++;
		}

		System.arraycopy(quest, 0, response, 0, 2); /* 0:2 */
		System.arraycopy(quest, 4, response, 4, 2); /* 4:6 -> 4:6 */
		System.arraycopy(quest, 4, response, 6, 2); /* 4:6 -> 7:9 */
		System.arraycopy(quest, DNS_PKG_HEADER_LEN, response, start,
				quest.length - DNS_PKG_HEADER_LEN); /* 12:~ -> 15:~ */
		start += quest.length - DNS_PKG_HEADER_LEN;

		for (int val : DNS_PAYLOAD) {
			response[start] = (byte) val;
			start++;
		}

		/* IP address in response */
		for (byte ip : ips) {
			response[start] = ip;
			start++;
		}

		byte[] result = new byte[start];
		System.arraycopy(response, 0, result, 0, start);
		Log.d(TAG, "DNS Response package size: " + start);

		return result;
	}

	/**
	 * 由上级DNS通过TCP取得解析
	 * 
	 * @param quest
	 *            原始DNS请求
	 * @return
	 */
	protected byte[] fetchAnswer(byte[] quest) {

		Socket innerSocket = new InnerSocketBuilder(dnsHost, dnsPort, target)
				.getSocket();
		DataInputStream in;
		DataOutputStream out;
		byte[] result = null;
		try {
			if (innerSocket != null && innerSocket.isConnected()) {
				// 构造TCP DNS包
				int dnsqLength = quest.length;
				byte[] tcpdnsq = new byte[dnsqLength + 2];
				System.arraycopy(int2byte(dnsqLength), 0, tcpdnsq, 1, 1);
				System.arraycopy(quest, 0, tcpdnsq, 2, dnsqLength);

				// 转发DNS
				in = new DataInputStream(innerSocket.getInputStream());
				out = new DataOutputStream(innerSocket.getOutputStream());
				out.write(tcpdnsq);
				out.flush();

				ByteArrayOutputStream bout = new ByteArrayOutputStream();

				int b = -1;
				while ((b = in.read()) != -1) {
					bout.write(b);
				}
				byte[] tcpdnsr = bout.toByteArray();
				if (tcpdnsr != null && tcpdnsr.length > 2) {
					result = new byte[tcpdnsr.length - 2];
					System.arraycopy(tcpdnsr, 2, result, 0, tcpdnsr.length - 2);
				}
				innerSocket.close();
			}
		} catch (IOException e) {
			Log.e(TAG, "", e);
		}
		return result;
	}

	/**
	 * 获取UDP DNS请求的域名
	 * 
	 * @param request
	 *            dns udp包
	 * @return 请求的域名
	 */
	protected String getRequestDomain(byte[] request) {
		String requestDomain = "";
		int reqLength = request.length;
		if (reqLength > 13) { // 包含包体
			byte[] question = new byte[reqLength - 12];
			System.arraycopy(request, 12, question, 0, reqLength - 12);
			requestDomain = parseDomain(question);
			requestDomain = requestDomain.substring(0,
					requestDomain.length() - 1);
		}
		return requestDomain;
	}

	@Override
	public int getServPort() {
		return this.srvPort;
	}

	private void initOrgCache() {
		try {
			URL aURL = new URL("http://myhosts.sinaapp.com/hosts");
			HttpURLConnection conn = (HttpURLConnection) aURL.openConnection();
			conn.connect();
			InputStream is = conn.getInputStream();
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(is));
			String line = reader.readLine();
			if (line == null)
				return;
			if (!line.startsWith("#SSHTunnel"))
				return;
			while (true) {
				line = reader.readLine();
				if (line == null)
					break;
				if (line.startsWith("#"))
					continue;
				line = line.trim().toLowerCase();
				if (line.equals(""))
					continue;
				String[] hosts = line.split(" ");
				if (hosts.length == 2) {
					orgCache.put(hosts[1], hosts[0]);
					Log.d(TAG, hosts[0] + " " + hosts[1]);
				}
			}
		} catch (Exception e) {
			Log.e(TAG, "cannot get remote host files", e);
		}

	}

	@Override
	public boolean isClosed() {
		return srvSocket.isClosed();
	}

	public boolean isInService() {
		return inService;
	}

	/**
	 * 由缓存载入域名解析缓存
	 */
	private void loadCache() {
		ObjectInputStream ois = null;
		File cache = new File(homePath + CACHE_PATH + CACHE_FILE);
		try {
			if (!cache.exists())
				return;
			ois = new ObjectInputStream(new FileInputStream(cache));
			dnsCache = (Hashtable<String, DnsResponse>) ois.readObject();
			ois.close();
			ois = null;

			Hashtable<String, DnsResponse> tmpCache = (Hashtable<String, DnsResponse>) dnsCache
					.clone();
			for (DnsResponse resp : dnsCache.values()) {
				// 检查缓存时效(十天)
				if ((System.currentTimeMillis() - resp.getTimestamp()) > 864000000L) {
					Log.d(TAG, "删除" + resp.getRequest() + "记录");
					tmpCache.remove(resp.getRequest());
				}
			}

			dnsCache = tmpCache;
			tmpCache = null;

		} catch (ClassCastException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} catch (FileNotFoundException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} catch (IOException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} catch (ClassNotFoundException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} finally {
			try {
				if (ois != null)
					ois.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * 解析域名
	 * 
	 * @param request
	 * @return
	 */
	private String parseDomain(byte[] request) {

		String result = "";
		int length = request.length;
		int partLength = request[0];
		if (partLength == 0)
			return result;
		try {
			byte[] left = new byte[length - partLength - 1];
			System.arraycopy(request, partLength + 1, left, 0, length
					- partLength - 1);
			result = new String(request, 1, partLength) + ".";
			result += parseDomain(left);
		} catch (Exception e) {
			Log.e(TAG, e.getLocalizedMessage());
		}
		return result;
	}

	/*
	 * Parse IP string into byte, do validation.
	 * 
	 * @param ip IP string
	 * 
	 * @return IP in byte array
	 */
	protected byte[] parseIPString(String ip) {
		byte[] result = null;
		int value;
		int i = 0;
		String[] ips = null;

		ips = ip.split("\\.");

		Log.d(TAG, "Start parse ip string: " + ip + ", Sectons: " + ips.length);

		if (ips.length != IP_SECTION_LEN) {
			Log.e(TAG, "Malformed IP string number of sections is: "
					+ ips.length);
			return null;
		}

		result = new byte[IP_SECTION_LEN];

		for (String section : ips) {
			try {
				value = Integer.parseInt(section);

				/* 0.*.*.* and *.*.*.0 is invalid */
				if ((i == 0 || i == 3) && value == 0) {
					return null;
				}

				result[i] = (byte) value;
				i++;
			} catch (NumberFormatException e) {
				Log.e(TAG, "Malformed IP string section: " + section);
				return null;
			}
		}

		return result;
	}

	@Override
	public void run() {

		initOrgCache();
		loadCache();

		byte[] qbuffer = new byte[576];
		long starTime = System.currentTimeMillis();

		while (true) {
			try {
				DatagramPacket dnsq = new DatagramPacket(qbuffer,
						qbuffer.length);

				srvSocket.receive(dnsq);
				// 连接外部DNS进行解析。

				byte[] data = dnsq.getData();
				int dnsqLength = dnsq.getLength();
				byte[] udpreq = new byte[dnsqLength];
				System.arraycopy(data, 0, udpreq, 0, dnsqLength);
				// 尝试从缓存读取域名解析
				String questDomain = getRequestDomain(udpreq);

				Log.d(TAG, "解析" + questDomain);

				// if (questDomain.toLowerCase().contains("appspot.com")) {
				// byte[] ips = parseIPString(appHost);
				// byte[] answer = createDNSResponse(udpreq, ips);
				// addToCache(questDomain, answer);
				// }

				if (questDomain.toLowerCase().contains("google.cn")) {
					
					byte[] ips = parseIPString(appHost);
					byte[] answer = createDNSResponse(udpreq, ips);
					sendDns(answer, dnsq, srvSocket);
					
				} else if (dnsCache.containsKey(questDomain)) {

					sendDns(dnsCache.get(questDomain).getDnsResponse(), dnsq,
							srvSocket);

					Log.d(TAG, "命中缓存");

				} else if (orgCache.containsKey(questDomain)) { // 如果为自定义域名解析
					byte[] ips = parseIPString(orgCache.get(questDomain));
					byte[] answer = createDNSResponse(udpreq, ips);
					addToCache(questDomain, answer);
					sendDns(answer, dnsq, srvSocket);
					Log.d(TAG, "自定义解析" + orgCache);
				} else {
					starTime = System.currentTimeMillis();
					byte[] answer = fetchAnswer(udpreq);
					if (answer != null && answer.length != 0) {
						addToCache(questDomain, answer);
						sendDns(answer, dnsq, srvSocket);
						Log.d(TAG, "正确返回DNS解析，长度：" + answer.length + "  耗时："
								+ (System.currentTimeMillis() - starTime)
								/ 1000 + "s");
					} else {
						Log.e(TAG, "返回DNS包长为0");
					}

				}

				/* For test, validate dnsCache */
				/*
				 * if (dnsCache.size() > 0) { Log.d(TAG, "Domains in cache:");
				 * 
				 * Enumeration<String> enu = dnsCache.keys(); while
				 * (enu.hasMoreElements()) { String domain = (String)
				 * enu.nextElement(); DnsResponse resp = dnsCache.get(domain);
				 * 
				 * Log.d(TAG, domain + " : " + resp.getIPString()); } }
				 */

			} catch (SocketException e) {
				Log.e(TAG, e.getLocalizedMessage());
				break;
			} catch (IOException e) {
				Log.e(TAG, e.getLocalizedMessage());
			}
		}

	}

	/**
	 * 保存域名解析内容缓存
	 */
	private void saveCache() {
		ObjectOutputStream oos = null;
		File cache = new File(homePath + CACHE_PATH + CACHE_FILE);
		try {
			if (!cache.exists()) {
				File cacheDir = new File(homePath + CACHE_PATH);
				if (!cacheDir.exists()) { // android的createNewFile这个方法真够恶心的啊
					cacheDir.mkdir();
				}
				cache.createNewFile();
			}
			oos = new ObjectOutputStream(new FileOutputStream(cache));
			oos.writeObject(dnsCache);
			oos.flush();
			oos.close();
			oos = null;
		} catch (FileNotFoundException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} catch (IOException e) {
			Log.e(TAG, e.getLocalizedMessage(), e);
		} finally {
			try {
				if (oos != null)
					oos.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * 向来源发送dns应答
	 * 
	 * @param response
	 *            应答包
	 * @param dnsq
	 *            请求包
	 * @param srvSocket
	 *            侦听Socket
	 */
	private void sendDns(byte[] response, DatagramPacket dnsq,
			DatagramSocket srvSocket) {

		// 同步identifier
		System.arraycopy(dnsq.getData(), 0, response, 0, 2);

		DatagramPacket resp = new DatagramPacket(response, 0, response.length);
		resp.setPort(dnsq.getPort());
		resp.setAddress(dnsq.getAddress());

		try {
			srvSocket.send(resp);
		} catch (IOException e) {
			Log.e(TAG, "", e);
		}
	}

	public void setBasePath(String path) {
		this.homePath = path;
	}

	@Override
	public void setProxyHost(String host) {
		// TODO Auto-generated method stub

	}

	public void setTarget(String target) {
		this.target = target;
	}

	public boolean test(String domain, String ip) {
		boolean ret = true;

		// TODO: Implement test case

		return ret;
	}

}
