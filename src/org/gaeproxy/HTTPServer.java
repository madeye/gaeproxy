package org.gaeproxy;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

import android.util.Log;

public class HTTPServer implements WrapServer {
	
	private final String TAG = "HTTPServer";
	private int port = 1984;
	private String proxy = "";
	ServerSocket serverSocket = null;
	


	private boolean inService = false;

	public HTTPServer (String proxy, int port) {
		this.proxy = proxy;
		try {
			serverSocket = new ServerSocket(port);
			inService = true;
		} catch (SocketException e) {
			Log.e(TAG, "HTTPServer socket error" + port, e);
		} catch (Exception e) {
			Log.e(TAG, "HTTPServer cannot start" + port, e);
		}
	}
	
	@Override
	public void run() {
		
        Log.d(TAG, "startServer:port=" + port);

        try {
            while (true) {
                Log.d(TAG, "waiting for connect...");
                Socket client = serverSocket.accept();
                //new Thread(new ProxyServerWorkThread(client, proxy)).start();
                new ProxyServerWorkThread(client, proxy).run();
            }

        } catch (IOException e) {
        	Log.d(TAG, "Cannot construct socket");
        }
	}

	@Override
	public void close() throws IOException {
		serverSocket.close();
	}

	@Override
	public int getServPort() {
		return port;
	}

	@Override
	public boolean isClosed() {
		inService = false;
		return serverSocket.isClosed();
	}

	@Override
	public void setProxyHost(String host) {
		this.proxy = host;
	}
	
	public boolean isInService() {
		return inService;
	}

	public void setInService(boolean inService) {
		this.inService = inService;
	}

}
