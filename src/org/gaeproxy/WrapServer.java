package org.gaeproxy;

import java.io.IOException;

public interface WrapServer extends Runnable {

	public abstract void close() throws IOException;

	public abstract int getServPort();

	public abstract boolean isClosed();

	public abstract void setProxyHost(String host);
}
