package org.gaeproxy;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.apache.http.HttpHost;

import android.content.Context;
import android.os.Build;
import android.util.Log;

/**
 * Utility class for setting WebKit proxy used by Android WebView
 * 
 */
public class ProxySettings {

	private static final String TAG = "GAEProxy.ProxySettings";

	static final int PROXY_CHANGED = 193;

	private static Object getDeclaredField(Object obj, String name) throws SecurityException,
			NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
		Field f = obj.getClass().getDeclaredField(name);
		f.setAccessible(true);
		Object out = f.get(obj);
		// System.out.println(obj.getClass().getName() + "." + name + " = "+
		// out);
		return out;
	}

	public static Object getRequestQueue(Context ctx) throws Exception {
		Object ret = null;
		Class networkClass = Class.forName("android.webkit.Network");
		if (networkClass != null) {
			Object networkObj = invokeMethod(networkClass, "getInstance", new Object[] { ctx },
					Context.class);
			if (networkObj != null) {
				ret = getDeclaredField(networkObj, "mRequestQueue");
			}
		}
		return ret;
	}

	private static Object invokeMethod(Object object, String methodName, Object[] params,
			Class... types) throws Exception {
		Object out = null;
		Class c = object instanceof Class ? (Class) object : object.getClass();
		if (types != null) {
			Method method = c.getMethod(methodName, types);
			out = method.invoke(object, params);
		} else {
			Method method = c.getMethod(methodName);
			out = method.invoke(object);
		}
		// System.out.println(object.getClass().getName() + "." + methodName +
		// "() = "+ out);
		return out;
	}

	public static void resetProxy(Context ctx) throws Exception {
		Object requestQueueObject = getRequestQueue(ctx);
		if (requestQueueObject != null) {
			setDeclaredField(requestQueueObject, "mProxyHost", null);
		}
	}

	private static void setDeclaredField(Object obj, String name, Object value)
			throws SecurityException, NoSuchFieldException, IllegalArgumentException,
			IllegalAccessException {
		Field f = obj.getClass().getDeclaredField(name);
		f.setAccessible(true);
		f.set(obj, value);
	}

	/**
	 * Override WebKit Proxy settings
	 * 
	 * @param ctx
	 *            Android ApplicationContext
	 * @param host
	 * @param port
	 * @return true if Proxy was successfully set
	 */
	public static boolean setProxy(Context ctx, String host, int port) {
		boolean ret = false;
		setSystemProperties(host, port);

		try {
			if (Build.VERSION.SDK_INT < 14) {

				Object requestQueueObject = getRequestQueue(ctx);
				if (requestQueueObject != null) {
					// Create Proxy config object and set it into request Q
					HttpHost httpHost = new HttpHost(host, port, "http");

					setDeclaredField(requestQueueObject, "mProxyHost", httpHost);
					ret = true;
				}

			} else {
				ret = setICSProxy(host, port);
			}
		} catch (Exception e) {
			Log.e(TAG, "error setting up webkit proxying", e);
		}
		return ret;
	}

	private static boolean setICSProxy(String host, int port) throws ClassNotFoundException,
			NoSuchMethodException, IllegalArgumentException, InstantiationException,
			IllegalAccessException, InvocationTargetException {
		Class webViewCoreClass = Class.forName("android.webkit.WebViewCore");
		Class proxyPropertiesClass = Class.forName("android.net.ProxyProperties");
		if (webViewCoreClass != null && proxyPropertiesClass != null) {
			Method m = webViewCoreClass.getDeclaredMethod("sendStaticMessage", Integer.TYPE,
					Object.class);
			Constructor c = proxyPropertiesClass.getConstructor(String.class, Integer.TYPE,
					String.class);
			m.setAccessible(true);
			c.setAccessible(true);
			Object properties = c.newInstance(host, port, null);
			m.invoke(null, PROXY_CHANGED, properties);
			return true;
		}
		return false;

	}

	private static void setSystemProperties(String host, int port) {

		System.setProperty("http.proxyHost", host);
		System.setProperty("http.proxyPort", port + "");

		System.setProperty("https.proxyHost", host);
		System.setProperty("https.proxyPort", port + "");

	}
}
