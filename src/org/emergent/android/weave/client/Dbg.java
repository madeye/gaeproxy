package org.emergent.android.weave.client;

import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * @author Patrick Woodworth
 */
class Dbg {

	@SuppressWarnings("serial")
	public static class DebugLogRecord extends LogRecord {

		/**
		 * @serial Class that issued logging call
		 */
		private String sourceClassName;

		/**
		 * @serial Method that issued logging call
		 */
		private String sourceMethodName;

		private transient boolean needToInferCaller = true;

		DebugLogRecord(Level level, String msg) {
			super(level, msg);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public String getSourceClassName() {
			if (sourceClassName == null) {
				inferCaller();
			}
			return sourceClassName;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public String getSourceMethodName() {
			if (needToInferCaller) {
				inferCaller();
			}
			return sourceMethodName;
		}

		private void inferCaller() {
			// Get the stack trace.
			StackTraceElement stack[] = (new Throwable()).getStackTrace();
			// First, search back to a method in the Logger class.
			int ix = 0;
			while (ix < stack.length) {
				StackTraceElement frame = stack[ix];
				String cname = frame.getClassName();
				if (cname.equals(Dbg.class.getName())) {
					break;
				}
				ix++;
			}
			// Now search for the first frame before the "Logger" class.
			while (ix < stack.length) {
				StackTraceElement frame = stack[ix];
				String cname = frame.getClassName();
				if (!cname.equals(Dbg.class.getName())) {
					// We've found the relevant frame.
					setSourceClassName(cname);
					setSourceMethodName(frame.getMethodName());
					return;
				}
				ix++;
			}
			// We haven't found a suitable frame, so just punt. This is
			// OK as we are only committed to making a "best effort" here.
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void setSourceClassName(String sourceClassName) {
			this.sourceClassName = sourceClassName;
			needToInferCaller = false;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void setSourceMethodName(String sourceMethodName) {
			this.sourceMethodName = sourceMethodName;
			needToInferCaller = false;
		}
	}

	private static final Level LEVEL_ANDROID_VERBOSE = Level.FINE; // should
	// never
	// ship
	// using
	// this
	private static final Level LEVEL_ANDROID_DEBUG = Level.CONFIG; // stripped
	// at
	// runtime
	// (except
	// on
	// emulator?)
	@SuppressWarnings("unused")
	private static final Level LEVEL_ANDROID_INFO = Level.INFO;
	private static final Level LEVEL_ANDROID_WARN = Level.WARNING;

	@SuppressWarnings("unused")
	private static final Level LEVEL_ANDROID_ERROR = Level.SEVERE;
	@SuppressWarnings("unused")
	private static final Level LEVEL_V = LEVEL_ANDROID_VERBOSE;
	// private static final Level LEVEL_D = LEVEL_ANDROID_INFO;
	private static final Level LEVEL_D = LEVEL_ANDROID_DEBUG;

	private static final Level LEVEL_W = LEVEL_ANDROID_WARN;

	private static final Logger sm_logger = Logger
			.getLogger(WeaveConstants.LOGGER_NAME_FULL);

	public static void d(String fmt, Object... args) {
		logf(LEVEL_D, fmt, args);
	}

	public static void d(Throwable e) {
		log(LEVEL_D, e);
	}

	public static void d(Throwable e, String fmt, Object... args) {
		logf(LEVEL_D, e, fmt, args);
	}

	private static void log(Level level, Throwable e) {
		if (!sm_logger.isLoggable(level))
			return;
		LogRecord lr = new DebugLogRecord(level, "Something was thrown!");
		lr.setThrown(e);
		lr.setLoggerName(sm_logger.getName());
		sm_logger.log(lr);
	}

	private static void logf(Level level, String msg, Object... params) {
		if (!sm_logger.isLoggable(level))
			return;
		LogRecord lr = new DebugLogRecord(level, String.format(msg, params));
		lr.setLoggerName(sm_logger.getName());
		sm_logger.log(lr);
	}

	private static void logf(Level level, Throwable e, String msg,
			Object... params) {
		if (!sm_logger.isLoggable(level))
			return;
		LogRecord lr = new DebugLogRecord(level, String.format(msg, params));
		lr.setThrown(e);
		lr.setLoggerName(sm_logger.getName());
		sm_logger.log(lr);
	}

	public static void v(String fmt, Object... args) {
		// logf(LEVEL_V, fmt, args);
	}

	public static void v(Throwable e) {
		// log(LEVEL_V, e);
	}

	public static void v(Throwable e, String fmt, Object... args) {
		// logf(LEVEL_V, e, fmt, args);
	}

	public static void w(String fmt, Object... args) {
		logf(LEVEL_W, fmt, args);
	}

	public static void w(Throwable e) {
		log(LEVEL_W, e);
	}

	public static void w(Throwable e, String fmt, Object... args) {
		logf(LEVEL_W, e, fmt, args);
	}

	private Dbg() {
		// no instantiation
	}
}
