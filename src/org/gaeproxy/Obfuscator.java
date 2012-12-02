package org.gaeproxy;

public final class Obfuscator {

// -------------------------- STATIC METHODS --------------------------

  static {
    System.loadLibrary("obfuscator");
  }


// -------------------------- OTHER METHODS --------------------------

  public static native String obfuscate(String data);

}
