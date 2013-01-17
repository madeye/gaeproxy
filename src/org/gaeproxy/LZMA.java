package org.gaeproxy;

public class LZMA {
  static {
    System.loadLibrary("lzma");
  }

  public static native int extract(String[] argc);
}
