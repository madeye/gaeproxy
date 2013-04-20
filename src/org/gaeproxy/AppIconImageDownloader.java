package org.gaeproxy;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class AppIconImageDownloader extends BaseImageDownloader {
  public AppIconImageDownloader(Context context) {
    super(context);
  }

  public AppIconImageDownloader(Context context, int connectTimeout, int readTimeout) {
    super(context, connectTimeout, readTimeout);
  }

  @Override
  protected InputStream getStreamFromOtherSource(String imageUri, Object extra)
      throws IOException, NumberFormatException {
    int uid = Integer.parseInt(imageUri.substring(6));
    Drawable drawable = Utils.getAppIcon(context, uid);
    Bitmap bitmap = Utils.drawableToBitmap(drawable);

    ByteArrayOutputStream os = new ByteArrayOutputStream();
    bitmap.compress(Bitmap.CompressFormat.PNG, 0, os);
    return new ByteArrayInputStream(os.toByteArray());
  }
}
