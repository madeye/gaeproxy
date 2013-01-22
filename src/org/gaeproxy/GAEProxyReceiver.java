/* gaeproxy - GAppProxy / WallProxy client App for Android
 * Copyright (C) 2011 <max.c.lv@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 *                            ___====-_  _-====___
 *                      _--^^^#####//      \\#####^^^--_
 *                   _-^##########// (    ) \\##########^-_
 *                  -############//  |\^^/|  \\############-
 *                _/############//   (@::@)   \\############\_
 *               /#############((     \\//     ))#############\
 *              -###############\\    (oo)    //###############-
 *             -#################\\  / VV \  //#################-
 *            -###################\\/      \//###################-
 *           _#/|##########/\######(   /\   )######/\##########|\#_
 *           |/ |#/\#/\#/\/  \#/\##\  |  |  /##/\#/  \/\#/\#/\#| \|
 *           `  |/  V  V  `   V  \#\| |  | |/#/  V   '  V  V  \|  '
 *              `   `  `      `   / | |  | | \   '      '  '   '
 *                               (  | |  | |  )
 *                              __\ | |  | | /__
 *                             (vvv(VVV)(VVV)vvv)
 *
 *                              HERE BE DRAGONS
 *
 */

package org.gaeproxy;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager.NameNotFoundException;
import android.preference.PreferenceManager;
import android.telephony.TelephonyManager;
import android.util.Log;

public class GAEProxyReceiver extends BroadcastReceiver {

  private static final String TAG = "GAEProxy";

  @Override
  public void onReceive(Context context, Intent intent) {

    SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(context);
    String versionName;
    try {
      versionName = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
    } catch (NameNotFoundException e) {
      versionName = "NONE";
    }

    final boolean isAutoConnect = settings.getBoolean("isAutoConnect", false);
    final boolean isInstalled = settings.getBoolean(versionName, false);

    boolean isMarketEnable = settings.getBoolean("isMarketEnable", false);

    if (isMarketEnable) {
      TelephonyManager tm = (TelephonyManager) context
          .getSystemService(Context.TELEPHONY_SERVICE);
      String countryCode = tm.getSimCountryIso();

      try {
        Log.d(TAG, "Location: " + countryCode);
        if (countryCode.toLowerCase().equals("cn")) {
          String command = "setprop gsm.sim.operator.numeric 310026\n"
              + "setprop gsm.operator.numeric 310026\n"
              + "setprop gsm.sim.operator.iso-country us\n"
              + "setprop gsm.operator.iso-country us\n"
              + "chmod 777 /data/data/com.android.vending/shared_prefs\n"
              + "chmod 666 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
              + "setpref com.android.vending vending_preferences boolean metadata_paid_apps_enabled true\n"
              + "chmod 660 /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
              + "chmod 771 /data/data/com.android.vending/shared_prefs\n"
              + "setown com.android.vending /data/data/com.android.vending/shared_prefs/vending_preferences.xml\n"
              + "kill $(ps | grep vending | tr -s  ' ' | cut -d ' ' -f2)\n"
              + "rm -rf /data/data/com.android.vending/cache/*\n";
          Utils.runRootCommand(command);
        }
      } catch (Exception e) {
        // Nothing
      }
    }

    if (isAutoConnect && isInstalled) {
      final String portText = settings.getString("port", "");
      if (portText == null || portText.length() <= 0) {
        return;
      }
      try {
        int port = Integer.valueOf(portText);
        if (port <= 1024) {
          return;
        }
      } catch (Exception e) {
        return;
      }

      Intent it = new Intent(context, GAEProxyService.class);
      context.startService(it);
    }
  }

}
