/*
 * Zirco Browser for Android
 * 
 * Copyright (C) 2010 J. Devauchelle and contributors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package org.gaeproxy.zirco.ui.activities.preferences;

import org.gaeproxy.R;
import org.gaeproxy.zirco.utils.Constants;

import android.content.SharedPreferences.Editor;
import android.preference.PreferenceManager;

/**
 * User agent preference chooser activity.
 */
public class UserAgentPreferenceActivity extends
		BaseSpinnerCustomPreferenceActivity {

	@Override
	protected int getSpinnerPromptId() {
		return R.string.UserAgentPreferenceActivity_Prompt;
	}

	@Override
	protected int getSpinnerValuesArrayId() {
		return R.array.UserAgentValues;
	}

	@Override
	protected void onOk() {
		Editor editor = PreferenceManager.getDefaultSharedPreferences(this)
				.edit();
		editor.putString(Constants.PREFERENCES_BROWSER_USER_AGENT,
				mCustomEditText.getText().toString());
		editor.commit();
	}

	@Override
	protected void onSpinnerItemSelected(int position) {
		switch (position) {
		case 0:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.USER_AGENT_DEFAULT);
			break;
		case 1:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.USER_AGENT_DESKTOP);
			break;
		case 2: {
			mCustomEditText.setEnabled(true);

			if ((mCustomEditText.getText().toString()
					.equals(Constants.USER_AGENT_DEFAULT))
					|| (mCustomEditText.getText().toString()
							.equals(Constants.USER_AGENT_DESKTOP))) {
				mCustomEditText.setText(null);
			}
			break;
		}
		default:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.USER_AGENT_DEFAULT);
			break;
		}
	}

	@Override
	protected void setSpinnerValueFromPreferences() {
		String currentUserAgent = PreferenceManager
				.getDefaultSharedPreferences(this).getString(
						Constants.PREFERENCES_BROWSER_USER_AGENT,
						Constants.USER_AGENT_DEFAULT);

		if (currentUserAgent.equals(Constants.USER_AGENT_DEFAULT)) {
			mSpinner.setSelection(0);
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.USER_AGENT_DEFAULT);
		} else if (currentUserAgent.equals(Constants.USER_AGENT_DESKTOP)) {
			mSpinner.setSelection(1);
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.USER_AGENT_DESKTOP);
		} else {
			mSpinner.setSelection(2);
			mCustomEditText.setEnabled(true);
			mCustomEditText.setText(currentUserAgent);
		}
	}

}
