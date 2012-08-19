/*
 * Zirco Browser for Android
 * 
 * Copyright (C) 2010 - 2011 J. Devauchelle and contributors.
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
import android.os.Bundle;
import android.preference.PreferenceManager;

public class WeaveServerPreferenceActivity extends
		BaseSpinnerCustomPreferenceActivity {

	@Override
	protected int getSpinnerPromptId() {
		return R.string.WeaveServerPreferenceActivity_Prompt;
	}

	@Override
	protected int getSpinnerValuesArrayId() {
		return R.array.WeaveServerValues;
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}

	@Override
	protected void onOk() {
		Editor editor = PreferenceManager.getDefaultSharedPreferences(this)
				.edit();
		editor.putString(Constants.PREFERENCE_WEAVE_SERVER, mCustomEditText
				.getText().toString());
		editor.commit();
	}

	@Override
	protected void onSpinnerItemSelected(int position) {
		switch (position) {
		case 0:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.WEAVE_DEFAULT_SERVER);
			break;
		case 1: {
			mCustomEditText.setEnabled(true);

			if (mCustomEditText.getText().toString()
					.equals(Constants.WEAVE_DEFAULT_SERVER)) {
				mCustomEditText.setText(null);
			}
			break;
		}
		default:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.WEAVE_DEFAULT_SERVER);
			break;
		}
	}

	@Override
	protected void setSpinnerValueFromPreferences() {
		String currentServer = PreferenceManager.getDefaultSharedPreferences(
				this).getString(Constants.PREFERENCE_WEAVE_SERVER,
				Constants.WEAVE_DEFAULT_SERVER);

		if (currentServer.equals(Constants.WEAVE_DEFAULT_SERVER)) {
			mSpinner.setSelection(0);
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.WEAVE_DEFAULT_SERVER);
		} else {
			mSpinner.setSelection(1);
			mCustomEditText.setEnabled(true);
			mCustomEditText.setText(currentServer);
		}
	}

}
