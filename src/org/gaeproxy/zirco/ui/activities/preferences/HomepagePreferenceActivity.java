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
import android.os.Bundle;
import android.preference.PreferenceManager;

/**
 * Home page preference chooser activity.
 */
public class HomepagePreferenceActivity extends
		BaseSpinnerCustomPreferenceActivity {

	@Override
	protected int getSpinnerPromptId() {
		return R.string.HomepagePreferenceActivity_Prompt;
	}

	@Override
	protected int getSpinnerValuesArrayId() {
		return R.array.HomepageValues;
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}

	@Override
	protected void onOk() {
		Editor editor = PreferenceManager.getDefaultSharedPreferences(this)
				.edit();
		editor.putString(Constants.PREFERENCES_GENERAL_HOME_PAGE,
				mCustomEditText.getText().toString());
		editor.commit();
	}

	@Override
	protected void onSpinnerItemSelected(int position) {
		switch (position) {
		case 0:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.URL_ABOUT_START);
			break;
		case 1:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.URL_ABOUT_BLANK);
			break;
		case 2: {
			mCustomEditText.setEnabled(true);

			if ((mCustomEditText.getText().toString()
					.equals(Constants.URL_ABOUT_START))
					|| (mCustomEditText.getText().toString()
							.equals(Constants.URL_ABOUT_BLANK))) {
				mCustomEditText.setText(null);
			}
			break;
		}
		default:
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.URL_ABOUT_START);
			break;
		}
	}

	@Override
	protected void setSpinnerValueFromPreferences() {
		String currentHomepage = PreferenceManager.getDefaultSharedPreferences(
				this).getString(Constants.PREFERENCES_GENERAL_HOME_PAGE,
				Constants.URL_ABOUT_START);

		if (currentHomepage.equals(Constants.URL_ABOUT_START)) {
			mSpinner.setSelection(0);
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.URL_ABOUT_START);
		} else if (currentHomepage.equals(Constants.URL_ABOUT_BLANK)) {
			mSpinner.setSelection(1);
			mCustomEditText.setEnabled(false);
			mCustomEditText.setText(Constants.URL_ABOUT_BLANK);
		} else {
			mSpinner.setSelection(2);
			mCustomEditText.setEnabled(true);
			mCustomEditText.setText(currentHomepage);
		}
	}

}
