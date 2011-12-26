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

package org.gaeproxy.zirco.utils;

import android.view.animation.AccelerateInterpolator;
import android.view.animation.Animation;
import android.view.animation.TranslateAnimation;

/**
 * Holder for animation objects.
 */
public final class AnimationManager {

	/**
	 * Holder for singleton implementation.
	 */
	private static class AnimationManagerHolder {
		private static final AnimationManager INSTANCE = new AnimationManager();
	}
	private static final int BARS_ANIMATION_DURATION = 150;

	private static final int ANIMATION_DURATION = 350;
	/**
	 * Get the unique instance of the Controller.
	 * 
	 * @return The instance of the Controller
	 */
	public static AnimationManager getInstance() {
		return AnimationManagerHolder.INSTANCE;
	}
	private Animation mTopBarShowAnimation = null;
	private Animation mTopBarHideAnimation = null;

	private Animation mBottomBarShowAnimation = null;
	private Animation mBottomBarHideAnimation = null;
	private Animation mPreviousTabViewShowAnimation = null;
	private Animation mPreviousTabViewHideAnimation = null;

	private Animation mNextTabViewShowAnimation = null;
	private Animation mNextTabViewHideAnimation = null;
	private Animation mInFromRightAnimation;
	private Animation mOutToLeftAnimation;

	private Animation mInFromLeftAnimation;

	private Animation mOutToRightAnimation;

	/**
	 * Contructor.
	 */
	private AnimationManager() {

		mTopBarShowAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, -1.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mTopBarShowAnimation.setDuration(BARS_ANIMATION_DURATION);

		mTopBarHideAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, -1.0f);

		mTopBarHideAnimation.setDuration(BARS_ANIMATION_DURATION);

		mBottomBarShowAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, 1.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mBottomBarShowAnimation.setDuration(BARS_ANIMATION_DURATION);

		mBottomBarHideAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, 1.0f);

		mBottomBarHideAnimation.setDuration(BARS_ANIMATION_DURATION);

		mPreviousTabViewShowAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, -1.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mPreviousTabViewShowAnimation.setDuration(BARS_ANIMATION_DURATION);

		mPreviousTabViewHideAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				-1.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mPreviousTabViewHideAnimation.setDuration(BARS_ANIMATION_DURATION);

		mNextTabViewShowAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 1.0f, Animation.RELATIVE_TO_SELF,
				0.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mNextTabViewShowAnimation.setDuration(BARS_ANIMATION_DURATION);

		mNextTabViewHideAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_SELF, 0.0f, Animation.RELATIVE_TO_SELF,
				1.0f, Animation.RELATIVE_TO_SELF, 0.0f,
				Animation.RELATIVE_TO_SELF, 0.0f);

		mNextTabViewHideAnimation.setDuration(BARS_ANIMATION_DURATION);

		mInFromRightAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_PARENT, +1.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f);

		mInFromRightAnimation.setDuration(ANIMATION_DURATION);
		mInFromRightAnimation.setInterpolator(new AccelerateInterpolator());

		mOutToLeftAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, -1.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f);

		mOutToLeftAnimation.setDuration(ANIMATION_DURATION);
		mOutToLeftAnimation.setInterpolator(new AccelerateInterpolator());

		mInFromLeftAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_PARENT, -1.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f);

		mInFromLeftAnimation.setDuration(ANIMATION_DURATION);
		mInFromLeftAnimation.setInterpolator(new AccelerateInterpolator());

		mOutToRightAnimation = new TranslateAnimation(
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, +1.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f,
				Animation.RELATIVE_TO_PARENT, 0.0f);

		mOutToRightAnimation.setDuration(ANIMATION_DURATION);
		mOutToRightAnimation.setInterpolator(new AccelerateInterpolator());
	}

	public Animation getBottomBarHideAnimation() {
		return mBottomBarHideAnimation;
	}

	public Animation getBottomBarShowAnimation() {
		return mBottomBarShowAnimation;
	}

	/**
	 * Get the in from left animation object.
	 * 
	 * @return The animation object.
	 */
	public Animation getInFromLeftAnimation() {
		return mInFromLeftAnimation;
	}

	/**
	 * Get the in from right animation object.
	 * 
	 * @return The animation object.
	 */
	public Animation getInFromRightAnimation() {
		return mInFromRightAnimation;
	}

	public Animation getNextTabViewHideAnimation() {
		return mNextTabViewHideAnimation;
	}

	public Animation getNextTabViewShowAnimation() {
		return mNextTabViewShowAnimation;
	}

	/**
	 * Get the out to left animation object.
	 * 
	 * @return The animation object.
	 */
	public Animation getOutToLeftAnimation() {
		return mOutToLeftAnimation;
	}

	/**
	 * Get the out to right animation object.
	 * 
	 * @return The animation object.
	 */
	public Animation getOutToRightAnimation() {
		return mOutToRightAnimation;
	}

	public Animation getPreviousTabViewHideAnimation() {
		return mPreviousTabViewHideAnimation;
	}

	public Animation getPreviousTabViewShowAnimation() {
		return mPreviousTabViewShowAnimation;
	}

	public Animation getTopBarHideAnimation() {
		return mTopBarHideAnimation;
	}

	public Animation getTopBarShowAnimation() {
		return mTopBarShowAnimation;
	}

}
