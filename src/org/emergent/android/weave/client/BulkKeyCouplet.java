/*
 * Copyright 2010 Patrick Woodworth
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.emergent.android.weave.client;

import java.security.Key;

/**
 * @author Patrick Woodworth
 */
class BulkKeyCouplet {
	public final Key cipherKey;
	public final Key hmacKey;

	public BulkKeyCouplet(Key cipherKey, Key hmacKey) {
		this.cipherKey = cipherKey;
		this.hmacKey = hmacKey;
	}
}
