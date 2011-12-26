package org.gaeproxy.zirco.sync;

public interface ISyncListener {

	void onSyncCancelled();

	void onSyncEnd(Throwable result);

	void onSyncProgress(int step, int done, int total);

}
