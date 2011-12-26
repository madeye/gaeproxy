package org.gaeproxy.zirco.ui.runnables;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.gaeproxy.R;
import org.gaeproxy.zirco.providers.BookmarksProviderWrapper;
import org.gaeproxy.zirco.utils.ApplicationUtils;
import org.gaeproxy.zirco.utils.DateUtils;
import org.gaeproxy.zirco.utils.IOUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import android.app.ProgressDialog;
import android.content.Context;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

/**
 * Runnable to import history and bookmarks from an XML file.
 */
public class XmlHistoryBookmarksImporter implements Runnable {

	private Context mContext;
	private String mFileName;

	private ProgressDialog mProgressDialog;

	private String mErrorMessage = null;

	private Handler mHandler = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			if (mProgressDialog != null) {
				mProgressDialog.dismiss();
			}

			if (mErrorMessage != null) {
				ApplicationUtils
						.showOkDialog(
								mContext,
								android.R.drawable.ic_dialog_alert,
								mContext.getResources()
										.getString(
												R.string.Commons_HistoryBookmarksImportSDCardFailedTitle),
								String.format(
										mContext.getResources()
												.getString(
														R.string.Commons_HistoryBookmarksFailedMessage),
										mErrorMessage));

			}
		}
	};

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The current context.
	 * @param fileName
	 *            The file to import.
	 * @param progressDialog
	 *            The progress dialog shown during import.
	 */
	public XmlHistoryBookmarksImporter(Context context, String fileName,
			ProgressDialog progressDialog) {
		mContext = context;
		mFileName = fileName;
		mProgressDialog = progressDialog;
	}

	/**
	 * Get the content of a node, why Android does not include
	 * Node.getTextContent() ?
	 * 
	 * @param node
	 *            The node.
	 * @return The node content.
	 */
	private String getNodeContent(Node node) {
		StringBuffer buffer = new StringBuffer();
		NodeList childList = node.getChildNodes();
		for (int i = 0; i < childList.getLength(); i++) {
			Node child = childList.item(i);
			if (child.getNodeType() != Node.TEXT_NODE) {
				continue; // skip non-text nodes
			}
			buffer.append(child.getNodeValue());
		}

		return buffer.toString();
	}

	@Override
	public void run() {

		File file = new File(IOUtils.getBookmarksExportFolder(), mFileName);

		if ((file != null) && (file.exists()) && (file.canRead())) {

			try {

				DocumentBuilderFactory factory = DocumentBuilderFactory
						.newInstance();
				DocumentBuilder builder;

				builder = factory.newDocumentBuilder();

				Document document = builder.parse(file);

				Element root = document.getDocumentElement();

				if ((root != null) && (root.getNodeName().equals("itemlist"))) {

					NodeList itemsList = root.getElementsByTagName("item");

					Node item;
					NodeList record;
					Node dataItem;

					for (int i = 0; i < itemsList.getLength(); i++) {

						item = itemsList.item(i);

						if (item != null) {
							record = item.getChildNodes();

							String title = null;
							String url = null;
							int visits = 0;
							long date = -1;
							long created = -1;
							int bookmark = 0;

							for (int j = 0; j < record.getLength(); j++) {
								dataItem = record.item(j);

								if ((dataItem != null)
										&& (dataItem.getNodeName() != null)) {

									if (dataItem.getNodeName().equals("title")) {
										title = URLDecoder
												.decode(getNodeContent(dataItem));
									} else if (dataItem.getNodeName().equals(
											"url")) {
										url = URLDecoder
												.decode(getNodeContent(dataItem));
									} else if (dataItem.getNodeName().equals(
											"visits")) {
										try {
											visits = Integer
													.parseInt(getNodeContent(dataItem));
										} catch (Exception e) {
											visits = 0;
										}
									} else if (dataItem.getNodeName().equals(
											"date")) {
										try {
											date = Long
													.parseLong(getNodeContent(dataItem));
										} catch (Exception e) {
											date = -1;
										}
									} else if (dataItem.getNodeName().equals(
											"created")) {
										try {
											created = Long
													.parseLong(getNodeContent(dataItem));
										} catch (Exception e) {
											created = -1;
										}
									} else if (dataItem.getNodeName().equals(
											"bookmark")) {
										try {
											bookmark = Integer
													.parseInt(getNodeContent(dataItem));
										} catch (Exception e) {
											bookmark = 0;
										}
									}
								}
							}

							BookmarksProviderWrapper.insertRawRecord(
									mContext.getContentResolver(), title, url,
									visits, date, created, bookmark);
						}
					}

				} else if ((root != null)
						&& (root.getNodeName().equals("bookmarkslist"))) {
					// Old export format (before 0.4.0).

					NodeList bookmarksList = root
							.getElementsByTagName("bookmark");

					Node bookmark;
					NodeList bookmarkItems;
					String title;
					String url;
					String creationDate;
					int count;
					long date = -1;
					long created = -1;
					Node item;

					for (int i = 0; i < bookmarksList.getLength(); i++) {

						bookmark = bookmarksList.item(i);

						if (bookmark != null) {

							title = null;
							url = null;
							creationDate = null;
							count = 0;

							bookmarkItems = bookmark.getChildNodes();

							for (int j = 0; j < bookmarkItems.getLength(); j++) {

								item = bookmarkItems.item(j);

								if ((item != null)
										&& (item.getNodeName() != null)) {
									if (item.getNodeName().equals("title")) {
										title = getNodeContent(item);
									} else if (item.getNodeName().equals("url")) {
										url = URLDecoder
												.decode(getNodeContent(item));
									} else if (item.getNodeName().equals(
											"creationdate")) {
										creationDate = getNodeContent(item);

										date = DateUtils.convertFromDatabase(
												mContext, creationDate)
												.getTime();
										created = date;

									} else if (item.getNodeName().equals(
											"count")) {
										try {
											count = Integer
													.parseInt(getNodeContent(item));
										} catch (Exception e) {
											count = 0;
										}
									}
								}

							}

							BookmarksProviderWrapper.insertRawRecord(
									mContext.getContentResolver(), title, url,
									count, date, created, 1);
						}
					}
				}

			} catch (ParserConfigurationException e) {
				Log.w("Bookmark import failed", e.getMessage());
				mErrorMessage = e.toString();
			} catch (SAXException e) {
				Log.w("Bookmark import failed", e.getMessage());
				mErrorMessage = e.toString();
			} catch (IOException e) {
				Log.w("Bookmark import failed", e.getMessage());
				mErrorMessage = e.toString();
			}
		}

		mHandler.sendEmptyMessage(0);
	}

}
