package net.sf.jftp.net;

import java.util.List;

public interface FtpTestInterface extends BasicConnection {
	List<FtpTransfer> getTransfers();
	String getHost();
	String getUsername();
	String getPassword();
	int getPort();

	JConnection getJcon();
    DataConnection getDcon();

	boolean getConnected();
	String getDataType();
	boolean getHasUploaded();
}
