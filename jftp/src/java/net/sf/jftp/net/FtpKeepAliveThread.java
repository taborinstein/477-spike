package net.sf.jftp.net;

import javax.swing.SwingUtilities;

import net.sf.jftp.JFtp;
import net.sf.jftp.config.Settings;

public class FtpKeepAliveThread implements Runnable {

	private Thread runner;
	private FtpConnection conn;
	
	public FtpKeepAliveThread(FtpConnection conn) {
		this.conn = conn;
		
		runner = new Thread(this);
		runner.start();
	}
	
	public void run() {
		while(conn.isConnected()) {
			try {
				Thread.sleep(Settings.ftpKeepAliveInterval);

                String resp;
				// Check if the connection is still alive
				if (conn.isConnected()) {
					resp = conn.noop();
				} else {
                    break;
                }
                
                if (resp == null || !resp.startsWith("200")) {
                    SwingUtilities.invokeLater(() -> {
                        if (!conn.isConnected()) {
                            return;
                        }
                        JFtp.switchConnection();
                    });
                    break;
                }
			}
			catch(Exception ex) {
				ex.printStackTrace();
			}
		}
	}
}
