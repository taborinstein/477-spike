package net.sf.jftp.net;

import java.io.InputStream;
import java.net.Socket;

public interface DataConnectable {

    Socket sock = null;

    InputStream getInputStream();

    boolean isThere();

    FtpConnection getCon();

    boolean getFinished();

}