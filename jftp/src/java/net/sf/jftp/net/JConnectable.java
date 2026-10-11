package net.sf.jftp.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;

public interface JConnectable {

    boolean isThere();

    BufferedReader getReader();

    void send(String string);

    InetAddress getLocalAddress() throws IOException;

    BufferedReader getIn();

    OutputStream getOut();

    // ========================================== M3: TLS command ==================================
    boolean startTLS();

}