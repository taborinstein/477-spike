/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package net.sf.jftp.net;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.io.StreamTokenizer;
import java.net.ServerSocket;
import java.net.Socket;

import net.sf.jftp.config.Settings;
import net.sf.jftp.system.logging.Log;

/**
 * This class represents a ftp data connection.
 * It is used internally by FtpConnection, so you probably don't have to use it
 * directly.
 */
public class DataConnection implements Runnable {
    public final static String GET = "GET";
    public final static String PUT = "PUT";
    public final static String FAILED = "FAILED";
    public final static String FINISHED = "FINISHED";
    public final static String DFINISHED = "DFINISHED";
    public final static String GETDIR = "DGET";
    public final static String PUTDIR = "DPUT";

    private BufferedInputStream in = null;
    private BufferedOutputStream out = null;
    private Thread reciever;
    private int port = 7000;
    public Socket sock = null;
    private ServerSocket ssock = null;
    private String type;
    private String file;
    private String host;
    private boolean resume = false;
    public boolean finished = false;
    private boolean isThere = false;
    private long start;
    private FtpConnection con;
    private int skiplen = 0;
    private boolean justStream = false;
    private boolean ok = true;
    private String localfile = null;
    // private String outputCharset = "CP037";
    private String newLine = null;
    private String LINEEND = System.getProperty("line.separator");

    
// ================================================ JFTP M1 =====================================================================================
    private boolean m1Fail = false;
    private int failReason = 0; // 0 = none, 1 = control lost, 2 = data error. NOTE: Make an enum later
    private long serverCommitted = 0; //Number of bytes already sent, calculated and returned by the server

    public boolean hasError() {
        return m1Fail;
    }

    public int getFailReason() {
        return failReason;
    }

    public long getServerCommitted() {
        return serverCommitted;
    }

    //Match the codes defined in the server file
    private static final byte[] MARK = {'K', 'B', 'M', '1'};
    public static final int REASON_CONTROL_LOST = 1;
    public static final int REASON_DATA_ERROR = 2; //Also could be an enum if more reasons are added in later spikes

    /**
     * Called from the PUT(upload) part of run() if it fails. During a file upload (initiated by STOR), the server -> client direction of
     * the data line socket is idle because of passive mode. So the server may have put a fail message in there. The message will be 13
     * bytes: MARK + type +  committed.
     * If a message is in the line, then the control connection was lost
     * If there is nothing on the line, but a timeout happened, then the data connection was lost
     * The reason needs to be read BEFORE the socket is closed
     */
    private void readReason() {
        try {
            sock.setSoTimeout(2000); //Shorten timeout because the failure message comes through the data line fast
            InputStream rin = sock.getInputStream();

            byte[] rdin = new byte[13];
            int n = 0;
            while (n < rdin.length){
                int r = rin.read(rdin, n, rdin.length - n);
                if (r < 0) { //Check for the end of the message
                    break;
                }
                n += r;
            }

            //Check that the message uses the MARK specified earlier
            if (n == rdin.length && rdin[0] == MARK[0] && rdin[1] == MARK[1] && rdin[2] == MARK[2] && rdin[3] == MARK[3]){
                failReason = rdin[4] & 0xFF; //set failReason to the type given in the message. May add other fail cases in later spikes, so it has a specific value
                long c = 0;
                for(int i = 5; i < 13; i++){
                    c = (c << 8) | (rdin[i] & 0xFF);
                }
                serverCommitted = c;
            } else {
                failReason = REASON_DATA_ERROR; //No message, but timeout = data line failure
            }
        } catch(Exception e) {
            failReason = REASON_DATA_ERROR; //Assumes e is SocketTimeoutException
            Log.debug("readReason: " + e);
        } finally {
            m1Fail = true;
        }
    }

    private final java.util.concurrent.CountDownLatch goAhead = new java.util.concurrent.CountDownLatch(1);
    private volatile boolean cancelled = false;

    /** Called by FtpConnection once the server has sent 125/150 for STOR. */
    public void startTransfer() {
        goAhead.countDown();
    }

    /** Called by FtpConnection if STOR was rejected; releases the thread without sending data. */
    public void cancelTransfer() {
        cancelled = true;
        goAhead.countDown();
    }

// ============================================================================================================================================

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        reciever = new Thread(this);
        reciever.start();
    }

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type, boolean resume) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        this.resume = resume;

        // resume = false;
        reciever = new Thread(this);
        reciever.start();
    }

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type, boolean resume,
            boolean justStream) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        this.resume = resume;
        this.justStream = justStream;

        // resume = false;
        reciever = new Thread(this);
        reciever.start();
    }

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type, boolean resume,
            String localfile) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        this.resume = resume;
        this.localfile = localfile;

        // resume = false;
        reciever = new Thread(this);
        reciever.start();
    }

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type, boolean resume, int skiplen) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        this.resume = resume;
        this.skiplen = skiplen;

        // resume = false;
        reciever = new Thread(this);
        reciever.start();
    }

    public DataConnection(FtpConnection con, int port, String host,
            String file, String type, boolean resume,
            int skiplen, InputStream i) {
        this.con = con;
        this.file = file;
        this.host = host;
        this.port = port;
        this.type = type;
        this.resume = resume;
        this.skiplen = skiplen;

        if (i != null) {
            this.in = new BufferedInputStream(i);
        }

        // resume = false;
        reciever = new Thread(this);
        reciever.start();
    }

    public void run() {
        try {
            newLine = con.getCRLF();
            // Log.debug("NL: "+newLine+"\n\n\n\n\n");

            if (Settings.getFtpPasvMode()) {
                try {
                    sock = new Socket(host, port);
                    sock.setSoTimeout(Settings.getSocketTimeout());
                } catch (Exception ex) {
                    ok = false;
                    ex.printStackTrace();
                    debug("Can't open Socket on " + host + ":" + port);
                }
            } else {
                // Log.debug("trying new server socket: "+port);
                try {
                    ssock = new ServerSocket(port);
                } catch (Exception ex) {
                    ok = false;
                    ex.printStackTrace();
                    Log.debug("Can't open ServerSocket on port " + port);
                }
            }
        } catch (Exception ex) {
            debug(ex.toString());
        }

        isThere = true;

        boolean ok = true;

        RandomAccessFile fOut = null;
        BufferedOutputStream bOut = null;
        RandomAccessFile fIn = null;

        try {
            if (!Settings.getFtpPasvMode()) {
                int retry = 0;

                while ((retry++ < 5) && (sock == null)) {
                    try {
                        ssock.setSoTimeout(Settings.connectionTimeout);
                        sock = ssock.accept();
                    } catch (IOException e) {
                        sock = null;
                        debug("Got IOException while trying to open a socket!");

                        if (retry == 5) {
                            debug("Connection failed, tried 5 times - maybe try a higher timeout in Settings.java...");
                        }

                        finished = true;

                        throw e;
                    } finally {
                        ssock.close();
                    }

                    debug("Attempt timed out, retrying...");
                }
            }

            if (ok) {
                byte[] buf = new byte[Settings.bufferSize];
                start = System.currentTimeMillis();

                long buflen = 0;

                // ---------------download----------------------
                if (type.equals(GET) || type.equals(GETDIR)) {
                    if (!justStream) {
                        try {
                            if (resume) {
                                File f = new File(file);
                                fOut = new RandomAccessFile(file, "rw");
                                fOut.seek(f.length());
                                buflen = f.length();
                            } else {
                                if (localfile == null) {
                                    localfile = file;
                                }

                                File f2 = new File(Settings.appHomeDir);
                                f2.mkdirs();

                                File f = new File(localfile);

                                if (f.exists()) {
                                    f.delete();
                                }

                                bOut = new BufferedOutputStream(new FileOutputStream(localfile),
                                        Settings.bufferSize);
                            }
                        } catch (Exception ex) {
                            debug("Can't create outputfile: " + file);
                            ok = false;
                            ex.printStackTrace();
                        }
                    }

                    if (ok) {
                        try {
                            in = new BufferedInputStream(sock.getInputStream(),
                                    Settings.bufferSize);

                            if (justStream) {
                                return;
                            }
                        } catch (Exception ex) {
                            ok = false;
                            debug("Can't get InputStream");
                        }

                        if (ok) {
                            try {
                                long len = buflen;

                                if (fOut != null) {
                                    while (true) {
                                        // resuming
                                        int read = -2;

                                        try {
                                            read = in.read(buf);
                                        } catch (IOException es) {
                                            Log.out("got a IOException");
                                            ok = false;
                                            fOut.close();
                                            finished = true;
                                            con.fireProgressUpdate(file,
                                                    FAILED, -1);

                                            Log.out("last read: " + read +
                                                    ", len: " + (len + read));
                                            es.printStackTrace();

                                            return;
                                        }

                                        len += read;

                                        if (read == -1) {
                                            break;
                                        }

                                        if (newLine != null) {
                                            byte[] buf2 = modifyGet(buf, read);
                                            fOut.write(buf2, 0, buf2.length);
                                        } else {
                                            fOut.write(buf, 0, read);
                                        }

                                        con.fireProgressUpdate(file, type, len);

                                        if (time()) {
                                            // Log.debugSize(len, true, false, file);
                                        }

                                        if (read == StreamTokenizer.TT_EOF) {
                                            break;
                                        }
                                    }

                                    // Log.debugSize(len, true, true, file);
                                } else {
                                    // no resuming
                                    while (true) {
                                        // System.out.println(".");
                                        int read = -2;

                                        try {
                                            read = in.read(buf);
                                        } catch (IOException es) {
                                            Log.out("got a IOException");
                                            ok = false;
                                            bOut.close();
                                            finished = true;
                                            con.fireProgressUpdate(file,
                                                    FAILED, -1);

                                            Log.out("last read: " + read +
                                                    ", len: " + (len + read));
                                            es.printStackTrace();

                                            return;
                                        }

                                        len += read;

                                        if (read == -1) {
                                            break;
                                        }

                                        if (newLine != null) {
                                            byte[] buf2 = modifyGet(buf, read);
                                            bOut.write(buf2, 0, buf2.length);
                                        } else {
                                            bOut.write(buf, 0, read);
                                        }

                                        con.fireProgressUpdate(file, type, len);

                                        if (time()) {
                                            // Log.debugSize(len, true, false, file);
                                        }

                                        if (read == StreamTokenizer.TT_EOF) {
                                            break;
                                        }
                                    }

                                    bOut.flush();

                                    // Log.debugSize(len, true, true, file);
                                }
                            } catch (IOException ex) {
                                ok = false;
                                debug("Old connection removed");
                                con.fireProgressUpdate(file, FAILED, -1);

                                // debug(ex + ": " + ex.getMessage());
                                ex.printStackTrace();
                            }
                        }
                    }
                }

                // ---------------upload----------------------
                if (type.equals(PUT) || type.equals(PUTDIR)) {
                    if (in == null) {
                        try {
                            fIn = new RandomAccessFile(file, "r");

                            if (resume) {
                                fIn.seek(skiplen);
                            }

                            // fIn = new BufferedInputStream(new FileInputStream(file));
                        } catch (Exception ex) {
                            debug("Can't open inputfile: " + " (" + ex + ")");
                            ok = false;
                        }
                    }

                    if (ok) {
                        // M1: don't send a byte until the server has accepted STOR
                        try {
                            if (!goAhead.await(30, java.util.concurrent.TimeUnit.SECONDS) || cancelled) {
                                debug("Upload not started: STOR not accepted");
                                ok = false;
                            }
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            ok = false;
                        }
                    }

                    if (ok) {
                        try {
                            out = new BufferedOutputStream(sock.getOutputStream());
                        } catch (Exception ex) {
                            ok = false;
                            debug("Can't get OutputStream");
                        }

                        if (ok) {
                            try {
                                int len = skiplen;
                                InputStream rin = sock.getInputStream();   // M1: server -> client is idle during STOR

                                while (true) {
                                    int read;

                                    if (in != null) {
                                        read = in.read(buf);
                                    } else {
                                        read = fIn.read(buf);
                                    }

                                    len += read;

                                    // System.out.println(file + " " + type+ " " + len + " " + read);
                                    if (read == -1) {
                                        break;
                                    }

                                    if (newLine != null) {
                                        byte[] buf2 = modifyPut(buf, read);
                                        out.write(buf2, 0, buf2.length);
                                    } else {
                                        out.write(buf, 0, read);
                                    }

                                    con.fireProgressUpdate(file, type, len);

                                    // M1: anything arriving on the idle direction is a server notice
                                    if (rin.available() > 0) {
                                        debug("Server notice on data connection");
                                        readReason();
                                        ok = false;
                                        break;
                                    }

                                    if (time()) {
                                        // Log.debugSize(len, false, false, file);
                                    }

                                    if (read == StreamTokenizer.TT_EOF) {
                                        break;
                                    }
                                }

                                out.flush();

                                // Log.debugSize(len, false, true, file);

// =========================================== JFTP M1 - MODIFIED THIS PART ==================================================================
                            } catch (IOException ex) {
                                ok = false;
                                debug("Error: Data connection closed.");
                                if (!m1Fail) {          // M1: don't overwrite a reason already read from the frame
                                    readReason();
                                }
                                con.fireProgressUpdate(file, FAILED, -1);
                                ex.printStackTrace();
                            }
// =========================================================================================================================================
                        }
                    }
                }
            }
        } catch (IOException ex) {
            Log.debug("Can't connect socket to ServerSocket");
            ex.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.flush();
                    out.close();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            try {
                if (bOut != null) {
                    bOut.flush();
                    bOut.close();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            try {
                if (fOut != null) {
                    fOut.close();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            try {
                if (in != null && !justStream) {
                    in.close();
                }

                if (fIn != null) {
                    fIn.close();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        try {
            sock.close();
        } catch (Exception ex) {
            debug(ex.toString());
        }

        if (!Settings.getFtpPasvMode()) {
            try {
                ssock.close();
            } catch (Exception ex) {
                debug(ex.toString());
            }
        }

        finished = true;

        if (ok) {
            con.fireProgressUpdate(file, FINISHED, -1);
        } else {
            con.fireProgressUpdate(file, FAILED, -1);
        }
    }

    public InputStream getInputStream() {
        return in;
    }

    public FtpConnection getCon() {
        return con;
    }

    private void debug(String msg) {
        Log.debug(msg);
    }

    public void reset() {
        // reciever.destroy();
        reciever = new Thread(this);
        reciever.start();
    }

    private boolean time() {
        long now = System.currentTimeMillis();
        long offset = now - start;

        if (offset > Settings.statusMessageAfterMillis) {
            start = now;

            return true;
        }

        return false;
    }

    public boolean isThere() {
        if (finished) {
            return true;
        }

        return isThere;
    }

    public void setType(String tmp) {
        type = tmp;
    }

    public boolean isOK() {
        return ok;
    }

    public void interrupt() {
        if (Settings.getFtpPasvMode() &&
                (type.equals(GET) || type.equals(GETDIR))) {
            try {
                reciever.join();
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }
    }

    private byte[] modifyPut(byte[] buf, int len) {
        // Log.debug("\n\n\n\nNewline: "+newLine);
        if (newLine == null)
            return buf;

        String s = (new String(buf)).substring(0, len);
        s = s.replaceAll(LINEEND, newLine);
        // Log.debug("Newline_own: "+LINEEND+", s:"+s);

        return s.getBytes();
    }

    private byte[] modifyGet(byte[] buf, int len) {
        // Log.debug("\n\n\n\nNewline: "+newLine);
        if (newLine == null)
            return buf;

        String s = (new String(buf)).substring(0, len);
        s = s.replaceAll(newLine, LINEEND);
        // Log.debug("Newline_own: "+LINEEND+", s:"+s);

        return s.getBytes();
    }
}
