//============================================ M3: New file Claude Wrote ============================================

package net.sf.jftp.net;

import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import net.sf.jftp.config.Settings;
import net.sf.jftp.system.logging.Log;

public class FtpsTLS
{
    private static SSLSocketFactory factory;

    /** SSLSocketFactory for FTPS. With ftpsTrustAllCerts it trusts any server
     *  cert (lab/self-signed); otherwise the JVM default trust store is used. */
    public static synchronized SSLSocketFactory getFactory() throws Exception
    {
        if(factory != null) return factory;

        if(Settings.ftpsTrustAllCerts)
        {
            Log.out("FTPS: WARNING - trusting ALL server certificates (lab mode)");
            SSLContext ctx = SSLContext.getInstance("TLS");
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager()
                {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] c, String a) { }
                    public void checkServerTrusted(X509Certificate[] c, String a) { }
                }
            };
            ctx.init(null, trustAll, new SecureRandom());
            factory = ctx.getSocketFactory();
        }
        else
        {
            factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
        return factory;
    }

    /** Upgrade an already-connected plain socket to a TLS client socket and
     *  handshake. Used for the control channel (after 234) and PROT P data. */
    public static SSLSocket wrapClient(Socket plain, String host, int port) throws Exception
    {
        SSLSocket ssl = (SSLSocket) getFactory().createSocket(plain, host, port, true);
        ssl.setUseClientMode(true);
        ssl.startHandshake();
        return ssl;
    }
}