/*
 * FTPS (explicit FTP over TLS, RFC 4217) helper for J-FTP.
 *
 * Builds the SSLSocketFactory used to protect the control and data channels,
 * and wraps an already-connected plain Socket into a TLS client Socket.
 *
 */
package net.sf.jftp.net;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import net.sf.jftp.config.Settings;
import net.sf.jftp.system.logging.Log;


public class FtpsTLS
{
    private static SSLSocketFactory factory;

    /**
     * Returns (and caches) the SSLSocketFactory used for FTPS.
     *
     * With Settings.ftpsTrustAllCerts the factory trusts any server
     * certificate -- convenient for a lab server using a self-signed cert,
     * but NOT safe for production. Otherwise the server certificate is
     * validated against a pinned cert (or the JVM default trust store).
     */
    public static synchronized SSLSocketFactory getFactory() throws Exception
    {
        if(factory != null)
        {
            return factory;
        }

        if(Settings.ftpsTrustAllCerts)
        {
            // LAB ONLY: accept any certificate. THIS is what the MITM exploits.
            Log.out("FTPS: WARNING - trusting ALL server certificates (lab mode)");

            SSLContext ctx = SSLContext.getInstance("TLS");
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager()
                {
                    public X509Certificate[] getAcceptedIssuers()
                    {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] c, String a) { }

                    public void checkServerTrusted(X509Certificate[] c, String a) { }
                }
            };
            ctx.init(null, trustAll, new SecureRandom());
            factory = ctx.getSocketFactory();
        }
        else
        {
            // Validate the server certificate. Build a trust store that contains
            // only the server's real cert (pinning); any other cert -- including a
            // MITM's forged one -- fails checkServerTrusted and the handshake aborts.
            SSLContext ctx = SSLContext.getInstance("TLS");
            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            File certFile = resolveTrustedCert(Settings.ftpsTrustedCert);
            if(certFile != null)
            {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(null, null);                       // empty, in-memory trust store
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                try(InputStream in = new FileInputStream(certFile))
                {
                    ks.setCertificateEntry("ftps-server", cf.generateCertificate(in));
                }
                tmf.init(ks);
                Log.out("FTPS: validating server cert against pinned " + certFile.getPath());
            }
            else
            {
                // No pinned cert found: use the JVM default trust store (CA-signed
                // certs, or one supplied via -Djavax.net.ssl.trustStore).
                tmf.init((KeyStore) null);
                Log.out("FTPS: no pinned cert found; using default trust store");
            }

            ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
            factory = ctx.getSocketFactory();
        }

        return factory;
    }

    /**
     * Locate the pinned server cert without a machine-specific absolute path.
     * Tries the configured name plus a few repo-relative fallbacks, so it works
     * for any teammate whether the client runs from the jftp dir or the repo
     * root. Each person generates their own cert.pem (make_cert.py) at the repo
     * root; nothing needs to be committed.
     */
    private static File resolveTrustedCert(String configured)
    {
        String[] candidates = {
            configured,        // whatever Settings says (default "cert.pem")
            "cert.pem",        // working dir = repo root (e.g. 477-spike)
            "../cert.pem",     // working dir = jftp (one level under the repo root)
            "../../cert.pem"   // deeper working dir, just in case
        };
        for(String c : candidates)
        {
            if(c == null)
            {
                continue;
            }
            File f = new File(c);
            if(f.isFile())
            {
                return f;
            }
        }
        return null;
    }

    /**
     * Upgrade an already-connected plain socket to a TLS client socket and
     * complete the handshake. Used for both the control channel (after the
     * server's 234 reply to AUTH TLS) and each PROT P data channel.
     */
    public static SSLSocket wrapClient(Socket plain, String host, int port) throws Exception
    {
        SSLSocket ssl = (SSLSocket) getFactory().createSocket(plain, host, port, true);
        ssl.setUseClientMode(true);
        ssl.startHandshake();
        return ssl;
    }
}