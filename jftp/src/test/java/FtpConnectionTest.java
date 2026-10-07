import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import net.sf.jftp.net.DataConnectionDataSource;
import net.sf.jftp.net.FtpConnection;
import net.sf.jftp.net.JConnection;
import net.sf.jftp.net.JConnectable;
import net.sf.jftp.net.JConnectionDataSource;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FtpConnectionTest {

    String LS = "drwxr-xr-x 7 me me 4096 Oct 4 14:27 .\n" + //
            "drwxr-xr-x 5 me me 4096 Oct 4 16:06 ..\n" + //
            "drwxr-xr-x 5 me me 4096 Oct 4 14:31 super_cool_file\n" + //
            "drwxr-xr-x 3 me me 4096 Sep 25 11:35 super_cool_directory";

    @Test
    public void test0ListNormal() {
        JConnectionDataSource jcon = new JConnectionDataSource();
        jcon.handle("LIST", (String arg) -> {
            assertEquals("-laL", arg);
            return "150 okay, opening a definitely real connection";
        });
        FtpConnection connection = new FtpConnection(jcon);
        // connection.LIST = "LIST";
        connection.login("username", "password");
        try {
            DataConnectionDataSource dcon = new DataConnectionDataSource(connection);
            dcon.supplyOutput(LS);
            dcon.onEnd(() -> jcon.queue_response("256 transfer complete"));
            connection.list(dcon); // already in FtpC
            assertEquals(String.join("\n", connection.currentListing), LS); // this contains the result
            new Thread(() -> connection.disconnect()).run();
            // need to wait for keepAliveThread to finish :)
        } catch (IOException ioe) {
            System.err.println(ioe);
        }
    }

    @Test
    public void test1ListBadCompat() {
        JConnectionDataSource jcon = new JConnectionDataSource();
        jcon.handle("LIST", (String arg) -> {
            assertNotEquals("-laL", arg);
            return "150 okay, opening a definitely real connection";
        });
        FtpConnection connection = new FtpConnection(jcon);
        connection.LIST = "LIST";
        connection.login("username", "password");
        try {
            DataConnectionDataSource dcon = new DataConnectionDataSource(connection);
            dcon.supplyOutput("-laL not found");
            dcon.onEnd(() -> jcon.queue_response("256 transfer complete"));
            connection.list(dcon); // already in FtpC
            assertNotEquals(String.join("\n", connection.currentListing), LS); // this contains the result
            new Thread(() -> connection.disconnect()).run();
            // need to wait for keepAliveThread to finish :)
        } catch (IOException ioe) {
            System.err.println(ioe);
        }
    }

    @Test
    public void test2SmallFile() {
        JConnectionDataSource jcon = new JConnectionDataSource();
        FtpConnection connection = new FtpConnection(jcon);
        connection.login("username", "password");
        connection.upload("my_cool_file", () -> {
            DataConnectionDataSource dcon = new DataConnectionDataSource(connection);
            jcon.handle("STOR", (String arg) -> {
                assertFalse("Check that the transfer hasn't finished yet", dcon.finished);
                return "200 ok";
            });
            dcon.supplyInput("this is a super cool file");
            new Thread(() -> {
                try {
                    // immediately finish; this simulates a really small transfer
                    dcon.finished = true;
                    jcon.queue_response("256 transfer complete");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            return dcon;
        });
        connection.disconnect();
    }

    @Test
    public void test3BigFile() {
        JConnectionDataSource jcon = new JConnectionDataSource();
        FtpConnection connection = new FtpConnection(jcon);
        connection.login("username", "password");
        connection.upload("my_cool_file", () -> {
            DataConnectionDataSource dcon = new DataConnectionDataSource(connection);
            jcon.handle("STOR", (String arg) -> {
                assertFalse("Check that the transfer hasn't finished yet", dcon.finished);
                return "200 ok";
            });
            dcon.supplyInput("this is a super cool file");
            new Thread(() -> {
                try {
                    // wait a bit; this simulates a really big transfer
                    Thread.sleep(1000);
                    dcon.finished = true;
                    jcon.queue_response("256 transfer complete");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            return dcon;
        });
        connection.disconnect();
    }
}