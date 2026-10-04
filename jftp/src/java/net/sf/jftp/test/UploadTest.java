// ========================================== JFTP M2: NEW FILE ===============================================================
package net.sf.jftp.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
 
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.Timeout;
 
import net.sf.jftp.net.FtpConnection;
import net.sf.jftp.net.FtpConstants;

/**
 * Upload tests for JFTP against pyftpdlib server in a test directory
 */
public class UploadTest {
    private static final ServerTestSuite server = new ServerTestSuite();

    @Rule
    public TemporaryFolder local = new TemporaryFolder();
    
    @Rule
    public Timeout timeout = Timeout.seconds(20);

    private FtpConnection con;

    @BeforeClass
    public static void startServer() throws Exception {
        boolean enabled = false;
        assert enabled = true;

        if(!enabled) {
            throw new IllegalStateException("assertions are disabled. Run the tests with -ea");
        }

        server.start();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        server.stop();

        //ASSERT: Make sure the test directory was torn down
        assertFalse("Test directory was not torn down", Files.exists(server.root()));
    }

    @Before
    public void connect() {
        con = login("test");
    }

    @After
    public void disconnect() {
        con.disconnect();
    }

    private FtpConnection login(String user){
        FtpConnection c = new FtpConnection("127.0.0.1", server.port(), "/");

        // ASSERT: LOGIN SUCCEEDED
        assertEquals("login as" + user, FtpConstants.LOGIN_OK, c.login(user, user));

        c.setLocalPath(local.getRoot().getAbsolutePath());
        return c;
    }

    private byte[] localFile(String filename, int size) throws Exception {
        byte[] data = new byte[size];
        new Random(size).nextBytes(data);
        Files.write(new File(local.getRoot(), filename).toPath(), data);
        return data;
    }

    /**
     * Uploads a file and checks that client, server, and disk all agree on the size
     */
    private void uploadAndVerify(String filename, int size) throws Exception {
        byte[] data = localFile(filename, size);

        // ASSERT: UPLOAD RETURNED A SUCCESS
        assertEquals("upload() return code: ", FtpConstants.TRANSFER_SUCCESSFUL, con.upload(filename));

        //Check the server's record of the transfer
        assertTrue("server did not report receiving " + size + " bytes for " + filename, server.await("RECEIVED " + filename + " " + size, 5000));
        assertEquals("server-side assertions", Collections.emptyList(), server.failures());

        //Check what is actually on the disk
        assertArrayEquals("stored file differs from source", data, Files.readAllBytes(server.root().resolve(filename)));
    }

    //============================== TESTS =======================================================================================================================

    @Test
    public void uploadSmallFile() throws Exception {
        uploadAndVerify("small.bin", 10);
    }

    @Test
    public void uploadLargeFile() throws Exception {
        uploadAndVerify("large.bin", 5000000);
    }

    @Test
    public void uploadEmptyFile() throws Exception {
        uploadAndVerify("empty.bin", 0);
    }

    @Test
    public void uploadPermissions() throws Exception {
        localFile("denied.bin", 1000);
        FtpConnection readOnly = login("readonly");

        try {
            assertEquals("upload() return code", FtpConstants.TRANSFER_FAILED, readOnly.upload("denied.bin"));
        } finally {
            readOnly.disconnect();
        }

        assertFalse("denied upload left a file on the server", Files.exists(server.root().resolve("denied.bin")));
    }

    @Test (expected = AssertionError.class)
    public void missingLocalFile() {
        con.upload("does-not-exist.bin");
    }

    @Test
    public void listingMatchesDirectory() throws Exception {
        //Put some files onto the disk directly without using JFTP to do so
        Files.write(server.root().resolve("report.txt"), new byte[1234]);
        Files.write(server.root().resolve("my notes.txt"), new byte[7]);
        Files.createDirectories(server.root().resolve("photos"));

        //Check what is really in the server directory
        Map<String, String> expected = new TreeMap<String, String>();
        for (File f : server.root().toFile().listFiles()) {
            expected.put(f.isDirectory() ? f.getName() + "/" : f.getName(),
                        f.isDirectory() ? "dir" : String.valueOf(f.length()));
        }

        //Check what JFTP says is there
        //Force LIST Compatibility mode here since that's not what's being tested
        FtpConnection.LIST = "LIST";
        con.list();
        String[] names = con.sortLs();
        String[] sizes = con.sortSize();

        assertEquals("names and sizes are out of step", names.length, sizes.length);

        //Make a map of what JFTP says is there to compare against the expected
        Map<String, String> clientListing = new TreeMap<String, String>();
        for (int i = 0; i < names.length; i++) {
            clientListing.put(names[i], names[i].endsWith("/") ? "dir" : sizes[i]);
        }

        assertEquals("JFtp's listing differs from the server directory", expected, clientListing);
    }

    @Test (expected = IOException.class)
    public void listingBreaksWithoutCompatibility() throws Exception {
        Files.write(server.root().resolve("report.txt"), new byte[1234]);
        Files.write(server.root().resolve("my notes.txt"), new byte[7]);
        Files.createDirectories(server.root().resolve("photos"));

        Map<String, String> expected = new TreeMap<String, String>();
        for (File f : server.root().toFile().listFiles()) {
            expected.put(f.isDirectory() ? f.getName() + "/" : f.getName(),
                        f.isDirectory() ? "dir" : String.valueOf(f.length()));
        }

        //WITHOUT List compatibility mode on, the extra -laL flag sent causes a timeout here
        con.list();
        String[] names = con.sortLs();
        String[] sizes = con.sortSize();

        assertEquals("names and sizes are out of step", names.length, sizes.length);

        Map<String, String> clientListing = new TreeMap<String, String>();
        for (int i = 0; i < names.length; i++) {
            clientListing.put(names[i], names[i].endsWith("/") ? "dir" : sizes[i]);
        }

        assertEquals("JFtp's listing differs from the server directory", expected, clientListing);
    }
}