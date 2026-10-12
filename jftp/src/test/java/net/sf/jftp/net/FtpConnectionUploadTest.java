package net.sf.jftp.net;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import net.sf.jftp.config.Settings;

public class FtpConnectionUploadTest {

	private static final String LOCAL_FILE = "test.txt";
    private static final int PORT = 12345;
    private static final String HOST = "127.0.0.1";
    private static final String USERNAME = "chenp5";
    private static final String PASSWORD = "123456";

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	private static Process server;
	private FtpConnection conn;
    private InvocationHandler handler;
    private FtpTestInterface proxy;

    @BeforeClass 
    public static void startPyftpdlibServer() throws IOException, IllegalStateException {
        ProcessBuilder processBuilder = new ProcessBuilder("python", "-m", "pyftpdlib", "-w", "-p", String.valueOf(PORT), "--username", USERNAME, "--password", PASSWORD);
        processBuilder.directory(new File("../pyftpdlib"));

        processBuilder.inheritIO();

        server = processBuilder.start();
        waitForServerStartup();
    }

    private static void waitForServerStartup() throws IllegalStateException {
        int maxAttempts = 10;
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            if (server.isAlive() && isServerRunning()) {
                return;
            } else if (!server.isAlive()) {
                throw new IllegalStateException("Python server terminated.");
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Thread was interrupted.");
            }
        }

        server.destroyForcibly();
        throw new IllegalStateException("Python server failed to start in time.");
    }

    private static boolean isServerRunning() {
        Socket socket = null;
        try {
            socket = new Socket(HOST, PORT);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {}
            }
        }
    }

    @AfterClass
    public static void stopPyftpdlibServer() {
        if (server != null) {
            server.destroyForcibly();
        }
    }

    @Before 
    public void setUp() {
        Settings.ftpKeepAlive = false;
        Settings.enableUploadResuming = false;
        Settings.setProperty("jftp.enableMultiThreading", true);
        Settings.setProperty("jftp.noUploadMultiThreading", false);
        FtpConnection.LIST = FtpConnection.LIST_DEFAULT;

        conn = new FtpConnection(HOST, PORT, Settings.defaultDir);

        handler = new SEIInvocationHandler(conn);
		proxy = (FtpTestInterface) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[] {FtpTestInterface.class}, handler);
    }

	@After
	public void tearDown() {
		if (conn != null && conn.isConnected()) {
			try {
				conn.disconnect();
			} catch (Exception ignored) {
			}
		}
	}

	private FtpTransferTestInterface makeFtpTransferProxy(FtpTransfer transfer) {
		return (FtpTransferTestInterface) Proxy.newProxyInstance(
				ClassLoader.getSystemClassLoader(),
				new Class[] { FtpTransferTestInterface.class },
				new SEIInvocationHandler(transfer));
	}

	private File createLocalUploadFile() throws IOException {
		File local = folder.newFile(LOCAL_FILE);
		try (OutputStream out = new FileOutputStream(local)) {
			out.write("hello world!!".getBytes(StandardCharsets.UTF_8));
		}
		conn.setLocalPath(folder.getRoot().getAbsolutePath());
		return local;
	}

	@Test
	public void testLoginStoresCredentialsAndOpensControlConnection() {
		int status = conn.login(USERNAME, PASSWORD);

		assertEquals(FtpConnection.LOGIN_OK, status);
		assertEquals(HOST, proxy.getHost());
		assertEquals(PORT, proxy.getPort());
		assertEquals(USERNAME, proxy.getUsername());
		assertEquals(PASSWORD, proxy.getPassword());
		assertTrue(proxy.getConnected());
		assertNotNull(proxy.getJcon());
		assertTrue(proxy.getJcon().getLocalPort() > 0);
	}

	@Test
	public void testUploadWiring() throws IOException {
		createLocalUploadFile();
		conn.login(USERNAME, PASSWORD);

		int status = proxy.handleUpload(LOCAL_FILE);

		assertEquals(FtpConnection.NEW_TRANSFER_SPAWNED, status);
		assertEquals(1, proxy.getTransfers().size());

		FtpTransferTestInterface transfer = makeFtpTransferProxy(proxy.getTransfers().get(0));
		assertEquals(HOST, transfer.getHost());
		assertEquals(PORT, transfer.getPort());
		assertEquals(USERNAME, transfer.getUser());
		assertEquals(PASSWORD, transfer.getPass());
		assertEquals(LOCAL_FILE, transfer.getFile());
		assertEquals(Transfer.UPLOAD, transfer.getType());
	}

	@Test(timeout = 8000)
	public void testUploadFile() throws IOException {
		File local = createLocalUploadFile();
		conn.login(USERNAME, PASSWORD);

		int status = proxy.upload(local.getAbsolutePath());

		assertEquals(FtpConnection.TRANSFER_SUCCESSFUL, status);
		assertTrue(proxy.getHasUploaded());
		assertEquals(DataConnection.PUT, proxy.getDataType());
		assertNotNull(proxy.getDcon());
	}

	@Test
	public void testLoginFailsWithWrongPassword() {
		int status = conn.login(USERNAME, "wrong-password");

		assertEquals(FtpConnection.WRONG_LOGIN_DATA, status);
		assertEquals(false, proxy.getConnected());
	}

    @Test 
    public void testLoginFailsWithWrongUsername() {
        int status = conn.login("wrong-username", PASSWORD);

        assertEquals(FtpConnection.WRONG_LOGIN_DATA, status);
        assertEquals(false, proxy.getConnected());
    }
}
