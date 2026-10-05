// =============================================== JFTP M2: NEW FILE=======================================================================

package net.sf.jftp.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Starts test_server.py, gets its directory and port, and collects the assert messages it sends
 */
public class ServerTestSuite{
    private Process process;
    private BufferedReader out;
    private Path root;
    private int port;
    private final List<String> lines = new ArrayList<String>();

    public Path root() {
        return root;
    }

    public int port() {
        return port;
    }

    public void start() throws IOException {
        String python = System.getProperty("ftp.python", "python");
        String script = System.getProperty("ftp.script", "../pyftpdlib/test_server.py");

        if(!new File(script).isFile()){
            throw new IOException("server script not found: " + new File(script).getAbsolutePath());
        }

        ProcessBuilder pb = new ProcessBuilder(python, script);
        //Get the logs from the server to go to the test console
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);

        process = pb.start();
        out = new BufferedReader(new InputStreamReader(process.getInputStream()));

        root = Paths.get(expect("ROOT "));
        port = Integer.parseInt(expect("READY "));
    }

    /**
     * Waits to see a certain prefix from the server, and gets the rest of the information sent along with that prefix
     */
    private String expect(String prefix) throws IOException {
        String line = out.readLine();

        if(line == null || !line.startsWith(prefix)) {
            throw new IOException("Expected \"" + prefix + "...\" from server, got: " + line);
        }

        return line.substring(prefix.length());
    }

    /**
     * Waits until server has sent the specified line. False if not within timeout
     */
    public boolean await (String line, long timeOutMS) throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + timeOutMS;

        while(true) {
            drain();

            if(lines.contains(line)) {
                return true;
            }

            if(System.currentTimeMillis() >= deadline) {
                return false;
            }

            Thread.sleep(20);
        }
    }

    /**
     * Makes a list of failure messages sent from the server
     */
    public List<String> failures() throws IOException {
        drain();

        List<String> failed = new ArrayList<String>();

        for(String line : lines) {
            if (line.startsWith("FAIL ")) {
                failed.add(line);
            }
        }

        return failed;
    }

    private void drain() throws IOException {
        while(out.ready()) {
            String line = out.readLine();
            if(line == null) {
                return;
            }

            lines.add(line);
        }
    }

    /**
     * Tear down test directory
     */
    public void stop() throws IOException, InterruptedException {
        if(process == null) {
            return;
        }

        //Send the .stop file
        if(root != null && Files.isDirectory(root)) {
            Files.write(root.resolve(".stop"), new byte[0]);
        }

        if(!process.waitFor(10, TimeUnit.SECONDS)){
            process.destroy();
            throw new IOException("Server did not stop. Test directory may not be torn down: " + root);
        }
    }

}