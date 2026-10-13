package net.sf.jftp.net;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DataConnectionDataSource implements DataConnectable {

    FtpConnection ftpCon = null;
    byte[] input_bytes = {};
    byte[] output_bytes = {};
    public boolean finished = false;
    List<Runnable> end_callbacks = new ArrayList<>();


    public DataConnectionDataSource(FtpConnection ftpCon) {
        System.out.println("DataConnectionDataSource created");
        ftpCon = this.ftpCon;
    }

    class DCInputStream extends InputStream {
        int pos = 0;
        
        @Override
        public int read() throws IOException {
            if (pos == output_bytes.length) {
                while(end_callbacks.size() > 0) end_callbacks.remove(0).run();
                return -1;
            }
            return output_bytes[pos++];
        }

    }

    public void supplyInput(String s) {
        input_bytes = s.getBytes();
    }

    public void supplyOutput(String s) {
        output_bytes = s.getBytes();
    }

    public void onEnd(Runnable callback) {
        end_callbacks.add(callback);
    }

    @Override
    public InputStream getInputStream() {
        return new DCInputStream();
    }

    @Override
    public boolean isThere() {
        return true;
    }

    @Override
    public FtpConnection getCon() {
        return this.ftpCon;
    }

    @Override 
    public boolean getFinished() {
        return this.finished;
    }

}