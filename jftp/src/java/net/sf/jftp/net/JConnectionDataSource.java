package net.sf.jftp.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.function.Function;

public class JConnectionDataSource implements JConnectable {

    // String input_string = "220 ready!!!!!\n" +
    // "331 username okay, send password :3\n" +
    // "230 logged in :D\n" +
    // "215 system type :I\n" +
    // "200 type set to binary!!!!!\n" +
    // "257 \"/\" is the current directory D:\n" +
    // "";
    HashMap<String, Function<String, String>> handler = new HashMap<>();
    public LinkedList<String> message_queue = new LinkedList<>();

    class JCReader extends BufferedReader {
        boolean has_init = false;
        public boolean closed = false;

        public JCReader() {
            super(new StringReader(""));
        }

        public void close() throws IOException {
            super.close();
            closed = true;
        }

        public String readLine() {
            System.out.println("rL >>>");
            while (message_queue.isEmpty() && !closed) {
                try {
                    Thread.sleep(100);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            };
            if (closed) return null;
            System.out.println("rL >>>");
            return message_queue.pop();
        }
    }

    public JConnectionDataSource() {
        message_queue.add("220 ready");
        // setup default handlers
        handler.put("NOOP", (String args) -> "200 still alive");
        handler.put("USER", (String args) -> "331 username okay, send password");
        handler.put("PASS", (String args) -> "230 logged in successfully");
        handler.put("SYST", (String args) -> "215 system type");
        handler.put("TYPE", (String args) -> {
            if (args.equals("I"))
                return "200 type set to: binary";
            if (args.equals("A"))
                return "200 type set to: ascii";
            return "504 unsupported type: " + args;
        });
        handler.put("PWD", (String args) -> "257 \"/\" is the current directory");
        handler.put("MODE", (String args) -> "200 transfer mode set to: s");
        handler.put("PASV", (String args) -> "227 entering passive mode (0,0,0,0,0,00000)");
        handler.put("LIST", (String args) -> "150 okay, opening a definitely real connection");
        handler.put("STOR", (String args) -> "150 okay, opening a definitely real connection");
        handler.put("QUIT", (String args) -> {
            try {
                in.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return "221 goodbye :(";
        });
    }

    BufferedReader in = new JCReader();

    public void handle(String command, Function<String, String> lambda) {
        handler.put(command, lambda);
    }

    public void queue_response(String s) {
        message_queue.add(s);
        System.out.println(message_queue);
    }

    @Override
    public boolean isThere() {
        return true;
    }

    @Override
    public BufferedReader getReader() {
        return in;
    }

    @Override
    public void send(String string) {
        System.out.println("\u001b[1m==> " + string + "\u001b[0m");
        String command = string.split(" ")[0];
        String args = string.replaceFirst(command + " ", "").trim();
        if (handler.containsKey(command)) {
            Function<String, String> lambda = handler.get(command);
            message_queue.add(lambda.apply(args));
        } else
            message_queue.add("404 command " + command + " not found :(");

    }

    @Override
    public InetAddress getLocalAddress() throws IOException {
        System.out.println("getLocalAddress()");
        return InetAddress.getByName(null);

    }

    @Override
    public BufferedReader getIn() {
        System.out.println("getIn()");
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getIn'");
    }

    @Override
    public OutputStream getOut() {
        System.out.println("getOut()");
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getOut'");
    }

}