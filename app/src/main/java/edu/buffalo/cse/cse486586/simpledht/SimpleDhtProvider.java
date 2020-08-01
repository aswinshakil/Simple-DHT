package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.TreeMap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.TextView;

import static android.content.ContentValues.TAG;

public class SimpleDhtProvider extends ContentProvider {

    static final int SERVER_PORT = 10000;
    ArrayList<String> remotePorts = new ArrayList<String>();
    ArrayList<String> allnodes = new ArrayList<String>();
    static final String KEY="key";
    static final String VALUE="value";
    static String myPort;
    static String portStr;
    static String hashedPort;
    static String pred;
    static String predHashed;
    static String suc;
    static String sucHashed;
    final String  DELIM= "&&";
    TreeMap<String, String> mapPort = new TreeMap<String, String>();
    MatrixCursor matrixCursor = null;
    static boolean queryflag = false;


    Uri providerUri = new Uri.Builder().scheme("content").authority("edu.buffalo.cse.cse486586.simpledht.provider").build();


    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        try {

            if (selection.equals("*")) {
                for (String node : allnodes) {
                    getContext().deleteFile(node);
                }
                allnodes.clear();

            } else if (selection.equals("@")) {
                for (String node : allnodes) {
                    getContext().deleteFile(node);
                }
                allnodes.clear();
            }
            else{
                 getContext().deleteFile(selection);
                 allnodes.remove(selection);
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        String key = values.getAsString("key");
        String value = values.getAsString("value");
        try {
            String keyHash = genHash(key);
            boolean flag = hashedPort.equals(predHashed) || compareKey(keyHash);
            if (flag) {
                allnodes.add(key);
                FileOutputStream fileOutput = getContext().openFileOutput(key, getContext().MODE_PRIVATE);
                fileOutput.write(value.getBytes());
                fileOutput.close();
            }else{
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"FIND"+DELIM+suc+DELIM+key+DELIM+value);
            }
        }catch (IOException e){
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return uri;
    }

    public boolean compareKey(String hashkey){
        if((predHashed.compareTo(hashedPort) > 0 || hashkey.compareTo(predHashed)> 0))
        {
            if(hashedPort.compareTo(hashkey)>0) {
                return true;
            }
        }
        if(hashkey.compareTo(predHashed)> 0 && hashkey.compareTo(hashedPort)>0  && predHashed.compareTo(hashedPort)>0)
        {
            return true;
        }
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        //Reference http://developer.android.com/reference/android/database/MatrixCursor.html
        String[] columnNames = {"key", "value"};
        matrixCursor = new MatrixCursor(columnNames);
        if(hashedPort.equals(predHashed) && hashedPort.equals(sucHashed) && selection.equals("*"))
        {
            selection="@";
        }
        if(selection.equals("@")) {
            try {
                // Reference https://developer.android.com/training/data-storage/app-specific#java
                for(String node: allnodes) {
                    FileInputStream fileInput = getContext().openFileInput(node);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String output = bufferedReader.readLine();
                    bufferedReader.close();
                    String[] row = {node, output};
                    matrixCursor.addRow(row);
                }
                matrixCursor.close();
                return matrixCursor;

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if(selection.equals("*")){
            try {
                for (String node : allnodes) {
                    FileInputStream fileInput = getContext().openFileInput(node);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String output = bufferedReader.readLine();
                    bufferedReader.close();
                    String[] row = {node, output};
                    matrixCursor.addRow(row);
                }
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "GLOBALQUERY"+ DELIM + portStr + DELIM + suc);
                while (!queryflag){
                    Thread.sleep(1000);
                }
            }catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            matrixCursor.close();
            return matrixCursor;
        }
        else {
            if (allnodes.contains(selection)) {
                try {
                    FileInputStream fileInput = getContext().openFileInput(selection);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String output = bufferedReader.readLine();
                    bufferedReader.close();
                    String[] column = {"key", "value"};
                    MatrixCursor matrixCursor = new MatrixCursor(column);
                    String[] row = {selection, output};
                    matrixCursor.addRow(row);
                    matrixCursor.close();
                    return matrixCursor;

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else{
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"QUERY"+DELIM+portStr+DELIM+suc+DELIM+selection);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                matrixCursor.close();
                return matrixCursor;
            }
        }
        return null;
    }

    @Override
    public boolean onCreate() {
        TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        remotePorts.add("11108");
        remotePorts.add("11112");
        remotePorts.add("11116");
        remotePorts.add("11120");
        remotePorts.add("11124");
        pred = portStr;
        suc = portStr;
        try {
            hashedPort = genHash(portStr);
            predHashed = hashedPort;
            sucHashed= hashedPort;
            mapPort.put(hashedPort,portStr);
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(!myPort.equals("11108"))
        {
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"ADD"+DELIM+portStr+DELIM+myPort);
        }
        return false;
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];

            Socket socket = null;
            try {
                while (true) {
                    socket = serverSocket.accept();
                    DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    String message = input.readUTF();
                    String[] split = message.split(DELIM);
                    if(split[0].equals("JOIN")){
                        String temp = genHash(split[1]);
                        String predTemp;
                        String sucTemp;
                        if(mapPort.ceilingKey(temp)==null || mapPort.floorKey(temp)==null)
                        {
                            predTemp = mapPort.lastKey();
                            sucTemp = mapPort.firstKey();

                        }
                        else{
                            predTemp = mapPort.floorKey(temp);
                            sucTemp = mapPort.ceilingKey(temp);
                        }
                        mapPort.put(temp,split[1]);
                        updateAll(mapPort.get(temp),mapPort.get(predTemp),mapPort.get(sucTemp));
                    }
                    if(split[0].equals("UPDATEBOTH")) {
                        pred = split[1];
                        predHashed= genHash(pred);
                        suc=split[2];
                        sucHashed=genHash(suc);
                    }
                    if(split[0].equals("UPDATEPRE")) {
                        suc=split[1];
                        sucHashed=genHash(suc);
                    }
                    if(split[0].equals("UPDATESUC")) {
                        pred = split[1];
                        predHashed= genHash(pred);
                    }
                    if(split[0].equals("INSERT")) {
                        ContentValues content = new ContentValues();
                        content.put(KEY, split[1]);
                        content.put(VALUE,split[2]);
                        Uri newUri = providerUri;
                        insert(newUri,content);
                    }
                    if(split[0].equals("GLOBALQUERY")){
                        if(!split[1].equals(portStr)) {
                            try {
                                for (String node : allnodes) {
                                    Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                            (Integer.parseInt(split[1]) * 2));
                                    FileInputStream fileInput = getContext().openFileInput(node);
                                    InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
                                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                    String output = bufferedReader.readLine();
                                    bufferedReader.close();
                                    String msg = "QUERYADD" + DELIM + node + DELIM + output;
                                    DataOutputStream out = new DataOutputStream(socket2.getOutputStream());
                                    out.writeUTF(msg);
                                    out.flush();
                                }
                                Socket socket3 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        (Integer.parseInt(suc) * 2));
                                String msg = "GLOBALQUERY" + DELIM + split[1];
                                DataOutputStream out = new DataOutputStream(socket3.getOutputStream());
                                out.writeUTF(msg);
                                out.flush();

                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        else{
                            queryflag=true;
                        }
                    }
                    if(split[0].equals("QUERY")){
                        if(allnodes.contains(split[2])){
                            try {
                                Socket socket1 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        (Integer.parseInt(split[1]) * 2));
                                    FileInputStream fileInput = getContext().openFileInput(split[2]);
                                    InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
                                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                    String output = bufferedReader.readLine();
                                    bufferedReader.close();
                                    String msg = "QUERYADD" + DELIM + split[2] + DELIM + output;
                                    DataOutputStream out = new DataOutputStream(socket1.getOutputStream());
                                    out.writeUTF(msg);
                                    out.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }

                        }
                        else{
                            Socket socket3 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    (Integer.parseInt(suc) * 2));
                            String msg = "QUERY" + DELIM + split[1] + DELIM + split[2];
                            DataOutputStream out = new DataOutputStream(socket3.getOutputStream());
                            out.writeUTF(msg);
                            out.flush();
                        }
                    }
                    if(split[0].equals("QUERYADD")) {
                        String[] row = {split[1], split[2]};
                        matrixCursor.addRow(row);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }

        protected void updateAll(String temp,String predTemp, String sucTemp ) {
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"UPDATEBOTH"+DELIM+temp+DELIM+predTemp+DELIM+sucTemp);
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"UPDATEPRE"+DELIM+temp+DELIM+predTemp);
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,"UPDATESUC"+DELIM+temp+DELIM+sucTemp);
        }

    }
    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            Socket socket = null;
            String[] split = msgs[0].split(DELIM);
            if(split[0].equals("ADD")){
                try {
                socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt("11108"));
                String msg = "JOIN"+DELIM+portStr+DELIM+myPort;
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                output.writeUTF(msg);
                output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(split[0].equals("UPDATEBOTH")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[1])*2));
                    String msg = "UPDATEBOTH"+DELIM+split[2]+DELIM+split[3];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(split[0].equals("UPDATEPRE")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[2])*2));
                    String msg = "UPDATEPRE"+DELIM+split[1];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(split[0].equals("UPDATESUC")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[2])*2));
                    String msg = "UPDATESUC"+DELIM+split[1];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(split[0].equals("FIND")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[1])*2));
                    String msg = "INSERT"+DELIM+split[2]+DELIM+split[3];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(split[0].equals("GLOBALQUERY")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[2])*2));
                    String msg = "GLOBALQUERY"+DELIM+split[1];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
            else if(split[0].equals("QUERY")){
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(split[2])*2));
                    String msg = "QUERY"+DELIM+split[1]+DELIM+split[3];
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    output.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
            return null;
            }
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }
}
