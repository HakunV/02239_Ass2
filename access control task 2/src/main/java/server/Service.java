package server;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Service extends Remote {
    // Methods now include 'username' as a parameter for session validation
    public String print(String username, String fileName, String printer) throws RemoteException;

    public String queue(String username, String printer) throws RemoteException;

    public String topQueue(String username, String printer, int job) throws RemoteException;

    public String start(String username) throws RemoteException;

    public String stop(String username) throws RemoteException;

    public String restart(String username) throws RemoteException;

    public String status(String username, String printer) throws RemoteException;

    public String readConfig(String username, String parameter) throws RemoteException;

    public String setConfig(String username, String parameter, String value) throws RemoteException;

    public String login(String username, String password) throws RemoteException;

}
