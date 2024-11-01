package server;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Service extends Remote {
    public String print(String fileName, String printer) throws RemoteException;

    public String queue(String printer) throws RemoteException;

    public String topQueue(String printer, int job) throws RemoteException;

    public String start() throws RemoteException;

    public String stop() throws RemoteException;

    public String restart() throws RemoteException;

    public String status(String printer) throws RemoteException;

    public String readConfig(String parameter) throws RemoteException;

    public String setConfig(String parameter, String value) throws RemoteException;
}