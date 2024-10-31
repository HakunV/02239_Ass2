package server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class Servant extends UnicastRemoteObject implements Service {

    public Servant() throws RemoteException {
        super();
    }

    public String print(String fileName, String printer) throws RemoteException {
        return "Printing " + fileName + " From " + printer;
    }

    public String queue(String printer) throws RemoteException {
        return "Here Is The Queue For Printer: " + printer;
    }

    public String topQueue(String printer, int job) throws RemoteException {
        return "Printer: " + printer + ", Moved Job: " + job + ", To The Top";
    }

    public String start() throws RemoteException {
        return "Started Print Server";
    }

    public String stop() throws RemoteException {
        return "Stopped Print Server";
    }

    public String restart() throws RemoteException {
        return "Print Server Restarted";
    }

    public String status(String printer) throws RemoteException {
        return "Here Is The Status Of Printer: " + printer;
    }

    public String readConfig(String parameter) throws RemoteException {
        return "Here Is The Configuration For: " + parameter;
    }

    public String setConfig(String parameter, String value) throws RemoteException {
        return "Parameter: " + parameter + ", Has Been Set To: " + value;
    }
}
