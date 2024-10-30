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

    public void queue(String printer) throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'queue'");
    }

    public void topQueue(String printer, int job) throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'topQueue'");
    }

    public void start() throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'start'");
    }

    public void stop() throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'stop'");
    }

    public void restart() throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'restart'");
    }

    public void status(String printer) throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'status'");
    }

    public void readConfig(String parameter) throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'readConfig'");
    }

    public void setConfig(String parameter, String value) throws RemoteException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setConfig'");
    }
}
