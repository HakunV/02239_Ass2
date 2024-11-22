package server;

import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import client.Client;

public class AuthServer {
    public static void main(String[] args) throws RemoteException, MalformedURLException, NotBoundException {
        System.out.println("Starting Service...");
        System.out.println();
        Registry reg = LocateRegistry.createRegistry(6969);

        Servant s = new Servant();

        reg.rebind("Printer", s);

        System.out.println("Service Started");
        System.out.println();

        Client.client(args);
        reg.unbind("Printer");
        UnicastRemoteObject.unexportObject(s, true);
    }
}
