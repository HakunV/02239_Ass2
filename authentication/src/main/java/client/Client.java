package client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

import server.Service;

public class Client {
    public static void client(String[] args) throws MalformedURLException, RemoteException, NotBoundException {
        Service service = (Service) Naming.lookup("rmi://localhost:6969/Printer");

        boolean clientActive = true;
        while (clientActive) {
            System.out.println("--- " + service.print("secret.txt", "CoolPrinter"));
            clientActive = false;
        }
    }
}
