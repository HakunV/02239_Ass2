package client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Scanner;

import server.Service;

public class Client {
    public static Scanner sc;
    public static Service service;
    private static String username;

    private static boolean clientActive = true;

    public static void client(String[] args) throws MalformedURLException, RemoteException, NotBoundException {
        service = (Service) Naming.lookup("rmi://localhost:6969/Printer");
        sc = new Scanner(System.in);

        tryLogin();

        while (clientActive) {
            clearConsole();
            printOptions();
            String input = sc.nextLine();

            switch (input) {
                case "print":
                    print();
                    break;
                case "queue":
                    queue();
                    break;
                case "topqueue":
                    topQueue();
                    break;
                case "start":
                    start();
                    break;
                case "stop":
                    stop();
                    break;
                case "restart":
                    restart();
                    break;
                case "status":
                    status();
                    break;
                case "readconfig":
                    readConfig();
                    break;
                case "setconfig":
                    setConfig();
                    break;
                case "exit":
                    shutdown();
                    break;
                default:
                    wrongInput();
                    break;
            }
        }
        sc.close();
    }

    private static void tryLogin() {
        while (!login()) {
            waitFor(5000);
        }
    }

    private static boolean login() {
        clearConsole();
        System.out.println("Enter username:");
        username = sc.nextLine();
        System.out.println("Enter password:");
        String password = sc.nextLine();

        try {
            String response = service.login(username, password);
            clearConsole();
            System.out.println(response);
            return response.toLowerCase().contains("successful");
        } catch (RemoteException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static void setConfig() {
        clearConsole();
        System.out.println("Type The Parameter To Be Set:");
        String param = sc.nextLine();

        clearConsole();
        System.out.println("Type Value:");
        String val = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.setConfig(username, param, val));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void readConfig() {
        clearConsole();
        System.out.println("Type The Parameter To Be Read:");
        String param = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.readConfig(username, param));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void status() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.status(username, printer));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void restart() {
        clearConsole();
        try {
            System.out.println("--- " + service.restart(username));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void stop() {
        clearConsole();
        try {
            System.out.println("--- " + service.stop(username));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void start() {
        clearConsole();
        try {
            System.out.println("--- " + service.start(username));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
        
    }

    private static void topQueue() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        System.out.println("Type Job ID:");
        int job = sc.nextInt();
        sc.nextLine(); // Consume the newline

        clearConsole();
        try {
            System.out.println("--- " + service.topQueue(username, printer, job));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void queue() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.queue(username, printer));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void print() {
        clearConsole();
        System.out.println("Type Name Of File To Be Printed:");
        String name = sc.nextLine();

        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.print(username, name, printer));
            waitFor(2000);
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            waitFor(3000);
            tryLogin();
        }
    }

    private static void wrongInput() {
        clearConsole();
        System.out.println("Invalid Input!!! Try Again");
        waitFor(2000);
    }

    private static void waitFor(int n) {
        try {
            Thread.sleep(n);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void printOptions() {
        System.out.println("Choose An Option By Typing The Word:");
        System.out.println();

        System.out.println("- print");
        System.out.println("- queue");
        System.out.println("- topqueue");
        System.out.println("- start");
        System.out.println("- stop");
        System.out.println("- restart");
        System.out.println("- status");
        System.out.println("- readconfig");
        System.out.println("- setconfig");
    }

    private static void clearConsole() {
        try {
            new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void shutdown() {
        System.out.println("\nExiting...");

        clientActive = false;
    }
}
