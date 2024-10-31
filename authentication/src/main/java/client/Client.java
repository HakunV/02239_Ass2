package client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.InputMismatchException;
import java.util.Scanner;

import server.Service;

public class Client {
    public static Scanner sc;
    public static Service service;

    public static void client(String[] args) throws MalformedURLException, RemoteException, NotBoundException {
        service = (Service) Naming.lookup("rmi://localhost:6969/Printer");
        sc = new Scanner(System.in);

        boolean clientActive = true;
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
                default:
                    wrongInput();
                    break;
            }
            // System.out.println("--- " + service.print("secret.txt", "CoolPrinter"));
            // clientActive = false;
        }
        sc.close();
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
            System.out.println("--- " + service.setConfig(param, val));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void readConfig() {
        clearConsole();
        System.out.println("Type The Parameter To Be Read:");
        String param = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.readConfig(param));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void status() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.status(printer));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void restart() {
        clearConsole();
        try {
            System.out.println("--- " + service.restart());
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void stop() {
        clearConsole();
        try {
            System.out.println("--- " + service.stop());
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void start() {
        clearConsole();
        try {
            System.out.println("--- " + service.start());
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void topQueue() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        System.out.println("Type Job ID:");
        int job = -1;
        while (job < 0) {
            try {
                job = sc.nextInt();
            }
            catch (InputMismatchException e) {
                System.out.println("Input Must Be A Number");
            }
        }

        clearConsole();
        try {
            System.out.println("--- " + service.topQueue(printer, job));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void queue() {
        clearConsole();
        System.out.println("Type Name Of Printer:");
        String printer = sc.nextLine();

        clearConsole();
        try {
            System.out.println("--- " + service.queue(printer));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
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
            System.out.println("--- " + service.print(name, printer));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        waitFor(2000);
    }

    private static void wrongInput() {
        clearConsole();
        System.out.println("INVALID INPUT!!! Try Again");
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
}
