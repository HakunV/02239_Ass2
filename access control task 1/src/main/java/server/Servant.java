package server;

import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.SimpleFormatter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.Buffer;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.SecureRandom;

// AccessControl.csv before:

// User,Operations
// AliceAdmin,all
// CeciliaPowerUser,print:restart:queue:topQueue
// BobJanitor,print:start:stop:restart:queue:topQueue:status:readConfig:setConfig
// DavidUser,print:queue
// EricaUser,print:queue
// FredUser,print:queue
// GeorgeUser,print:queue


// Users and passwords, after changes

//  Alice, George and Cecilia are administrators, service technician and power user who are allowed to perform more operations.

// AliceAdmin, adminpass // Admin can do everything
// GeorgeUser, georgian // Technician can invoke print, queue, topQueue, start, stop, restart, status, readConfig and setConfig operations

// Power user can invoke print, queue, topQueue, start, stop, and restart operations

// CeciliaPowerUser, powerpass
// IdaUser, IDApowerpass

//  David, Erica, Fred and Henry are ordinary users who are only allowed to: print files and display the print queue.

// DavidUser, secretpassword
// EricaUser, pasword1234
// FredUser, 1234567654321
// HenryUser, henrypass

public class Servant extends UnicastRemoteObject implements Service {
    private Map<String, Long> activeSessions; // Stores sessions with expiration time
    private static final long SESSION_DURATION = 300000; // 5 minutes in milliseconds

    private static final String ACCESS_CONTROL = new File("access control task 1/src/main/java/server/AccessControl.csv").getAbsolutePath();
    private static final String PASSWORD_FILE = new File("access control task 1/src/main/java/server/passwords.csv").getAbsolutePath();
    private static final String EVENTLOG_FILE = new File("access control task 1/src/main/java/server/eventlogs").getAbsolutePath();

    private static final Logger logger = Logger.getLogger(Servant.class.getName());

    public Servant() throws RemoteException {
        super();
        configureLogger();
        activeSessions = new HashMap<>();
    }

    private void configureLogger() {
        try {
            // Step 1: Verify and create the log directory
            File logDir = new File(EVENTLOG_FILE);
            if (!logDir.exists()) {
                if (logDir.mkdirs()) {
                    System.out.println("Log directory created: " + logDir.getAbsolutePath());
                } else {
                    System.err.println("Failed to create log directory: " + logDir.getAbsolutePath());
                }
            }

            // Step 2: Clear existing handlers for this logger
            clearHandlers(logger);

            // Step 3: Create a FileHandler
            String logFilePath = EVENTLOG_FILE + "/eventlog.log";
            System.out.println("Resolved log file path: " + logFilePath);
            FileHandler fileHandler = new FileHandler(logFilePath, true);
            fileHandler.setFormatter(new SimpleFormatter());
            fileHandler.setLevel(java.util.logging.Level.ALL);

            // Step 4: Attach the FileHandler to the logger
            logger.addHandler(fileHandler);

            // Step 5: Disable parent handlers
            logger.setUseParentHandlers(false);

            // Step 6: Set logger level
            logger.setLevel(java.util.logging.Level.ALL);

            // Debugging: Confirm configuration
            System.out.println("Logger handlers configured: " + logger.getHandlers().length);
            logger.info("Logger configuration complete.");

        } catch (IOException e) {
            System.err.println("Error configuring logger: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void clearHandlers(Logger logger) {
        for (Handler handler : logger.getHandlers()) {
            handler.close();
            logger.removeHandler(handler);
        }
    }

    // Reads the information of a user in the "password.csv" file
    private String[] getUserInfo(String username) {
        BufferedReader reader = null;
        String line = "";

        try {
            reader = new BufferedReader(new FileReader(Servant.PASSWORD_FILE));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            while ((line = reader.readLine()) != null) {
                String[] user = line.split(",");

                if (user[0].equals(username)) {
                    reader.close();
                    return user;
                }
            }
            reader.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Hashes of the inputted password and checks it with the hash stored for that user
    private boolean authenticate(String username, String password) {
        String[] userInfo = getUserInfo(username);

        if (userInfo == null) {
            return false;
        }

        // First hash the username with the salt of the user
        String userHash = hash_Argon2(userInfo[0], userInfo[2]);

        // Then hash the given password with the hash from before
        String passwordHash = hash_Argon2(password, userHash);

        if (passwordHash.equals(userInfo[1])) {
            return true;
        }
        return false;
    }

    // Check Login and creates session if successful
    public String login(String username, String password) throws RemoteException {
        if (authenticate(username, password)) {
            long expirationTime = System.currentTimeMillis() + SESSION_DURATION;
            activeSessions.put(username, expirationTime);
            logger.info("User " + username + " logged in with session valid until: " + expirationTime);
            return "Login successful. Session active.";
        }
        logger.warning("Login failed for user: " + username);
        return "Login failed. Invalid credentials.\nWait 5 seconds to try again";
    }

    // Checks if the session is expired. If not session is extended
    private boolean isSessionValid(String username) {
        if (activeSessions.containsKey(username)) {
            long currentTime = System.currentTimeMillis();
            long expirationTime = activeSessions.get(username);
            if (currentTime < expirationTime) {
                // Extend session validity upon valid use
                activeSessions.put(username, currentTime + SESSION_DURATION);
                logger.info("Session extended for user: " + username);
                return true;
            } else {
                activeSessions.remove(username); // Invalidate session
                logger.info("Session expired for user: " + username);
            }
        }
        return false;
    }

    // Helper method to enforce session check
    private boolean validateSession(String username, String operation) throws RemoteException {
        if (!isSessionValid(username)) {
            logger.warning("Unauthorized access attempt by user: " + username + ", Session invalid");
            throw new RemoteException("Session is not valid. Please log in again.");
        }
        else if (!validateAccess(username, operation)) {
            logger.warning("Unauthorized access attempt by user: " + username + ", Tried to run function: " + operation);
            return false;
        }
        return true;
    }

    // Checks the user rights from the Access Control List
    private boolean validateAccess(String username, String operation) throws RemoteException {
        String rights = getAccessRights(username);
        if (rights.equals("all")) {
            return true;
        }

        String[] rightsArr = rights.split(":");
        for (String r : rightsArr) {
            if (r.equals(operation)) {
                return true;
            }
        }
        return false;
    }

    // Reads the access rights from the "AccessControl.csv" file
    private String getAccessRights(String username) {
        BufferedReader br = null;
        String line = "";

        try {
            br = new BufferedReader(new FileReader(Servant.ACCESS_CONTROL));
        }
        catch(FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            while ((line = br.readLine()) != null) {
                String[] check = line.split(",");

                if (check[0].equals(username)) {
                    br.close();
                    return check[1];
                }
            }
            br.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String print(String username, String fileName, String printer) throws RemoteException {
        if (validateSession(username, "print")) {
            logger.info("Print command received. User: " + username + ", File: " + fileName + ", Printer: " + printer);
            return "Printing " + fileName + " on " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String queue(String username, String printer) throws RemoteException {
        if (validateSession(username, "queue")) {
            logger.info("Queue command received. User: " + username + ", Printer: " + printer);
            return "Queue for printer " + printer + ": [Sample Job List]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String topQueue(String username, String printer, int job) throws RemoteException {
        if (validateSession(username, "topQueue")) {
            logger.info("Top queue command received. User: " + username + ", Printer: " + printer + ", Job: " + job);
            return "Moved job " + job + " to the top of the queue for printer " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String start(String username) throws RemoteException {
        if (validateSession(username, "start")) {
            logger.info("Start command received. User: " + username);
            return "Print server started.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String stop(String username) throws RemoteException {
        if (validateSession(username, "stop")) {
            logger.info("Stop command received. User: " + username);
            return "Print server stopped.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String restart(String username) throws RemoteException {
        if (validateSession(username, "restart")) {
            logger.info("Restart command received. User: " + username);
            return "Print server restarted.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String status(String username, String printer) throws RemoteException {
        if (validateSession(username, "status")) {
            logger.info("Status command received. User: " + username + ", Printer: " + printer);
            return "Status of printer " + printer + ": [Sample status]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String readConfig(String username, String parameter) throws RemoteException {
        if (validateSession(username, "readConfig")) {
            logger.info("Read configuration command received. User: " + username + ", Parameter: " + parameter);
            return "Configuration for " + parameter + ": [Sample value]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String setConfig(String username, String parameter, String value) throws RemoteException {
        if (validateSession(username, "setConfig")) {
            logger.info("Set configuration command received. User: " + username + ", Parameter: " + parameter + ", Value: " + value);
            return "Set configuration parameter " + parameter + " to " + value;
        }
        return "Unauthorized access.";
    }

    // Generates a random salt. Used when adding new users
    private String getRandomSalt() {
        SecureRandom secRan = new SecureRandom();
        byte[] bytes = new byte[16];
        secRan.nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }

    // Uses the Argon2 hash algorithm, because it is slow, and a standard for password hashing
    public String hash_Argon2(String password, String salt) {
        Security.addProvider(new BouncyCastleProvider());

        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder();

        byte[] resultHash = new byte[256];

        builder.withIterations(5);
        builder.withSalt(salt.getBytes());
        builder.withVersion(19);

        Argon2Parameters params = builder.build();
        gen.init(params);
        gen.generateBytes(password.toCharArray(), resultHash);

        return Base64.getEncoder().encodeToString(resultHash);
    }
} 