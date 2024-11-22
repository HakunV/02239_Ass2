package server;

import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.SimpleFormatter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.SecureRandom;

// AliceAdmin, adminpass
// BobJanitor, servicepass
// CeciliaPowerUser, powerpass
// DavidUser, secretpassword
// EricaUser, pasword1234
// FredUser, 1234567654321
// GeorgeUser, georgian

public class Servant extends UnicastRemoteObject implements Service {
    private Map<String, Long> activeSessions; // Stores sessions with expiration time
    private static final long SESSION_DURATION = 300000; // 5 minutes in milliseconds

    private static final String ROLE_FILE = new File("access control task 2/src/main/java/server/RolePermissions.csv").getAbsolutePath();
    private static final String PASSWORD_FILE = new File("access control task 2/src/main/java/server/passwords.csv").getAbsolutePath();
    private static final String EVENTLOG_FILE = new File("access control task 2/src/main/java/server/eventlogs").getAbsolutePath();

    private static final Logger logger = Logger.getLogger(Servant.class.getName());

    public Servant() throws RemoteException {
        super();
        configureLogger();
        activeSessions = new HashMap<>();
    }

    // Session creation
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

    private void configureLogger() {
        try {
            File logDir = new File(EVENTLOG_FILE);
            if (!logDir.exists() && logDir.mkdirs()) {
                System.out.println("Log directory created: " + logDir.getAbsolutePath());
            }

            clearHandlers(logger);

            String logFilePath = EVENTLOG_FILE + "/eventlog.log";
            FileHandler fileHandler = new FileHandler(logFilePath, true);
            fileHandler.setFormatter(new SimpleFormatter());
            fileHandler.setLevel(java.util.logging.Level.ALL);

            logger.addHandler(fileHandler);
            logger.setUseParentHandlers(false);
            logger.setLevel(java.util.logging.Level.ALL);

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

    // Authentication check
    private boolean authenticate(String username, String password) {
        String[] userInfo = getUserInfo(username);

        if (userInfo == null) {
            return false;
        }

        String userHash = hash_Argon2(userInfo[0], userInfo[2]);
        String passwordHash = hash_Argon2(password, userHash);

        return passwordHash.equals(userInfo[1]);
    }

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

    private boolean hasPermission(String username, String action) {
        String userRole = getUserRole(username);
        if (userRole == null) {
            return false;
        }

        String[] rolePerm = getRolePermissions(userRole);
        if (rolePerm == null) {
            return false;
        }
        else if (rolePerm[0].equals("all")) {
            return true;
        }
        
        for (String p : rolePerm) {
            if (p.equals(action)) {
                return true;
            }
        }

        return false;
    }

    private String getUserRole(String username) {
        String[] user = getUserInfo(username);
        return user[3];
    }

    private String[] getRolePermissions(String role) {
        BufferedReader reader = null;
        String line = "";

        try {
            reader = new BufferedReader(new FileReader(Servant.ROLE_FILE));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            while((line = reader.readLine()) != null) {
                String[] roleInfo = line.split(",");

                if (roleInfo[0].equals(role)) {
                    reader.close();
                    return roleInfo[1].split(":");
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Session validation check
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
    private boolean validateSession(String username) throws RemoteException {
        if (!isSessionValid(username)) {
            logger.warning("Unauthorized access attempt by user: " + username + ", Session invalid");
            throw new RemoteException("Session is not valid. Please log in again.");
        }
        return true;
    }

    @Override
    public String print(String username, String fileName, String printer) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "print")) {
            logger.info("Print command received. User: " + username + ", File: " + fileName + ", Printer: " + printer);
            return "Printing " + fileName + " on " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String queue(String username, String printer) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "queue")) {
            logger.info("Queue command received. User: " + username + ", Printer: " + printer);
            return "Queue for printer " + printer + ": [Sample Job List]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String topQueue(String username, String printer, int job) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "topQueue")) {
            logger.info("Top queue command received. User: " + username + ", Printer: " + printer + ", Job: " + job);
            return "Moved job " + job + " to the top of the queue for printer " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String start(String username) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "start")) {
            logger.info("Start command received. User: " + username);
            return "Print server started.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String stop(String username) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "stop")) {
            logger.info("Stop command received. User: " + username);
            return "Print server stopped.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String restart(String username) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "restart")) {
            logger.info("Restart command received. User: " + username);
            return "Print server restarted.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String status(String username, String printer) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "status")) {
            logger.info("Status command received. User: " + username + ", Printer: " + printer);
            return "Status of printer " + printer + ": [Sample status]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String readConfig(String username, String parameter) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "readConfig")) {
            logger.info("Read configuration command received. User: " + username + ", Parameter: " + parameter);
            return "Configuration for " + parameter + ": [Sample value]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String setConfig(String username, String parameter, String value) throws RemoteException {
        if (validateSession(username) && hasPermission(username, "setConfig")) {
            logger.info("Set configuration command received. User: " + username + ", Parameter: " + parameter + ", Value: " + value);
            return "Set configuration parameter " + parameter + " to " + value;
        }
        return "Unauthorized access.";
    }

    private String getRandomSalt() {
        SecureRandom secRan = new SecureRandom();
        byte[] bytes = new byte[16];
        secRan.nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }

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
