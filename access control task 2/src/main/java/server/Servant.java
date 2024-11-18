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

public class Servant extends UnicastRemoteObject implements Service {
    private Map<String, String> userPasswordMap;
    private Map<String, Role> userRoleMap;
    private Map<Role, List<String>> rolePermissions;
    private Map<String, Long> activeSessions; // Stores sessions with expiration time
    private static final long SESSION_DURATION = 300000; // 5 minutes in milliseconds

    private static final String PASSWORD_FILE = new File("authentication/src/main/java/server/passwords.csv").getAbsolutePath();
    private static final String EVENTLOG_FILE = new File("authentication/src/main/java/server/eventlogs").getAbsolutePath();

    private static final Logger logger = Logger.getLogger(Servant.class.getName());

    // Define roles
    private enum Role {
        ADMIN, TECHNICIAN, POWER_USER, ORDINARY_USER
    }

    public Servant() throws RemoteException {
        super();
        configureLogger();
        userPasswordMap = new HashMap<>();
        userRoleMap = new HashMap<>();
        rolePermissions = new HashMap<>();
        activeSessions = new HashMap<>();

        initializeUsers();
        initializeRolePermissions();
    }

    private void initializeUsers() {
        // Initialize users with roles and passwords
        userPasswordMap.put("AliceAdmin", "adminpass");
        userRoleMap.put("AliceAdmin", Role.ADMIN);

        userPasswordMap.put("BobJanitor", "servicepass");
        userRoleMap.put("BobJanitor", Role.TECHNICIAN);

        userPasswordMap.put("CeciliaPowerUser", "powerpass");
        userRoleMap.put("CeciliaPowerUser", Role.POWER_USER);

        userPasswordMap.put("David", "davidpass");
        userRoleMap.put("David", Role.ORDINARY_USER);

        userPasswordMap.put("Erica", "ericapass");
        userRoleMap.put("Erica", Role.ORDINARY_USER);

        userPasswordMap.put("Fred", "fredpass");
        userRoleMap.put("Fred", Role.ORDINARY_USER);

        userPasswordMap.put("George", "georgepass");
        userRoleMap.put("George", Role.ORDINARY_USER);
    }

    private void initializeRolePermissions() {
        // Define permissions for each role
        rolePermissions.put(Role.ADMIN, List.of("print", "queue", "topQueue", "start", "stop", "restart", "status", "readConfig", "setConfig"));
        rolePermissions.put(Role.TECHNICIAN, List.of("start", "stop", "restart", "status", "readConfig", "setConfig"));
        rolePermissions.put(Role.POWER_USER, List.of("print", "queue", "topQueue", "restart"));
        rolePermissions.put(Role.ORDINARY_USER, List.of("print", "queue"));
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

    // Simple authentication check
    private boolean authenticate(String username, String password) {
        String[] userInfo = getUserInfo(username);

        if (userInfo == null) {
            return false;
        }

        String userHash = hash_Argon2(userInfo[0], userInfo[2]);
        String passwordHash = hash_Argon2(password, userHash);

        return passwordHash.equals(userInfo[1]);
    }

    private boolean hasPermission(String username, String action) {
        Role userRole = userRoleMap.get(username);
        if (userRole != null) {
            return rolePermissions.get(userRole).contains(action);
        }
        return false;
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
