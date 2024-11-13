package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
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
import java.security.NoSuchAlgorithmException;

public class Servant extends UnicastRemoteObject implements Service {

    private static final Logger logger = Logger.getLogger(Servant.class.getName());
    private Map<String, String> userPasswordMap;
    private Map<String, Long> activeSessions; // Stores sessions with expiration time
    private static final long SESSION_DURATION = 300000; // 5 minutes in milliseconds

    private static final String PASSWORD_FILE = new File("authentication/src/main/java/server/passwords.csv").getAbsolutePath();

    public Servant() throws RemoteException {
        super();
        userPasswordMap = new HashMap<>();
        activeSessions = new HashMap<>();
        
        // Sample user setup (In real applications, this should be securely loaded)
        userPasswordMap.put("AliceAdmin", "adminpass");
        userPasswordMap.put("BobJanitor", "servicepass");
        userPasswordMap.put("CeciliaPowerUser", "powerpass");

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
                    return user;
                }
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Simple authentication check
    private boolean authenticate(String username, String password) {
        String[] userInfo = getUserInfo(username);

        if (userInfo == null) {
            return false;
        }

        String userHash = hash_Argon2(userInfo[0], userInfo[2]);
        String passwordHash = hash_Argon2(password, userHash);

        if (passwordHash.equals(userInfo[1])) {
            return true;
        }
        return false;
    }

    // Session creation
    public String login(String username, String password) throws RemoteException {
        if (authenticate(username, password)) {
            long expirationTime = System.currentTimeMillis() + SESSION_DURATION;
            activeSessions.put(username, expirationTime);
            logger.info("User " + username + " logged in with session valid until: " + expirationTime);
            return "Login successful. Session active.";
        }
        return "Login failed. Invalid credentials.";
    }

    // Session validation check
    private boolean isSessionValid(String username) {
        if (activeSessions.containsKey(username)) {
            long currentTime = System.currentTimeMillis();
            long expirationTime = activeSessions.get(username);
            if (currentTime < expirationTime) {
                // Extend session validity upon valid use
                activeSessions.put(username, currentTime + SESSION_DURATION);
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
            logger.warning("Unauthorized access attempt by user: " + username);
            throw new RemoteException("Session is not valid. Please log in again.");
        }
        return true;
    }

    @Override
    public String print(String username, String fileName, String printer) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Print command received. User: " + username + ", File: " + fileName + ", Printer: " + printer);
            return "Printing " + fileName + " on " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String queue(String username, String printer) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Queue command received. User: " + username + ", Printer: " + printer);
            return "Queue for printer " + printer + ": [Sample Job List]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String topQueue(String username, String printer, int job) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Top queue command received. User: " + username + ", Printer: " + printer + ", Job: " + job);
            return "Moved job " + job + " to the top of the queue for printer " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String start(String username) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Start command received. User: " + username);
            return "Print server started.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String stop(String username) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Stop command received. User: " + username);
            return "Print server stopped.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String restart(String username) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Restart command received. User: " + username);
            return "Print server restarted.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String status(String username, String printer) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Status command received. User: " + username + ", Printer: " + printer);
            return "Status of printer " + printer + ": [Sample status]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String readConfig(String username, String parameter) throws RemoteException {
        if (validateSession(username)) {
            logger.info("Read configuration command received. User: " + username + ", Parameter: " + parameter);
            return "Configuration for " + parameter + ": [Sample value]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String setConfig(String username, String parameter, String value) throws RemoteException {
        if (validateSession(username)) {
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
