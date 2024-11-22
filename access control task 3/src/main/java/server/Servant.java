package server;

import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.SimpleFormatter;

import javax.swing.filechooser.FileNameExtensionFilter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.*;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.logging.Logger;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.SecureRandom;

public class Servant extends UnicastRemoteObject implements Service {
    //private Map<String, String> userPasswordMap;
    private Map<String, String> EmployeeMap;
    private Map<String, Long> activeSessions; // Stores sessions with expiration time
    private Map<String, Map<String, Boolean>> RoleMap;
    private static final long SESSION_DURATION = 300000; // 5 minutes in milliseconds
    private static final String MAIN_FOLDER = "access control task 3\\src\\main\\java\\server\\";
    private static final String EMPLOYEES_FILE = new File(MAIN_FOLDER + "employees.csv").getAbsolutePath();
    private static final String ROLEPERM_FILE = new File(MAIN_FOLDER + "roles_perms.csv").getAbsolutePath();
    private static final String PASSWORD_FILE = new File(MAIN_FOLDER + "passwords.csv").getAbsolutePath();
    private static final String EVENTLOG_FILE = new File(MAIN_FOLDER + "eventlogs").getAbsolutePath();

    public Servant() throws RemoteException {
        super();

        configureLogger();
        //userPasswordMap = new HashMap<>();
        EmployeeMap = new HashMap<>();
        activeSessions = new HashMap<>();
        RoleMap = new HashMap<>();
        
        //Array to store the filepaths to be used in folowing for loop
        String[] FilepathArr = {EMPLOYEES_FILE, ROLEPERM_FILE, PASSWORD_FILE, EVENTLOG_FILE};

        //Iterates over the array above to check whether each file actually exists
        //And that the files aren't empty (event logs file is allowed to be empty)
        for (String Filepath : FilepathArr) 
        {
            int index = Filepath.lastIndexOf("\\");
            String FileName = Filepath.substring(index + 1);
            try
            {
                if (!fileChecker(Filepath))
                {
                    throw new FileNotFoundException("File " + FileName + " does not exist or is empty");
                }
            }

            catch(FileNotFoundException FNFE)
            {
                System.out.println(FNFE.getMessage());
                if(!Filepath.contains(EVENTLOG_FILE))
                {
                    logger.warning(FNFE.getMessage());
                }
                System.exit(404);
            }
        }
        
        try
        {
            mapUsers();
            mapRoles();
        }
        catch(FileNotFoundException FNFE)
        {
            FNFE.printStackTrace();
        }
        catch(IOException IOE)
        {
            IOE.printStackTrace();
        }
        /*
            // Now consider the situation where Bob leaves the company and George takes over the responsibilities as service technician. At the same time, two new employees are hired: Henry, who should be granted the privileges of an ordinary user, and Ida who is a power user and should be given the same privileges as Cecilia.
            userPasswordMap.put("AliceAdmin", "adminpass"); // Admin can do everything
            userPasswordMap.put("George", "servicepass"); 
            userPasswordMap.put("Ida", "IDApowerpass"); // Ida
            userPasswordMap.put("CeciliaPowerUser", "powerpass"); // Power user can invoke print, queue, topQueue, start, stop, and restart operations
            //  David, Erica, Fred and George are ordinary users who are only allowed to: print files and display the print queue.
            userPasswordMap.put("David", "davidpass");
            userPasswordMap.put("Erica", "ericapass");
            userPasswordMap.put("Fred", "fredpass");
            userPasswordMap.put("Henry", "henrypass"); // Henry
        */

    }

    private boolean hasPerm(String Username, String Perm)
    {
        if(EmployeeMap.containsKey(Username))
        {
            String Role = EmployeeMap.get(Username);
            if(RoleMap.containsKey(Role))
            {
                return RoleMap.get(Role).get(Perm);
            }
        }
        
        return false;
    }

    private void mapUsers() throws FileNotFoundException, IOException
    {
        String[] FirstLine = {"username", "role"};
        BufferedReader BuffRead = new BufferedReader(new InputStreamReader(new FileInputStream(EMPLOYEES_FILE)));
        while(true) 
        {
            StringTokenizer StrTkn;
            try
            {
                StrTkn = new StringTokenizer((String) BuffRead.readLine(), ",");
            }
            catch(NullPointerException NPE)
            {
                break;
            }

            String[] UserRolePair = new String[2];
            UserRolePair[0] = StrTkn.nextToken();
            UserRolePair[1] = StrTkn.nextToken();

            if(!Arrays.equals(UserRolePair, FirstLine))
            {
                EmployeeMap.put(UserRolePair[0], UserRolePair[1]);
                logger.info("Read user: " + UserRolePair[0] + " with role: " + UserRolePair[1]);
            }
        }
        BuffRead.close();
    }
    //print,queue,topqueue,start,stop,restart,status,readconfig,setconfig
    private void mapRoles() throws FileNotFoundException, IOException
    {
        String[] FirstLine = {"roles","perm"};
        BufferedReader BuffRead = new BufferedReader(new InputStreamReader(new FileInputStream(ROLEPERM_FILE)));
        while(true) 
        {
            StringTokenizer StrTkn;
            try
            {
                StrTkn = new StringTokenizer((String) BuffRead.readLine(), ",");
            }
            catch(NullPointerException NPE)
            {
                break;
            }

            String[] RolePermPair = new String[2];
            RolePermPair[0] = StrTkn.nextToken();
            RolePermPair[1] = StrTkn.nextToken();

            if(!Arrays.equals(RolePermPair, FirstLine))
            {
                logger.info("Read role: " + RolePermPair[0] + " with perms: ");
                RoleMap.put(RolePermPair[0], permMapper(RolePermPair[1].toCharArray()));
                //UserRoleMap.put(RolePermPair[0], RolePermPair[1]);
            }
        }
        BuffRead.close();
    }

    private Map<String, Boolean> permMapper(char[] permCharArr)
    {
        Map<String, Boolean> PermStatusMap = new HashMap<>();
        String[] Perms = 
        {
            "print", 
            "queue", 
            "topqueue", 
            "start", 
            "stop", 
            "restart", 
            "status", 
            "readconfig", 
            "setconfig"
        };
        //boolean[] permBoolArr = new boolean[9];

        for(int index = 0; index < 9; index++)
        {
            //permBoolArr[index] = permCharArr[index] == '1';
            PermStatusMap.put(Perms[index], (permCharArr[index] == '1'));
            logger.info('\t' + Perms[index] + "\t:\t" + (permCharArr[index] == '1'));
        }

        return PermStatusMap;
    }

    private boolean fileChecker(String Filepath)
    {
        File FileObj = new File(Filepath);
        //int index = Filepath.lastIndexOf("\\");
        //String FileName = Filepath.substring(index + 1);
        if (!Filepath.contains(EVENTLOG_FILE))
        {
            return FileObj.exists() && FileObj.length() > 0;
        }

        return FileObj.exists();
    }

    private static final Logger logger = Logger.getLogger(Servant.class.getName());

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
        logger.warning("Login failed for user: " + username);
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
            logger.warning("Unauthorized access attempt by user: " + username);
            throw new RemoteException("Session is not valid. Please log in again.");
        }
        return true;
    }

    @Override
    public String print(String username, String fileName, String printer) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "print")) {
            logger.info("Print command received. User: " + username + ", File: " + fileName + ", Printer: " + printer);
            return "Printing " + fileName + " on " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String queue(String username, String printer) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "queue")) {
            logger.info("Queue command received. User: " + username + ", Printer: " + printer);
            return "Queue for printer " + printer + ": [Sample Job List]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String topQueue(String username, String printer, int job) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "topqueue")) {
            logger.info("Top queue command received. User: " + username + ", Printer: " + printer + ", Job: " + job);
            return "Moved job " + job + " to the top of the queue for printer " + printer;
        }
        return "Unauthorized access.";
    }

    @Override
    public String start(String username) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "start")) {
            logger.info("Start command received. User: " + username);
            return "Print server started.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String stop(String username) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "stop")) {
            logger.info("Stop command received. User: " + username);
            return "Print server stopped.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String restart(String username) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "restart")) {
            logger.info("Restart command received. User: " + username);
            return "Print server restarted.";
        }
        return "Unauthorized access.";
    }

    @Override
    public String status(String username, String printer) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "status")) {
            logger.info("Status command received. User: " + username + ", Printer: " + printer);
            return "Status of printer " + printer + ": [Sample status]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String readConfig(String username, String parameter) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "readconfig")) {
            logger.info("Read configuration command received. User: " + username + ", Parameter: " + parameter);
            return "Configuration for " + parameter + ": [Sample value]";
        }
        return "Unauthorized access.";
    }

    @Override
    public String setConfig(String username, String parameter, String value) throws RemoteException {
        if (validateSession(username) && hasPerm(username, "setconfig")) {
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