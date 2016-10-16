/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Originally from:
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 *
 * Based on modified version from:
 * https://github.com/escline/InstallCert
 *
 * Use:
 * java InstallCert hostname
 *
 * Example:
 *% java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.text.SimpleDateFormat;

/**
 * Class used to add the server's certificate to the KeyStore
 * with your trusted certificates (jssecacerts file).
 */
public class InstallCert {

    private static final BufferedReader INPUT_READER = new BufferedReader(new InputStreamReader(System.in));
    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    public static void main(String[] args) throws Exception {
        String host;
        int port;
        char[] passphrase;
        if ((args.length == 1) || (args.length == 2)) {
            String[] arg0 = args[0].split(":");
            host = arg0[0];
            port = (arg0.length == 1) ? 443 : Integer.parseInt(arg0[1]);

            String arg1 = (args.length == 1) ? "changeit" : args[1];
            passphrase = arg1.toCharArray();
        } else {
            System.out.println("Usage: java InstallCert <host>[:port] [passphrase]");
            return;
        }

        File jssecacerts = getOrCreateJssecacerts();

        KeyStore ks = loadKeyStore(jssecacerts, passphrase);
        
        SavingTrustManager tm = buildTrustManager(ks);

        X509Certificate[] chain = getCertificateChain(host, port, tm);
        if (chain == null) {
            System.out.println();
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        printCertificateChain(chain);

        int i = selectCertificateIndex(chain.length);
        if (i < 0) {
            System.out.println();
            System.out.println("jssecacerts not changed");
            return;
        }

        X509Certificate cert = chain[i];
        String alias = host + "-" + (i + 1);
        ks.setCertificateEntry(alias, cert);

        File jssecacertsBackup = backupFile(jssecacerts);

        saveKeyStore(ks, passphrase, jssecacerts);

        System.out.println();
        System.out.println(cert);
        System.out.println();
        System.out.println("Current jssecacerts backed up at: " + jssecacertsBackup.getAbsolutePath());
        System.out.println("Added certificate using alias '"+ alias + "' " +
                "to jssecacerts: " + jssecacerts.getAbsolutePath());
    }

    private static SavingTrustManager buildTrustManager(KeyStore ks) throws Exception {
       TrustManagerFactory tmf = TrustManagerFactory.getInstance(
               TrustManagerFactory.getDefaultAlgorithm());
       tmf.init(ks);
       X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];

       return new SavingTrustManager(defaultTrustManager);
    }

    private static File getOrCreateJssecacerts() throws Exception {
        char SEP = File.separatorChar;
        String dirPath = System.getProperty("java.home") + SEP
                + "lib" + SEP + "security";
        File dir = new File(dirPath);

        File jssecacerts = new File(dir, "jssecacerts");

        if (!jssecacerts.isFile()) {
            File cacerts = new File(dir, "cacerts");

            if (cacerts.isFile()) {
                System.out.println("jssecacerts not found. " +
                        "Copying cacerts to jssecacerts: " + jssecacerts.getAbsolutePath());
                copy(cacerts, jssecacerts);
            } else {
                throw new Exception("Neither jssecacerts nor cacerts found in: " + dirPath);
            }
        }

        return jssecacerts;
    }

    private static KeyStore loadKeyStore(File file, char[] passphrase) throws Exception {
        System.out.println("Loading KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passphrase);
        in.close();

        return ks;
    }

    private static X509Certificate[] getCertificateChain(
            String host, int port, InstallCert.SavingTrustManager tm)
            throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();

            System.out.println();
            System.out.println("No errors, certificate is already trusted. " +
                    "Press enter to continue or Ctrl+C to quit.");
            String line = INPUT_READER.readLine().trim();
        } catch (SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        return tm.chain;
    }

    private static void printCertificateChain(X509Certificate[] chain) throws Exception {
        System.out.println();
        System.out.println("Server sent " + chain.length + " certificate(s):");
        System.out.println();

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];

            System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + toHexString(md5.digest()));
            System.out.println();
        }
    }

    private static int selectCertificateIndex(int chainSize) throws Exception {
        System.out.println("Enter the certificate to add to the trusted keystore or press Ctrl+C to quit: [1]");
        String line = INPUT_READER.readLine().trim();

        int i = -1;
        try {
            i = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;

            if (i < 0 || i >= chainSize) {
                System.out.println("Certfificate number not valid");
                i = -1;
            }
        } catch (NumberFormatException e) {
            System.out.println("Number format not valid");
        }

        return i;
    }

    private static File backupFile(File file) throws Exception {
        String timestamp = new SimpleDateFormat("_yyyy-MM-dd_HH-mm-ss").format(new Date());
        File backup = new File(file.getAbsolutePath() + timestamp + ".bak");

        copy(file, backup);

        return backup;
    }

    private static void saveKeyStore(KeyStore ks, char[] passphrase, File file) throws Exception {
        OutputStream out = new FileOutputStream(file.getAbsolutePath());
        ks.store(out, passphrase);
        out.close();
    }

    private static void copy(File from, File to) throws Exception {
        InputStream inStream = new FileInputStream(from);
        OutputStream outStream = new FileOutputStream(to);

        byte[] buffer = new byte[1024];
        int length;
        while ((length = inStream.read(buffer)) > 0){
            outStream.write(buffer, 0, length);
        }

        inStream.close();
        outStream.close();
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);

        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }

        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            /**
             * This change has been done due to the following resolution advised for Java 1.7+
             * http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
             **/
            return new X509Certificate[0];
            //throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
