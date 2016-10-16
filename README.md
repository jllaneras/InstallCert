# InstallCert

Original program written by Andreas Sterbenz, and [posted in Oct, 2006](https://blogs.oracle.com/gc/entry/unable_to_find_valid_certification).

The link to Andreas' blog post no longer works but the source was linked [here](http://nodsw.com/blog/leeland/2006/12/06-no-more-unable-find-valid-certification-path-requested-target).

This is a fork from the version maintained by [Eric Cline](https://github.com/escline/InstallCert/).

## Description

InstallCert allows you to quickly add the SSL certificate from a server into 
the truststore (jre/lib/security/jssecacerts file) of the JVM you are running. 

It is particularly useful when developing Java applications that need to connect 
to test servers that use untrusted self-signed SSL certificates and you get the
typical exception below:

```
javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

## How does it do its magic?

1. It starts an SSL handshake with the server.
2. Retrieves the certificate chain the server identifies itself with.
3. Loads the JVM's truststore (jre/lib/security/jssecacerts). If the jssecacerts 
file does not exist yet in the JVM, it creates it by copying jre/lib/security/cacerts.
4. Creates a backup of the current jssecacerts truststore.
5. Adds the chosen certificate from the chain returned by the server in the 
jssecacerts truststore.

## How to use it

### Compile it first

```
javac InstallCert.java
```

### Usage

```
java InstallCert host:[port] [passphrase]
```

Note you might need to execute InstallCert as root because it will try to 
update the truststore in the installation directory of the JVM.

#### Arguments

 - `host`: domain name where the SSL certificate will be retrieved from. 
 - `port`: port where the server is listening to. The default value  is 443, the
 default HTTPS port.
 - `passphrase`: password of the jssecacerts truststore (or the cacerts one if 
 jssecacerts has not been created yet). The default value is `changeit`.

## Examples

```
java InstallCert untrusted-root.badssl.com

java InstallCert untrusted-root.badssl.com:1234

java InstallCert untrusted-root.badssl.com my_jssecacerts_password
```