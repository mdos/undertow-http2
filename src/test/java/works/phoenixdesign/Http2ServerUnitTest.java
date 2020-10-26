package works.phoenixdesign;

import net.bytebuddy.implementation.bytecode.Throw;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import javax.net.ssl.SSLContext;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.spec.RSAOtherPrimeInfo;

import static org.junit.Assert.*;

public class Http2ServerUnitTest {

    public static final int CLIENT_KEYSTORE_CERT_HASH = -1196462111;

    // Positive test: loadKeyStore() from resource
    @Test
    public void loadKeyStoreReturnsKeyStore_WhenResourceLoads()
            throws IllegalAccessException, InvocationTargetException, KeyStoreException
    {
        // client.keystore contains a single cert at "client" alias
        Method method = Whitebox.getMethod(Http2Server.class, "loadKeyStore", String.class);
        KeyStore keystore = (KeyStore)method.invoke(null, "/client.keystore");
        Certificate cert = keystore.getCertificate("client");
        System.out.println("cert type: " + cert.getType() + " hash: " + cert.hashCode());

        assertTrue(keystore!=null);
        assertTrue(keystore.size() == 1);
        assertTrue(cert.getType() == "X.509");
        assertTrue(cert.hashCode() == CLIENT_KEYSTORE_CERT_HASH);
    }


    // Negative test: Http2Server.loadKeyStore() throws RuntimeException
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void loadKeyStoreThrowsRuntimeException_WhenLoadFails()
            throws Throwable
    {
        // set up the env such that the keystore name will not be found
        exceptionRule.expect(RuntimeException.class);
        exceptionRule.expectMessage("Could not load keystore");

        Method method = Whitebox.getMethod(Http2Server.class, "loadKeyStore", String.class);
        try {
            method.invoke(null, "bogusName");
        } catch (InvocationTargetException wrapped_exception) {
            throw wrapped_exception.getCause();
        }
        fail("Failed to throw RuntimeException");
    }

    // Positive test: createSSLContext()
    @Test
    public void createSslContextSucceeds_WhenValidKeystoresAreUsed()
            throws Exception
    {
        // Create HttpClient SSL ctx (borrowing Http2Server is technically lazy and cheating)
        Method loadKeyStore = Whitebox.getMethod(Http2Server.class, "loadKeyStore", String.class);
        Method createSslContext = Whitebox.getMethod(Http2Server.class, "createSSLContext", KeyStore.class, KeyStore.class);
        KeyStore keystore = (KeyStore)loadKeyStore.invoke(null, "/client.keystore");
        KeyStore truststore = (KeyStore)loadKeyStore.invoke(null, "/client.truststore");
        SSLContext ctx = Whitebox.invokeMethod(Http2Server.class, "createSSLContext", keystore, truststore);

        assertTrue(ctx!=null);
        assertTrue(ctx.getProtocol().equals("TLS"));
    }

    // Negative test: createSSLContext()
    @Test
    public void createSslContextDoesntThrow_WhenNullKeystoresAreUsed()
            throws IllegalAccessException, InvocationTargetException
    {
        Method createSslContext = Whitebox.getMethod(Http2Server.class, "createSSLContext", KeyStore.class, KeyStore.class);
        SSLContext ctx = (SSLContext)createSslContext.invoke(null, null, null);
        assertTrue(ctx!=null);
    }
}
