package works.phoenixdesign;


// http://localhost:8080 redirects 307 to https://localhost:8443
// https://localhost:8443 serves up dir listing with self signed cert (Security warning)
// http://localhost:8081 (200) dumps a dir listing
// https://localhost:8444 dumps dir listing if you ignore sec warning

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.powermock.reflect.Whitebox;

import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

import static org.junit.Assert.*;

public class Http2ServerPortTest {
    private static final int HTTP_TEMPORARY_REDIRECT = 307;
    private static final String CLIENT_TRUSTSTORE_ALIAS = "server";
    static SSLContext ctx;

    @BeforeClass
    public static void setUpClass() throws Exception {
        // invoke main to launch servers
        Method method = Whitebox.getMethod(Http2Server.class, "main", String[].class);
        String[] params = null;
        method.invoke( null, (Object)params);

        // Create HttpClient SSL ctx (borrowing Http2Server is technically lazy and cheating I know)
        Method loadKeyStore = Whitebox.getMethod(Http2Server.class, "loadKeyStore", String.class);
        Method createSslContext = Whitebox.getMethod(Http2Server.class, "createSSLContext", KeyStore.class, KeyStore.class);
        KeyStore keystore = (KeyStore)loadKeyStore.invoke(null, "/client.keystore");
        KeyStore truststore = (KeyStore)loadKeyStore.invoke(null, "/client.truststore");
        printCert(truststore, "server");
        ctx = (SSLContext)createSslContext.invoke(null, keystore, truststore);
    }

    @Test
    public void serverSupportsHTTP2() throws IOException, InterruptedException {
        HttpResponse<Void> rsp = invokeGetRequest("http://localhost:8081");
        assertEquals(200, rsp.statusCode());
        assertSame(rsp.version(), HttpClient.Version.HTTP_2);
    }

    @Test
    public void serverReturns404_WhenBadGetRequestUrl() throws IOException, InterruptedException {
        HttpResponse<Void> rsp = invokeGetRequest("http://localhost:8081/undefined/url");
        assertEquals(404, rsp.statusCode());
    }

    @Test
    public void serverRedirectsToSsl_WhenGetRequestToNonSslPort() throws IOException, InterruptedException {
        HttpResponse<Void> rsp = invokeGetRequest("http://localhost:8080");
        assertEquals(rsp.statusCode(), HTTP_TEMPORARY_REDIRECT);

        assertTrue(rsp.headers().firstValue("location").isPresent());
        assertEquals("https://localhost:8443/", rsp.headers().firstValue("location").get());
    }

    @Ignore    // TODO: Figure out javax.net.http.HttpClient related truststore connection issue
    @Test
    public void serverReturns200_WhenGetRequestOnSslPort() throws IOException, InterruptedException {
        HttpResponse<Void> rsp = invokeGetRequest("http://localhost:8444");
        assertEquals(200, rsp.statusCode());
    }

    @Test
    public void playingaround() throws IOException, InterruptedException {
        System.out.println("System.getProperty(javax.net.ssl.trustStore): " + System.getProperty("javax.net.ssl.trustStore"));
    }


    protected HttpResponse<Void> invokeGetRequest(String url) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(ctx)
                .sslParameters(ctx.getDefaultSSLParameters())
                .build();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        HttpResponse<Void> rsp = client.send(req, HttpResponse.BodyHandlers.discarding());
        return rsp;
    }

    private static void printCert(KeyStore store, String alias) {
        try {
            Certificate cert = store.getCertificate(alias);
            assertNotNull(cert);
            System.out.println(cert.toString());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }
}
