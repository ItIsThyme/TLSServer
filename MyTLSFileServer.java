import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.naming.ldap.*;
import javax.net.*;
import java.io.*;

class MyTLSFileServer{



    public static void main(String[] args){
	ServerSocketFactory ssf = getSSF();

	if (ssf == null){
	    System.err.println("Couldn't produce a Socket Factory");
	    return;
	}
	
	SSLServerSocket ss =
	    (SSLServerSocket) ssf.createServerSocket(40202);
	String EnabledProtocols[] =
	    {"TLSv1.2", "TLSv1.3"};
	ss.setEnabledProtocols(EnabledProtocols);
	SSLSocket s = (SSLSocket)ss.accept();

	
    }



    
    private static ServerSocketFactory getSSF(){
	/*
	 * Get an SSL Context that speaks some version
	 * of TLS, a KeyManager that can hold certs in * X.509 format, and a JavaKeyStore (JKS)
	 * instance
	 */
	try{
	    SSLContext ctx =
		SSLContext.getInstance("TLS");
	    KeyManagerFactory kmf =
		KeyManagerFactory.getInstance("SunX509");
	    KeyStore ks =
		KeyStore.getInstance("JKS");
	    
	    //Use the java Console class to securely retrieve the password for the keystore and load it
	    try{
		Console cons;
		char[] passwd;
		if ((cons = System.console()) != null &&
		    (passwd = cons.readPassword("[%s]", "Password:")) != null) {
		    
		//Load keystore
		    try{
			ks.load(new FileInputStream("server.jks"),
				passwd);
		    }catch(IOException e){
		    System.err.println("could not read keystore: " + e);
		    return null;
		    }
		    kmf.init(ks, passwd);
		    //Clear password
		java.util.Arrays.fill(passwd, ' ');
		}
	    }catch(Exception e){
		//The console somehow failed
		System.err.println("could not get password: " + e);
		return null;
	    }
	    //here we should have an initialised keyfactory  and zeroed the password array

	    //initialise the ssl context using the keys from the keyfactory
	    ctx.init(kmf.getKeyManagers(), null, null);
	    
	    //get the ServerSocket and return it
	    ServerSocketFactory ssf =
		ctx.getServerSocketFactory();
	    return ssf;	
	}catch (Exception e){
	    System.err.println("Error with keygen algorithms: " + e);
	    return null;
	}
	
    }
}
