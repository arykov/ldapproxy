package com.ryaltech.utils.ldap;

import com.beust.jcommander.Parameter;

public class ProxyParameters {

	@Parameter(names = "-la", description = "Address to listen on. Localhost by default")
	String localAddress = "localhost";
	@Parameter(names = "-lp", description = "Port to listen on. ", required=true)
	Integer localPort;
	@Parameter(names = "-ra", description = "Address to listen on. Localhost by default", required=true)
	String remoteAddress;
	@Parameter(names = "-rp", description = "Address to listen on. Localhost by default", required=true)
	Integer remotePort;
	@Parameter(names = "-dn", description = "DN of user to use for remote ldap", required=true)
	String proxyDN;
	@Parameter(names = "-pass", description = "Password of user to use for remote ldap", required=true, password=true)
	String proxyPassword;
	@Parameter(names={"-v", "-verbose"}, description="To run in verbose mode")
	boolean verbose = false;
	@Parameter(names=("-jks"), description="Java keystore file")
	String jksFile;
	@Parameter(names=("-jksPass"), description="Java keystore password")
	String jksPass;
	@Parameter(names={"-ka","-keyAlias"}, description="Key alias")
	String keyAlias;

	@Parameter(names={"-h", "-help", "-?"}, description="Java keystore password", help=true)
	boolean help;


}
