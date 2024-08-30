/*
 * Copyright (c) 1999.  Sun Microsystems. All rights reserved.
 * 
 * Updates a directory containing Java objects that uses 
 * draft-ryan-java-schema-00.txt to RFC 2713.
 * Before running this program, you should use CreateJavaSchema to
 * update the schema and then use the directory server's administration
 * tool to verify that the schema changes have been properly applied. 
 * If the schema has not been properly updated, use the administration tool
 * to correct it before updating the entries using this program.
 *
 * You should first turn off schema-checking at the directory server 
 * before running this program.
 *
 * usage:
 * java [-Djava.naming.provider.url=<provider_url>] \
 *     UpdateJavaObjects [-h|-l|-u] [-n<dn>] [-p<passwd>] [-a<auth>] 
 *      
 * -h		Prints the usage message
 * -l		Lists the entries that will be updated.
 * -u		Update entries containing Java object
 * -n <dn> 	Use <dn> as the distinguished name for authentication
 * -p <passwd>	Use <passwd> as the password for authentication
 * -a <auth>	Use <auth> as the authentication mechanism. Default is "simple".
 *
 * If neither -u, -l, -h has been specified, the default is "-l".
 *
 * Here are some examples:
 * The following lists the changes that will be made:
 *     #java UpdateJavaObjects
 *
 * The following updates the entries that contain Java objects,
 * logging in as "cn=directory manager" with the password "secret".
 *     #java UpdateJavaObjects -u "-ncn=directory manager" -psecret
 *
 * @author Rosanna Lee
 */

import javax.naming.*;
import javax.naming.directory.*;
import java.util.Hashtable;

public class UpdateJavaObjects {
    static private final int LIST = 0;
    static private final int UPDATE_OBJECTS = 2;

    static private String dn, passwd, auth;
    static private String cmd, objType;

    public static void main(String[] args) {
	new UpdateJavaObjects().run(args, "UpdateJavaObjects", "Java");
    }

    protected void run(String[] args, String cmd, String objType) {
	this.cmd = cmd;
	this.objType = objType;

	int command = processCommandLine(args);
	try {
	    DirContext ctx = signOn();
	    switch (command) {
	    case LIST:
		updateObjects(ctx, true);
		break;
	    case UPDATE_OBJECTS:
		updateObjects(ctx, false);
		break;
	    }
	} catch (NamingException e) {
	    e.printStackTrace();
	}
    }

    /**
     * Signs on to directory server using parameters supplied to program.
     * @return The initial context to the server.
     */
    static private DirContext signOn() throws NamingException {
	if (dn != null && auth == null) {
	    auth = "simple"; 	// use simple for Netscape
	}

	Hashtable env = new Hashtable();
	env.put(Context.INITIAL_CONTEXT_FACTORY, 
	    "com.sun.jndi.ldap.LdapCtxFactory");

	if (auth != null) {
	    env.put(Context.SECURITY_AUTHENTICATION, auth);
	    env.put(Context.SECURITY_PRINCIPAL, dn);
	    env.put(Context.SECURITY_CREDENTIALS, passwd);
	}

	return new InitialDirContext(env);
    }

    /**
      * Changes to be performed on entries containing Java objects:
      * For entries containing the javaSerializedObject attribute:
      * o Save attribute value with javaSerializedData attribute
      * o Delete javaSerializedObject attribute
      *
      * For entries containing the javaFactoryLocation attribute:
      * o Save attribute value with javaCodebase attribute
      * o Delete javaFactoryLocation attribute
      *
      * For entries containing "javaObject" in  objectclass attribute:
      * o add "javaSerializedObject" as value
      *
      * For entries containing "javaNamingReference" in  objectclass attribute:
      * o add "javaObject" as value
      */
    protected void updateObjects(DirContext ctx, boolean listOnly) 
	throws NamingException {

	SearchControls ctls = new SearchControls();
	ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	ctls.setReturningAttributes(new String[] {
	    "javaSerializedObject", "javaFactoryLocation", "objectclass"});

	// Update serialized objects
	NamingEnumeration enum = ctx.search("", 
	    "(&(javaSerializedObject=*) (objectclass=javaobject))", ctls);

	while (enum.hasMore()) {
	    SearchResult sr = (SearchResult)enum.next();
	    System.out.println(sr.getName());
	    ModificationItem mods[] =
		getModifications(sr.getAttributes(), "javaSerializedObject",
		    "javaSerializedData", "javaSerializedObject");

	    if (listOnly) {
		printMods(mods);
	    } else {
		ctx.modifyAttributes(sr.getName(), mods);
	    }
	}


	// Update references
	enum = ctx.search("", 
	    "(&(objectclass=javanamingreference) (!(objectclass=javaobject)))",
	    ctls);

	while (enum.hasMore()) {
	    SearchResult sr = (SearchResult)enum.next();
	    System.out.println(sr.getName());
	    ModificationItem mods[] = 
		getModifications(sr.getAttributes(), "javaFactoryLocation",
		    "javaCodebase", "javaObject");

	    if (listOnly) {
		printMods(mods);
	    } else {
		ctx.modifyAttributes(sr.getName(), mods);
	    }
	}
    }

    /**
     * Create a list of modifications.
     */
    protected static ModificationItem[] getModifications(Attributes attrs,
	String oldAttrID, String newAttrID, String newOC) throws NamingException {
	    Attribute oldAttr = (oldAttrID == null? null : attrs.get(oldAttrID));
	    ModificationItem[] mods;
	    int count = 0;

	    if (oldAttr != null) {
		Attribute newAttr = new BasicAttribute(newAttrID);
		newAttr.add(oldAttr.get());
		mods = new ModificationItem[3];
		mods[count++] = new ModificationItem(
		    DirContext.REMOVE_ATTRIBUTE, oldAttr);
		mods[count++] = new ModificationItem(
		    DirContext.ADD_ATTRIBUTE, newAttr);
	    } else {
		mods = new ModificationItem[1];
	    }

	    mods[count++] = new ModificationItem(
		DirContext.ADD_ATTRIBUTE, new BasicAttribute("objectclass", newOC));

	    return mods;
    }

    protected static void printMods(ModificationItem[] mods) {
	for (int i = 0; i < mods.length; i++) {
	    System.out.println("\t" + mods[i]);
	}
    }


    static private int processCommandLine(String[] args) {
	String option;
	boolean objects = false;
	boolean list = false;

	for (int i = 0; i < args.length; i++) {
	    option = args[i];
	    if (option.startsWith("-h")) {
		printUsage(null);
	    }
	    if (option.startsWith("-l")) {
		list = true;
	    } else if (option.startsWith("-u")) {
		objects = true;
	    } else if (option.startsWith("-a")) {
		auth = option.substring(2);
	    } else if (option.startsWith("-n")) {
		dn = option.substring(2);
	    } else if (option.startsWith("-p")) {
		passwd = option.substring(2);
	    } else {
		// invalid option
		printUsage("Invalid option");
	    }
	}

	if (list) {
	    if (objects) {
		printUsage("Too many options");
	    }
	} else if (objects) {
	    return UPDATE_OBJECTS;
	}
	return LIST;
    }

    static private void printUsage(String msg) {
	if (msg != null) {
	    System.out.println(msg);
	}

System.out.print("Usage: ");
System.out.println("java [-Djava.naming.provider.url=<provider_url>] \\");
System.out.println("  " + cmd + " [-h|-l|-u] [-n<dn>] [-p<passwd>] [-a<auth>]");
System.out.println();
System.out.println("  -h\t\tPrints the usage message");
System.out.println("  -l\t\tPrints the entries that will be updated");
System.out.println("  -u\t\tUpdate entries containing " + objType + " object");
System.out.println("  -n <dn>\tUse <dn> as the distinguished name for authentication");
System.out.println("  -p <passwd>\tUse <passwd> as the password for authentication");
System.out.println("  -a <auth>\tUse <auth> as the authentication mechanism");
System.out.println("\t\t Default is 'simple' if dn specified; otherwise 'none'");
	System.exit(-1);
    }
}
