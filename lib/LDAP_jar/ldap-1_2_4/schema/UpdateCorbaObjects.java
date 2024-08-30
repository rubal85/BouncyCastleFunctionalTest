/*
 * Copyright (c) 1999.  Sun Microsystems. All rights reserved.
 * 
 * Updates a directory containing Java objects that uses 
 * draft-ryan-corba-schema-00.txt to RFC 2714.
 * Before running this program, you should use CreateCorbaSchema to
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
 *     UpdateCorbaObjects [-h|-l|-u] [-n<dn>] [-p<passwd>] [-a<auth>] 
 *      
 * -h		Prints the usage message
 * -l		Lists the entries that will be updated.
 * -u		Update entries containing Corba object
 * -n <dn> 	Use <dn> as the distinguished name for authentication
 * -p <passwd>	Use <passwd> as the password for authentication
 * -a <auth>	Use <auth> as the authentication mechanism. Default is "simple".
 *
 * If neither -u, -l, -h has been specified, the default is "-l".
 *
 * Here are some examples:
 * The following lists the changes that will be made:
 *     #java UpdateCorbaObjects
 *
 * The following updates the entries that contain CORBA objects,
 * logging in as "cn=directory manager" with the password "secret".
 *     #java UpdateCorbaObjects -u "-ncn=directory manager" -psecret
 *
 * @author Rosanna Lee
 */

import javax.naming.*;
import javax.naming.directory.*;
import java.util.Hashtable;

public class UpdateCorbaObjects extends UpdateJavaObjects {
    public static void main(String[] args) {
	new UpdateCorbaObjects().run(args, "UpdateCorbaObjects", "CORBA");
    }

    /**
      * Changes to be performed on entries containing CORBA objects:
      * For entries containing the corbaObject object class:
      * o Add the corbaObjectReference object class.
      */
    protected void updateObjects(DirContext ctx, boolean listOnly)
	throws NamingException {

	SearchControls ctls = new SearchControls();
	ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	ctls.setReturningAttributes(new String[] {"objectclass"});

	// Update serialized objects
	NamingEnumeration enum = ctx.search("", "(objectclass=corbaobject)", ctls);

	while (enum.hasMore()) {
	    SearchResult sr = (SearchResult)enum.next();
	    System.out.println(sr.getName());
	    ModificationItem mods[] = 
		getModifications(sr.getAttributes(), null, null, // no attr changes
		    "corbaObjectReference");

	    if (listOnly) {
		printMods(mods);
	    } else {
		ctx.modifyAttributes(sr.getName(), mods);
	    }
	}
    }
}
