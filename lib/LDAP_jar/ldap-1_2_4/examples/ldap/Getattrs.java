/*
 *
 * @(#)Getattrs.java	1.2 99/07/26 
 *
 * Copyright 1997, 1998, 1999 Sun Microsystems, Inc. All Rights
 * Reserved.
 *
 * Sun grants you ("Licensee") a non-exclusive, royalty free,
 * license to use, modify and redistribute this software in source and
 * binary code form, provided that i) this copyright notice and license
 * appear on all copies of the software; and ii) Licensee does not utilize
 * the software in a manner which is disparaging to Sun.
 *
 * This software is provided "AS IS," without a warranty of any
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY
 * LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THE SOFTWARE
 * OR ITS DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR
 * ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL,
 * CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND
 * REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT OF THE USE OF
 * OR INABILITY TO USE SOFTWARE, EVEN IF SUN HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * This software is not designed or intended for use in on-line
 * control of aircraft, air traffic, aircraft navigation or aircraft
 * communications; or in the design, construction, operation or
 * maintenance of any nuclear facility. Licensee represents and warrants
 * that it will not use or redistribute the Software for such purposes.
 */


import java.util.Hashtable;
import java.util.Enumeration;
 
import javax.naming.*;
import javax.naming.directory.*;

/*
 * Retrieve several attributes of a particular entry.
 *
 * [equivalent to getattrs.c in Netscape SDK]
 */
class Getattrs {

public static void main(String[] args) {

    Hashtable env = new Hashtable(5, 0.75f);
    /*
     * Specify the initial context implementation to use.
     * For example,
     * This could also be set by using the -D option to the java program.
     *   java -Djava.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory \
     *       Getattrs
     */
    env.put(Context.INITIAL_CONTEXT_FACTORY, Env.INITCTX);

    /* Specify host and port to use for directory service */
    env.put(Context.PROVIDER_URL, Env.MY_SERVICE);

    try {
        /* get a handle to an Initial DirContext */
        DirContext ctx = new InitialDirContext(env);

        String[] attrs = new String[4];
        attrs[ 0 ] = "cn";              /* Get canonical name(s) (full name) */
        attrs[ 1 ] = "sn";              /* Get surname(s) (last name) */
        attrs[ 2 ] = "mail";            /* Get email address(es) */
        attrs[ 3 ] = "telephonenumber"; /* Get telephone number(s) */

        Attributes result = ctx.getAttributes(Env.ENTRYDN, attrs);

        if (result == null) {
            System.out.println(Env.ENTRYDN + 
                               "has none of the specified attributes.");
        } else {
            /* print it out */
            Attribute attr = result.get("cn");
            if (attr != null) {
                System.out.println("Full name:" );
                for (NamingEnumeration vals = attr.getAll();
                     vals.hasMoreElements();
                     System.out.println("\t" + vals.nextElement()))
                    ;
            }

            attr = result.get("sn");
            if (attr != null) {
                System.out.println("Last name (surname):" );
                for (NamingEnumeration vals = attr.getAll();
                     vals.hasMoreElements();
                     System.out.println("\t" + vals.nextElement()))
                    ;
            }

            attr = result.get("mail");
            if (attr != null) {
                System.out.println("Email address:" );
                for (NamingEnumeration vals = attr.getAll();
                     vals.hasMoreElements();
                     System.out.println("\t" + vals.nextElement()))
                    ;
            }
            attr = result.get("telephonenumber");
            if (attr != null) {
                System.out.println("Telephone number:" );
                for (NamingEnumeration vals = attr.getAll();
                     vals.hasMoreElements();
                     System.out.println("\t" + vals.nextElement()))
                    ;
            }
        }
    } catch (NamingException e) {
        System.err.println("Getattrs example failed.");
        e.printStackTrace();
    }
}
}
