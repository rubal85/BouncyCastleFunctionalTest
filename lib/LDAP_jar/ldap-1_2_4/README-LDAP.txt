	Java Naming and Directory Interface(TM) (JNDI)
	     LDAP Service Provider Release Notes
	               FCS 1.2.4
		      August 3, 2001


This is the 1.2.4 maintenance release of the JNDI LDAP service
provider.  Please send feedback on the LDAP service provider to us at
jndi@java.sun.com, or to the public mailing list at
jndi-interest@java.sun.com.


CHANGES SINCE 1.2.3

Here are the highlights:

- Support for the Start TLS extension (RFC 2830). This feature works
with only the J2SDK 1.4 or higher releases.

- Support for the DIGEST-MD5 SASL authentication mechanism (RFCs 2829
and 2831).  This feature requires the Java Cryptography Extension
(JCE), version 1.2 and higher, available both as an Optional Package
(http://java.sun.com/products/jce) and in the Java 2 Platform,
Standard Edition, v1.4 or higher releases.

- Support for the GSSAPI SASL authentication mechanism (RFC
2222). This allows communication with the LDAP service using Kerberos
v5.  This feature requires the Java GSS (RFC 2853), available in the
Java 2 Platform, Standard Edition, v1.4 or higher releases.

- Support for SASL mechanisms with integrity/privacy for all platforms
  (previously, only Solaris was supported)

- Support for connection timeout when creating an initial context

- NamingEnumeration's hasMore()/next() need not be called in lock-step

- Support for IPv6 addresses in LDAP URLs

- Correct mapping of the following LDAP error codes to 
  AuthenticationNotSupportedException:
      strongAuthRequired           (8)
      confidentialityRequired      (13)
      inappropriateMatching        (18)

- Ensure that bind()/rebind() includes the entry's RDN in the attributes
  being added

- Support for modifyAttributes() on schema entries

- UnsolicitedNotificationListeners receive event when server closes connection

- DirContext.getSchema() no longer interferes with closing underlying connection

- Escaped trailing spaces no longer disappear from LDAP RDNs

- Fixed concurrent reading of schema tree (used to cause corruption of schema 
tree)

- Fixed referral handling for the list() and rename() methods


RELEASE INFORMATION

This release contains:

lib/ldap.jar
	Archive of class files for the service provider.

lib/providerutil.jar
	Utilities used by service providers developed by Sun Microsystems.
	The LDAP service provider uses some of the classes in this archive.
	This archive file is interchangeable with the providerutil.jar
	file that you may have downloaded with one of the other service 
	providers currently available from Sun Microsystems.

lib/ldapsec.jar
	Archive ("security pack") for supporting SASL (EXTERNAL, DIGEST-MD5,
	and GSSAPI) and StartTLS.

lib/ldapbp.jar
	Archive ("booster pack") for supporting CRAM-MD5 SASL 
        authentication, Java(TM) Remote Method Invocation and CORBA 
        object factories, and the sort, virtual-list-view, paged-results, 
        tree-delete and dir-sync controls.

lib/jaas.jar
	Archive of class files for Java(TM) Authentication and Authorization
        Service (JAAS) that is used by SASL classes.
	See http://java.sun.com/products/jaas/.

doc/providers/jndi-ldap-gl.html
	Guidelines for developers of LDAP service providers.

doc/providers/jndi-ldap-ext.html
doc/providers/jndi-ldap.html
	Documentation of the service provider.

http://www.ietf.org/rfc/rfc2713.txt
	Documentation of the schema for representing objects in the 
        Java(TM) programming language in an LDAP directory.

http://www.ietf.org/rfc/rfc2714.txt
	Documentation of the schema for representing CORBA objects 
	in an LDAP directory.

doc/ldapcontrols/
	javadoc for controls that are shipped with this release.

doc/sasl/
	javadoc for SASL API preview.

schema/
	Utilities for converting objects bound using the schema described
	in older versions of RFCs 2713 and 2714, and for
	adding the schema for RFCs 2713 and 2714. See schema/README.txt.

examples/ldap
	Examples for the LDAP programmer. These examples
	illustrate how to perform operations equivalent to
	the Netscape SDK's C language examples. They also
        include examples of how to use the controls.
        See examples/ldap/README.


The classes in this release have been generated using the Java(TM) 2 SDK,
Standard Edition, v1.2.


ADDITIONAL INFORMATION

examples/api (available as part of the general JNDI 1.2 distribution)
	Generic examples for accessing any naming and
	directory service, including LDAP. See examples/api/README.

examples/browser (available as a separate download)
	A JNDI browser for browsing any naming and directory
	service, including LDAP. See examples/browser/README-DEMO.txt.

http://java.sun.com/products/jndi/1.2/javadoc        
	JNDI 1.2 javadoc.

http://java.sun.com/products/jndi/tutorial/
	The JNDI Tutorial
