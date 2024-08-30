		    Java/CORBA LDAP Schema Tools
		 	   February 29, 2000


This note describes the tools for creating schema entries for storing
Java and CORBA objects, and for updating existing directory entries
that use the now obsolete draft-ryan-java-schema-00.txt and
draft-ryan-corba-schema-01.txt.  This note also summarizes the changes
between the different versions of the Java schema.

The Java schema is described in RFC 2713.
      http://www.ietf.org/rfc/rfc2713.txt

The CORBA schema is described in RFC 2714.
      http://www.ietf.org/rfc/rfc2714.txt

NOTE: Entries created using the schema defined in
draft-ryan-java-schema-01.rev.txt are compatible with those defined in
draft-ryan-java-schema02.txt and RFC 2713.  You only need to update
the schema, not the directory entries containing Java objects.



1. SUMMARY OF CHANGES FOR ATTRIBUTES IN JAVA SCHEMA
draft-ryan-java-schema-02.txt     -> RFC 2713

   javaSerialized Data's syntax changed from 
   Binary (1.3.6.1.4.1.1466.115.121.1.5) to 
   Octet String (1.3.6.1.4.1.1466.115.121.1.40).

   For Netscape Directory (4.1 and earlier), continue to use Binary
   because it does not support Octet String yet.

draft-ryan-java-schema-01.rev.txt -> draft-ryan-java-schema-02.txt

   javaCodebase                      -> [syntax is an ordered list of URLs]
   javaRemoteLocation                -> [deleted]
				        javaClassNames [new]
				        javaDoc [new]

   * Added javaClassNames for storing additional class information.

   * Added javaDoc for storing links to documentation

   * Clarified definition of javaCodebase. Each value is an ordered list of
     URLs, separated by spaces. The URLs in each value collectively forms the
     codebase. Multiple values of javaCodebase are independent codebases.


draft-ryan-java-schema-00 -> draft-ryan-java-schema-01.rev.txt

   javaClassName             -> [updated EQUALITY syntax, new OID]
   javaSerializedObject      -> javaSerializedData [new OID]
   javaReferenceAddress      -> [updated EQUALITY syntax, new OID]
   javaFactory               -> [updated EQUALITY syntax, new OID]
   javaFactoryLocation       -> javaCodebase [new OID, new IA5 syntax]
				javaRemoteLocation [new]

   * The javaFactory attribute was renamed to javaCodebase and shared by
     other object classes for specifying a codebase.  It now uses IA5
     syntax instead of DirectoryString.

   * javaSerializedObject was renamed to javaSerializedData. 

   * The attributes used to specify class names (javaClassName,
     javaFactory) use a case-exact matching rule for equality.

   * A new attribute, javaRemoteLocation, was added to represent the RMI
     URL used to name an RMI object.

   * Removed javaRemoteLocation. Remote objects now stored as JNDI references
     or as marshalled objects.



2. SUMMARY OF CHANGES FOR OBJECT CLASSES IN JAVA SCHEMA

draft-ryan-java-schema-01.rev.txt -> draft-ryan-java-schema-02.txt

   javaObject                        -> [+ javaClassNames, javaDoc, description]
   javaRemoteObject                  -> [deleted]
			                javaMarshalledObject [new]

   * Added javaMarshalledObject, which is like a javaSerializedObject except
     for its interpretation of the javaClassName and javaClassNames attributes.
     Used for storing remote objects or serializable objects.

   * Deleted javaRemoteObject. Remote objects now stored as JNDI references
     or marshalled objects.

   * Added optional attributes to javaObject: javaClassNames, javaDoc,
     description


draft-ryan-java-schema-00.txt -> draft-ryan-java-schema-01.rev.txt

   javaObject                    -> javaSerializedObject [new parent, new OID]
   javaNamingReference           -> [new parent, new OID]
				    javaObject [new]
				    javaRemoteObject [new]

   * A superclass javaObject was added to be the base class for all three
   types of Java-related objects.  

   * javaObject, which used to represent a serialized object, was renamed
   to javaSerializedObject.

   * A new object class, javaRemoteObject, was added for representing a
   Java RMI object.



3. SUMMARY OF CHANGES FOR OBJECT CLASSES IN CORBA SCHEMA

draft-ryan-corba-schema-00.txt -> draft-ryan-corba-schema-01.txt

   corbaObject                    -> [made ABSTRACT and removed corbaIor]
			             corbaObjectReference [new]

   * Moved corbaIor to a separate object class, corbaObjectReference, that is
     a subclass of corbaObject.



4. UPDATING THE DIRECTORY SCHEMA

   You can use your directory's administration tool to update the schema
   according to draft-ryan-java-schema-02.txt and
   draft-ryan-corba-schema-00.txt as summarized above. Or, you can use
   the CreateJavaSchema and CreateCorbaSchema programs.

      java [-Djava.naming.provider.url=<provider_url>] \
         CreateCorbaSchema|CreateJavaSchema \
	   [-h|-s[n]] [-n<dn>] [-p<passwd>] [-a<auth>] 
       
     -h		  Print the usage message
     -l		  List the relevant schema in the directory
     -s[n|n41|ad] Update schema:
                    -sn   means use a workaround for schema bugs in
                          pre-4.1 releases of Netscape Directory Server

		    -sn41 means use a workaround for schema bugs in
                          Netscape Directory Server version 4.1

		    -sad  means use a workaround for schema bugs in
			  Microsoft Windows 2000 Active Directory

     -n<dn> 	  Use <dn> as the distinguished name for authentication
     -p<passwd>	  Use <passwd> as the password for authentication
     -a<auth>	  Use <auth> as the authentication mechanism.
		  Default is "simple".
 
   If neither -s, -l, nor -h has been specified, the default is "-l".

   NOTE: If you are using Netscape Directory Server 4.0 (or earlier),
         you need to use the "-sn" option to workaround schema bugs in
         the server.

   NOTE: If you are using Netscape Directory Server 4.1, 
         you need to use the "-sn41" option to workaround schema bugs in
         the server. Also, before making any changes to the schema, you 
         must make the following schema modification. Locate the ns-schema.conf
         file in the server installation at the directory named:

             <NETSCAPE-DIRECTORY-HOME>/slapd-<SERVER-ID>/config/

         Comment out the line that contains 'java-object-schema.conf'
         because that schema is now out-of-date. Then re-start the
         server and use the CreateJavaSchema program to install the
         updated schema. It is necessary to manually remove the
         reference to the old schema from the list of built-in schemas
         in ns-schema.conf because the server does not permit such
         built-in schemas to be modified via the LDAP protocol.

   NOTE: If you are using Microsoft Active Directory you need to use
         the "-sad" option to workaround schema bugs in the server.
         Also, to enable any schema modifications the following registry
         property must be created and set to (DWORD) 1:

             HKEY_LOCAL_MACHINE
	       System
	         CurrentControlSet
	           Services
	             NTDS
	               Parameters
	                 Schema Update Allowed

   If the directory's administration tool supports turning off schema
   checking then do so before running the CreateJavaSchema or
   CreateCorbaSchema programs.

   When you run these programs, you need to login as the directory
   administrator, quoting the "-n" option if there are blanks in the
   distinguished name. After updating the schema, you should use the
   directory server's administration tool to verify that the changes
   have been properly applied. The Netscape Directory Server 3.0, for
   example, ignores some attributes. If the schema has not been properly
   updated, use the administration tool to correct it.

   For example, to create the Java schema in a Netscape Directory Server
   version 4.1,

       java -Djava.naming.provider.url=ldap://myserver CreateJavaSchema\
           -sn41 "-ncn=Directory Administrator" -psecret

   For example, to create the CORBA schema in a Netscape Directory Server
   version 4.0,

       java -Djava.naming.provider.url=ldap://myserver CreateCorbaSchema\
           -sn "-ncn=Directory Administrator" -psecret

   For example, to create the Java schema in a Windows 2000 Active Directory,

       java -Djava.naming.provider.url=ldap://myserver CreateJavaSchema\
           -sad "-ncn=administrator,cn=users,dc=xxx,dc=yyy,dc=zzz" -psecret



5. UPDATING EXISTING DIRECTORY ENTRIES

   JAVA SCHEMA 

   If your directory has entries that use
   draft-ryan-java-schema-01.rev.txt, you can use UpdateJavaObjects to
   update the entries so that they conform to the new schema.

   NOTE: Entries created using the schema defined in
         draft-ryan-java-schema-01.rev.txt are compatible with those defined in
         draft-ryan-java-schema02.txt.  You only need to update the schema, not
         the directory entries containing Java objects. That is, you DO NOT
         need to use UpdataJavaObjects if your entries were added using the
         schema in draft-ryan-java-schema-01.rev.txt.

   Turn schema-checking off first.

   0. Update schema first using CreateJavaSchema.

   1. See what changes will be made.

      You can narrow the scope of the subtree to search by supplying the
      appropriate DN in the provider URL.

      # java -Djava.naming.provider.url=ldap://myserver/o=JNDITutorial \
            UpdateJavaObjects

   2. Update the objects. 

      You can narrow the scope of the subtree to update by supplying the
      appropriate DN in the provider URL. You probably also need to provider
      a login DN and password depending on the access control of the server.

      # java -Djava.naming.provider.url=ldap://myserver/o=JNDITutorial \
            UpdateJavaObjects -u

   3. Repeat Step 2 to verify that no more objects need to be updated.


   CORBA SCHEMA

   If your directory has entries that use draft-ryan-corba-schema-00.txt,
   you can use UpdateCorbaObjects to update the entries so that they
   conform to the new schema. Turn schema-checking off first.

   0. Update schema first using CreateCorbaSchema.

   1. See what changes will be made.

      You can narrow the scope of the subtree to search by supplying the
      appropriate DN in the provider URL.

      # java -Djava.naming.provider.url=ldap://myserver/o=JNDITutorial \
            UpdateCorbaObjects

   2. Update the objects. 

      You can narrow the scope of the subtree to update by supplying the
      appropriate DN in the provider URL. You probably also need to provider
      a login DN and password depending on the access control of the server.

      # java -Djava.naming.provider.url=ldap://myserver/o=JNDITutorial \
            UpdateCorbaObjects -u

   3. Repeat Step 2 to verify that no more objects need to be updated.

----
