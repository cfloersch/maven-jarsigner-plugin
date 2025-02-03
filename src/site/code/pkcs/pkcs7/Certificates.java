package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.ASN1SetOf;
import org.xpertss.crypto.asn1.ASN1Opaque;
import org.xpertss.crypto.asn1.ASN1Exception;
import org.xpertss.crypto.asn1.Decoder;
import org.xpertss.crypto.asn1.Encoder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.math.*;

/**
 * Represents a set of certificates. The ASN.1 structure of this type is:
 * <blockquote><code>
 *   Certificates ::= SET OF Certificate
 * </code></blockquote>
 * This tye is a convenience type for transporting sets of certificates. It
 * decodes certificates using X.509 certificate factories of the installed
 * providers.
 * <p/>
 * This class des a little optimization - it decodes certificates using the
 * {@link ASN1Opaque ASN1Opaque} type. Therefor, the structure of certificates
 * is not decoded immediately, only the identifier and length octets are
 * decoded. Certificate decoding takes place in a postprocessing step which
 * generates transparent certificate representations using a X.509 certificate
 * factory.
 * <p/>
 * TODO I notice this does not define the ASN1Choice aspect and always assumes
 * we have a SetOf
 */
public class Certificates extends ASN1SetOf {

   /**
    * The certificate factory that is used for decoding certificates.
    */
   protected CertificateFactory factory;

   private final List<X509Certificate> certs = new ArrayList<>();

   /**
    * Creates an instance ready for decoding.
    */
   public Certificates()
   {
      super(ASN1Opaque.class);
   }


   /**
    * Decodes this instance using the given decoder. After
    * decoding, the opaque certificates are transformed into
    * instances of X509Certificate by means of a
    * CertificateFactory. If no such factory was set then
    * a default factory of type &quot;X.509&quot; is
    * requested. If no such factory is available then
    * &quot;X509&quot; is tried instead. If neither of
    * these attempts is successful then an ASN1Exception
    * is raised.
    *
    * @param dec The decoder to use.
    * @exception ASN1Exception if a decoding error occurs.
    * @exception IOException if guess what...
    */
   public void decode(Decoder dec)
      throws IOException
   {
      super.decode(dec);

      if (factory == null) {
         try {
            factory = CertificateFactory.getInstance("X.509");
         } catch (CertificateException e1) {
            try {
               factory = CertificateFactory.getInstance("X509");
            } catch (CertificateException e2) {
               throw new ASN1Exception("Unable to load certificate factory");
            }
         }
      }

      for (int i = size() - 1; i >= 0; i--) {
         ASN1Opaque o = (ASN1Opaque) get(i);
         try(InputStream in = new ByteArrayInputStream(o.getEncoded())) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            certs.set(i, cert);
         } catch(CertificateException e) {
            throw new ASN1Exception(e.getMessage());
         }
      }
   }


   /**
    * Encodes this using the given {@link Encoder Encoder}.
    * There is a trick behind encoded this instance. Actually
    * not this instance is encoded but a cache that is filled
    * with encoded instances of the certificates in this type.
    *
    * @param enc The encoder to use for encoding.
    * @exception ASN1Exception if an encoding error occurs.
    * @exception IOException if guess what...
    */
   public void encode(Encoder enc)
      throws IOException
   {
      clear();
      for(X509Certificate cert : certs) {
         try {
            add(new ASN1Opaque(cert.getEncoded()));
         } catch(CertificateException e) {
            throw new ASN1Exception(e.getMessage());
         }
      }
      super.encode(enc);
   }



   /**
    * Adds the given certificate to this structure if none
    * with the same issuer and serial number already exists.
    *
    * @param cert The certificate to add.
    * @return <code>true</code> if the certificate was added
    *   and <code>false</code> if it already existed.
    */
   public boolean addCertificate(X509Certificate cert)
   {
      X500Principal issuer = cert.getIssuerX500Principal();
      BigInteger serial = cert.getSerialNumber();

      if (getCertificate(issuer, serial) == null) {
         certs.add(cert);
         return true;
      }
      return false;
   }


   public X509Certificate getCertificate(X500Principal issuer, BigInteger serial)
   {
      if (issuer == null || serial == null)
         throw new NullPointerException("Issuer or serial number!");
      for(X509Certificate cert : certs) {
         if(issuer.equals(cert.getIssuerX500Principal())
               && serial.equals(cert.getSerialNumber())) {
            return cert;
         }
      }
      return null;
   }



   /*
   // TODO Maybe today would be better to be a Set<X509Certificate>
   public Iterator<X509Certificate> certificates(X500Principal subject)
   {
      return new CertificateIterator(subject, CertificateSource.ALL, certs);
   }


   public Iterator<X509Certificate> certificates(X500Principal subject, int keyUsage)
   {
      return new CertificateIterator(subject, keyUsage, certs);
   }
   */


}
