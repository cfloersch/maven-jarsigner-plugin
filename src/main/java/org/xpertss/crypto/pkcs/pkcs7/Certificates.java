package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.ASN1CollectionOf;
import org.xpertss.crypto.asn1.ASN1SetOf;
import org.xpertss.crypto.asn1.ASN1Opaque;
import org.xpertss.crypto.asn1.ASN1Exception;
import org.xpertss.crypto.asn1.Decoder;
import org.xpertss.crypto.asn1.Encoder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.math.*;
import java.util.stream.Collectors;

/**
 * Represents a set of certificates. The ASN.1 structure of this type is:
 * <blockquote><code>
 *   Certificates ::= SET OF Certificate
 * </code></blockquote>
 * This tye is a convenience type for transporting sets of certificates. It decodes
 * certificates using X.509 certificate factories of the installed providers.
 * <p/>
 * This class des a little optimization - it decodes certificates using the {@link
 * ASN1Opaque} type. Therefor, the structure of certificates is not decoded immediately,
 * only the identifier and length octets are decoded. Certificate decoding takes place
 * in a postprocessing step which generates transparent certificate representations
 * using a X.509 certificate factory.
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
    * Adds the given certificate to this structure if none with the same issuer and serial
    * number already exists.
    *
    * @param cert The certificate to add.
    * @return <code>true</code> if the certificate was added and <code>false</code> if it
    *    already existed.
    *
    * TODO Probably don't need this one as certChain and certPath should be better alternatives
    */
   public boolean addCertificate(X509Certificate cert)
   {
      X500Principal issuer = cert.getIssuerX500Principal();
      BigInteger serial = cert.getSerialNumber();

      if (getCertificate(issuer, serial) == null) {
         certs.add(cert);
         setOptional(false);
         return true;
      }
      return false;
   }


   /**
    * Add a certificate chain to this Certificates object. This will iterate the chain from the
    * last element which is assumed to be the trust root, through to the signer certificate,
    * adding each if, and oly if, it does not already exist in the collection.
    * 
    * @param chain The chain of certificates to add
    */
   public void addCertChain(X509Certificate ... chain)
   {
      for(int i = chain.length - 1; i >= 0; i--) {
         X509Certificate cert = chain[i];
         X500Principal issuer = cert.getIssuerX500Principal();
         BigInteger serial = cert.getSerialNumber();
         if (getCertificate(issuer, serial) == null) {
            certs.add(cert);
         }
      }
      setOptional(certs.isEmpty());
   }

   /**
    * Add the certificates within a certificate path to this Certificates object. This will
    * iterate the chain from the last element which is assumed to be the trust root, through to
    * the signer certificate, adding each if, and oly if, it does not already exist in the
    * collection.
    * <p/>
    * It is assumed that the certificate path contains {@link X509Certificate} instances. This
    * will throw ClassCastException if they are not.
    *
    * @param certPath The chain of certificates to add
    */
   public void addCertPath(CertPath certPath)
   {
      List<X509Certificate> chain = certPath.getCertificates().stream()
                                       .map(cert -> (X509Certificate) cert)
                                       .collect(Collectors.toList());
      for(X509Certificate cert : chain) {
         X500Principal issuer = cert.getIssuerX500Principal();
         BigInteger serial = cert.getSerialNumber();
         if (getCertificate(issuer, serial) == null) {
            certs.add(cert);
         }
      }
      setOptional(certs.isEmpty());
   }
   




   /**
    * Returns the certificate with the given issuer and serial number if one exists of {@code
    * null} if it does not exist.
    *
    * @param issuer The issuer of the certificate
    * @param serial The serial number of the desired certificate
    */
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

   /**
    * This will return the certificate chain with the signer cert first followed by the
    * remainder of the chain. This will return {@code null} if a certificate with the
    * given issuer and serial number is not found.
    *
    * @param issuer The issuer of the subject certificate
    * @param serial The serial number of the subject certificate
    */
   public List<X509Certificate> getCertificates(X500Principal issuer, BigInteger serial)
   {
      if (issuer == null || serial == null)
         throw new NullPointerException("Issuer or serial number!");
      ArrayList<X509Certificate> chain = new ArrayList<>();
      X500Principal next = null;
      for(int i = certs.size() - 1; i >= 0; i--) {
         X509Certificate cert = certs.get(i);
         if(issuer.equals(cert.getIssuerX500Principal()) && serial.equals(cert.getSerialNumber())) {
            chain.add(cert);
            next = issuer;
         } else if(next != null && next.equals(cert.getSubjectX500Principal())) {
            chain.add(cert);
            if(isSelfSigned(cert)) return Collections.unmodifiableList(chain);
            next = cert.getIssuerX500Principal();
         }
      }
      return null;
   }

   /**
    * Returns all certificates in this collection as an unmodifiable List.
    */
   public List<X509Certificate> getCertificates()
   {
      return Collections.unmodifiableList(certs);
   }



   /*
    * Ordering of multiple certificate chains
    *
    * Example 1 - Two signers, both signer certs issued by same intermediary
    *   Root CA Certificate
    *   Intermediate CA Certificate
    *   SignerA's Certificate
    *   SignerB's Certificate
    *
    * Example 2 - Two signers, different intermediaries, same root
    *   Root CA Certificate
    *   Intermediate A CA Certificate
    *   SignerA's Certificate
    *   Intermediate B CA Certificate
    *   SignerB's Certificate
    *
    * Example 3 - Two signers, completely different chains
    *   Root A CA Certificate
    *   Intermediate A CA Certificate
    *   SignerA's Certificate
    *   Root B CA Certificate
    *   Intermediate B CA Certificate
    *   SignerB's Certificate
    */



   public String toString()
   {

      String s = getClass().getName();
      int n = s.lastIndexOf('.');

      if (n < 0) n = -1;

      s = s.substring(n + 1);
      if (s.startsWith("ASN1")) s = s.substring(4);

      StringBuffer buf = new StringBuffer(s);

      if (isOptional()) buf.append(" OPTIONAL");

      if (this instanceof ASN1CollectionOf)
         buf.append(" ").append( ((ASN1CollectionOf) this).getElementType().getName() );
      buf.append(" {\n");
      int i = 0;
      for(X509Certificate cert : certs) {
         buf.append("Certificate").append("[" + i + "]").append(" {").append("\n");
         buf.append("Subject: ").append(cert.getSubjectDN()).append("\n");
         buf.append("Issuer: ").append(cert.getIssuerDN()).append("\n");
         buf.append("Serial: ").append(cert.getSerialNumber()).append("\n");
         buf.append("}").append("\n");
         i++;

      }

      buf.append("}");
      return buf.toString();
   }




   /**
    * Decodes this instance using the given decoder. After decoding, the opaque certificates
    * are transformed into instances of X509Certificate by means of the default X509
    * CertificateFactory. If no such factory is available then an {@link ASN1Exception} is
    * raised.
    *
    * @param decoder The decoder to use.
    * @exception ASN1Exception if a decoding error occurs.
    * @exception IOException if an IO error occurs
    */
   public void decode(Decoder decoder)
      throws IOException
   {
      super.decode(decoder);

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

      for(int i = 0; i < size(); i++) {
         ASN1Opaque o = (ASN1Opaque) get(i);
         try(InputStream in = new ByteArrayInputStream(o.getEncoded())) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            certs.add(cert);
         } catch(CertificateException e) {
            throw new ASN1Exception(e);
         }
      }
   }


   /**
    * Encodes this using the given {@link Encoder}. There is a trick behind encoded this
    * instance. Each certificate is encoded using its default encoding model and embedded
    * as opaque elements in this sequence.
    *
    * @param enc The encoder to use for encoding.
    * @exception ASN1Exception if an encoding error occurs.
    * @exception IOException if guess what...
    */
   public void encode(Encoder enc)
      throws IOException
   {
      if(!isOptional()) {
         clear();
         for(X509Certificate cert : certs) {
            try {
               add(new ASN1Opaque(cert.getEncoded()));
            } catch(CertificateException e) {
               throw new ASN1Exception(e);
            }
         }
      }
      super.encode(enc);
   }




   private static boolean isSelfSigned(X509Certificate cert)
   {
      return cert.getSubjectDN().equals(cert.getIssuerDN());
   }


}
