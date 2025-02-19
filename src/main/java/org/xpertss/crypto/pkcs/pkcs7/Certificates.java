package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.utils.CertOrder;
import org.xpertss.crypto.utils.CertificateUtils;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.cert.CertPath;
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
 * This tye is a convenience type for transporting sets of certificates. It decodes
 * certificates using X.509 certificate factories of the installed providers.
 * <p/>
 * This class des a little optimization - it decodes certificates using the {@link
 * ASN1Opaque} type. Therefor, the structure of certificates is not decoded immediately,
 * only the identifier and length octets are decoded. Certificate decoding takes place
 * in a postprocessing step which generates transparent certificate representations
 * using an X.509 certificate factory.
 */
public class Certificates extends ASN1TaggedType {

   /**
    * The certificate factory that is used for decoding certificates.
    */
   protected CertificateFactory factory;

   private final List<X509Certificate> certs = new ArrayList<>();

   private ASN1SetOf certSet;


   /**
    * Creates an instance ready for decoding.
    */
   public Certificates(int tag)
   {
      super(tag);
      certSet = new ASN1SetOf(ASN1Opaque.class);
      certSet.setExplicit(false);
      setInnerType(certSet);
      setOptional(true);
   }





   /**
    * Adds the given certificate to this structure if none with the same issuer and serial
    * number already exists.
    *
    * @param cert The certificate to add.
    * @return <code>true</code> if the certificate was added and <code>false</code> if it
    *    already existed.
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
    * adding each if, and only if, it does not already exist in the collection.
    * 
    * @param chain The chain of certificates to add
    */
   public void addCertChain(X509Certificate ... chain)
   {
      chain = CertOrder.Forward.convertTo(chain);
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
    * iterate the path from the last element which is assumed to be the trust root, through to
    * the signer certificate, adding each if, and only if, it does not already exist in the
    * collection.
    * <p/>
    * It is assumed that the certificate path contains {@link X509Certificate} instances. This
    * will throw ClassCastException if they are not.
    *
    * @param certPath The chain of certificates to add
    */
   public void addCertPath(CertPath certPath)
   {
      X509Certificate[] chain = CertificateUtils.toX509Chain(certPath);
      chain = CertOrder.Reverse.convertTo(chain);

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
      // TODO Maybe use AuthorityKeyIdentifier/SubjectKeyIdentifier instead of names
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
            if(CertificateUtils.isSelfSigned(cert)) return Collections.unmodifiableList(chain);
            next = cert.getIssuerX500Principal();
         }
      }
      return null;
   }

   /**
    * Returns all certificates in this collection as an unmodifiable List.
    * <p/>
    * A Certificates entity stores certificates from the trust root to the
    * end-entity ordering.
    */
   public List<X509Certificate> getCertificates()
   {
      // TODO Currently returns certs in Trust -> End-entity (aka Reverse) order.
      //  Should I reverse it?
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

      for(int i = 0; i < certSet.size(); i++) {
         ASN1Opaque o = (ASN1Opaque) certSet.get(i);
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
         certSet.clear();
         for(X509Certificate cert : certs) {
            try {
               certSet.add(new ASN1Opaque(cert.getEncoded()));
            } catch(CertificateException e) {
               throw new ASN1Exception(e);
            }
         }
      }
      super.encode(enc);
   }





}
