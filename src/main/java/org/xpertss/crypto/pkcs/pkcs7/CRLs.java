/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/2/2025
 */
package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.ASN1Exception;
import org.xpertss.crypto.asn1.ASN1Opaque;
import org.xpertss.crypto.asn1.ASN1SetOf;
import org.xpertss.crypto.asn1.Decoder;
import org.xpertss.crypto.asn1.Encoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

// TODO Impl like certificates but with X509 CLRs
public class CRLs  extends ASN1SetOf {


   /**
    * The certificate factory that is used for decoding certificates.
    */
   protected CertificateFactory factory;

   private final List<X509CRL> crls = new ArrayList<>();

   /**
    * Creates an instance ready for decoding.
    */
   public CRLs()
   {
      super(ASN1Opaque.class);
   }







   // TODO What other methods make sense here?







   /**
    * Decodes this instance using the given decoder. After decoding, the opaque CRLs are
    * transformed into instances of X509CRL by means of the default X509 CertificateFactory.
    * If no such factory is available then an {@link ASN1Exception} is raised.
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
            X509CRL crl = (X509CRL) factory.generateCRL(in);
            crls.add(crl);
         } catch(CRLException e) {
            throw new ASN1Exception(e);
         }
      }
   }


   /**
    * Encodes this using the given {@link Encoder}. There is a trick behind encoding this
    * instance. Each CRL is encoded using its default encoding model and embedded as opaque
    * elements in this sequence.
    *
    * @param enc The encoder to use for encoding.
    * @exception ASN1Exception if an encoding error occurs.
    * @exception IOException if guess what...
    */
   public void encode(Encoder enc)
      throws IOException
   {
      clear();
      for(X509CRL crl : crls) {
         try {
            add(new ASN1Opaque(crl.getEncoded()));
         } catch(CRLException e) {
            throw new ASN1Exception(e);
         }
      }
      super.encode(enc);
   }



}
