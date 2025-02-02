package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;

import java.security.cert.X509Certificate;


/**
 * A common interface for signable classes such as {@link
 * SignedData SignedData} and {@link SignedAndEnvelopedData
 * SignedAndEnvelopedData}.
 */
public interface Signable {
   /**
    * Adds the given {@link SignerInfo SignerInfo} to this
    * instance. This method should be used rarely. In general,
    * the <code>Signer</code> instances take care of adding
    * <code>SignerInfo</code> instances. Explicit adding of a
    * <code>SignerInfo</code> is provided only in those cases
    * where fine control of the creation of signatures is
    * required.
    *
    * @param info The <code>SignerInfo</code> to add.
    */
   public void addSignerInfo(SignerInfo info);


   /**
    * Returns the <code>SignerInfo</code> that matches the
    * given certificate.
    *
    * @param cert The certificate matching the <code>SignerInfo
    *   </code> to be retrieved.
    * @return The <code>SignerInfo</code> or <code>null</code>
    *   if no matching one is found.
    */
   public SignerInfo getSignerInfo(X509Certificate cert);


   /**
    * Retrieves the content of the<code>Signable</code>,
    * consisting of the ASN.1 type embedded in its <code>
    * ContentInfo</code> structure.
    *
    * @return The contents octets.
    */
   public ASN1Type getContent();


   /**
    * Returns the content type of the content embedded
    * in this structure.
    *
    * @return The content type of this structure's payload.
    */
   public ASN1ObjectIdentifier getContentType();

}
