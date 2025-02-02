/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.crypto.pkcs;

import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;

import java.security.NoSuchAlgorithmException;

/**
 * This class provides a means to translate common human readable
 * crypto algorithm names into their ObjectIdentifier counter part
 * and vice-versa
 */
public class Algorithm {

   
   public ASN1ObjectIdentifier lookup(String algorithmName)
      throws NoSuchAlgorithmException
   {
      return null;
   }

   public String lookup(ASN1ObjectIdentifier oid)
      throws NoSuchAlgorithmException
   {
      return null;
   }

}
