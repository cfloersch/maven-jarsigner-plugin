/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/17/2025
 */
package org.xpertss.jarsigner;

import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * An Identity represents the name (Alias) associated with a private key and it's
 * associated Certificate chain.
 */
public interface Identity {

   public String getName();

   public PrivateKey getPrivateKey();
   public X509Certificate getCertificate();

   public X509Certificate[] getCertificateChain();


}
