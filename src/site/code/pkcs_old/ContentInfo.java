package org.xpertss.crypto.pkcs_old;

/**
 *  ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 *  }
 *
 *  ContentType ::= OBJECT IDENTIFIER
 *
 *  Content-Types
 *    DATA
 *    SIGNED_DATA
 *    ENVELOPED_DATA
 *    SIGNED_AND_ENVELOPED_DATA
 *    DIGESTED_DATA
 *    ENCRYPTED_DATA
 *    TIMESTAMP_TOKEN_INFO
 */
public class ContentInfo {

    private ContentInfo()
    {

    }



    public static ContentInfo empty()
    {
        return new ContentInfo();
    }
}
