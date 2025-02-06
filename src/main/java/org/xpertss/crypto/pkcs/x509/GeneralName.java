package org.xpertss.crypto.pkcs.x509;

import org.xpertss.crypto.asn1.*;

/**
 * <pre>
 *   GeneralNames  ::= CHOICE {
 *     otherName                    [0] OtherName,
 *     rfc822Name                   [1] IA5String,
 *     dNSName                      [2] IA5String,
 *     x400Address                  [3] ORAddress,
 *     directoryName                [4] Name,
 *     ediPartyName                 [5] EDIPartyName,
 *     uniformResourceIdentifier    [6] URI
 *   }
 *
 *
 *   OtherName ::= SEQUENCE {
 *     type-id    OBJECT IDENTIFIER,
 *     value      [0] ANY DEFINED BY type-id
 *   }
 *
 *
 *   ORAddress ::= SEQUENCE {
 *     type-id    OBJECT IDENTIFIER,
 *     value      [0] ANY DEFINED BY type-id
 *   }
 *
 *
 *   URI ::= IA5String
 *
 *   Name ::= SET OF RelativeDistinguishedName
 *
 *   RelativeDistinguishedName ::= SET SIZE (1..2) OF AttributeTypeAndValue
 *
 *   AttributeTypeAndValue ::= SEQUENCE {
 *     type  OBJECT IDENTIFIER,
 *     value ANY DEFINED BY type
 *   }
 *
 *
 *   EDIPartyName ::= SEQUENCE {
 *     partyName        [1] DirectoryString OPTIONAL,
 *     partNumber       [2] INTEGER OPTIONAL
 *   }
 *
 *   DirectoryString ::= CHOICE {
 *     teletexString   TeletexString,
 *     printableString PrintableString,
 *     universalString UniversalString,
 *     utf8String      UTF8String,
 *     bmpString       BMPString
 *   }
 * </pre>
 */
public class GeneralName extends ASN1Choice {

    // Types: dNSName, directoryName (aka X.500 distinguished name), rfc822Name (email),
    //          x400Address, ediPartyName, uniformResourceIdentifier, otherName

    public GeneralName()
    {
        super(3);
        addType(new ASN1Sequence());
        addType(new ASN1IA5String());
        addType(new ASN1Set());
    }
}
