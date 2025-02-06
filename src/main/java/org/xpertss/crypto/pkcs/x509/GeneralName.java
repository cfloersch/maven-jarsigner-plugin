package org.xpertss.crypto.pkcs.x509;

import org.xpertss.crypto.asn1.*;

/**
 * <pre>
 *   GeneralName  ::= CHOICE {
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
        addType(new ASN1TaggedType(0, new ASN1Sequence(), false, true));
        addType(new ASN1TaggedType(1, new ASN1IA5String(), false, true));
        addType(new ASN1TaggedType(2, new ASN1IA5String(), false, true));
        addType(new ASN1TaggedType(3, new ASN1Sequence(), false, true));
        addType(new ASN1TaggedType(4, new ASN1SetOf(ASN1Opaque.class), false, true));
        addType(new ASN1TaggedType(5, new ASN1Sequence(), false, true));
        addType(new ASN1TaggedType(6, new ASN1IA5String(), false, true));
    }
}
