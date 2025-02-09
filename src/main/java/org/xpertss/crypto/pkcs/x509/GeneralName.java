package org.xpertss.crypto.pkcs.x509;

import org.xpertss.crypto.asn1.*;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This class represents the <em>GeneralName</em> data type as denoted in X.509. It implements
 * the following ASN1 data structure:
 * <p/>
 * <pre>
 *   GeneralName  ::= CHOICE {
 *     otherName                    [0]  IMPLICIT  OtherName,
 *     rfc822Name                   [1]  IMPLICIT  IA5String,
 *     dNSName                      [2]  IMPLICIT  IA5String,
 *     x400Address                  [3]  IMPLICIT  ORAddress,
 *     directoryName                [4]  IMPLICIT  Name,
 *     ediPartyName                 [5]  IMPLICIT  EDIPartyName,
 *     uniformResourceIdentifier    [6]  IMPLICIT  URI
 *     iPAddress                    [7]  IMPLICIT  OCTET STRING
 *     registeredID                 [8]  IMPLICIT  OBJECT IDENTIFIER
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
 *     type     [0] INTEGER,
 *     value    [1] OCTET STRING
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
 *     teletexString     TeletexString,
 *     printableString   PrintableString,
 *     universalString   UniversalString,
 *     utf8String        UTF8String,
 *     bmpString         BMPString
 *   }
 * </pre>
 */
public class GeneralName extends ASN1Choice {

    public static final int otherName = 0;
    public static final int rfc822Name = 1;
    public static final int dNSName = 2;
    public static final int x400Address = 3;
    public static final int directoryName = 4;
    public static final int ediPartyName = 5;
    public static final int uniformRessourceIdentifier = 6;
    public static final int iPAddress = 7;
    public static final int registeredID = 8;


    private X500Principal x500Name;

    // Types: dNSName, directoryName (aka X.500 distinguished name), rfc822Name (email),
    //          x400Address, ediPartyName, uniformResourceIdentifier, otherName

    public GeneralName()
    {
        super(3);
        addType(new ASN1TaggedType(otherName, new OtherName(), false, false));

        addType(new ASN1TaggedType(rfc822Name, new ASN1IA5String(), false, false));
        addType(new ASN1TaggedType(dNSName, new ASN1IA5String(), false, false));

        addType(new ASN1TaggedType(x400Address, new ASN1Sequence(), false, false));

        addType(new ASN1TaggedType(directoryName, new ASN1SequenceOf(ASN1Opaque.class), false, false));

        addType(new ASN1TaggedType(ediPartyName, new ASN1Sequence(), false, false));

        addType(new ASN1TaggedType(uniformRessourceIdentifier, new ASN1IA5String(), false, false));
        addType(new ASN1TaggedType(iPAddress, new ASN1OctetString(), false, false));
        addType(new ASN1TaggedType(registeredID, new ASN1ObjectIdentifier(), false, false));
    }



    public GeneralName(int type, String value)
    {
        switch(type) {
            case rfc822Name:
            case dNSName:
            case uniformRessourceIdentifier:
                setInnerType(new ASN1TaggedType(type, new ASN1IA5String(value), false, false));
                break;
            case directoryName:
                x500Name = new X500Principal(value);
                setInnerType(new ASN1TaggedType(directoryName, new ASN1SequenceOf(ASN1Opaque.class), false, false));
                break;
            case registeredID:
                setInnerType(new ASN1TaggedType(registeredID, new ASN1ObjectIdentifier(value), false, false));
                break;
            case iPAddress:
              setInnerType(new ASN1TaggedType(iPAddress, new ASN1OctetString(toBytes(value)), false, false));
              break;
           default:
                throw new UnsupportedOperationException("Type doesn't support string values");
        }
    }


    public GeneralName(X500Principal x500Name)
    {
        this.x500Name = x500Name;
        setInnerType(new ASN1TaggedType(directoryName, new ASN1SequenceOf(ASN1Opaque.class), false, false));
    }



    // TODO Do I care about constructors for x400, EDI, or Other Names?




    public int getType()
    {
        return getTag();
    }

    
    public ASN1Type getGeneralName()
    {
        // extract the TaggedType first, then the "real" inner value
        ASN1TaggedType inner = (ASN1TaggedType) getInnerType();
        if(inner != null) {
            switch(getTag()) {
                case otherName:
                    return (OtherName) inner.getInnerType();
                case rfc822Name:
                    return (ASN1IA5String) inner.getInnerType();
                case dNSName:
                    return (ASN1IA5String) inner.getInnerType();
                case x400Address:
                    throw new UnsupportedOperationException("x400Address not yet supported!");
                case directoryName:
                    return (ASN1Sequence) inner.getInnerType();
                case ediPartyName:
                    throw new UnsupportedOperationException("ediPartyName not yet supported!");
                case uniformRessourceIdentifier:
                    return (ASN1IA5String) inner.getInnerType();
                case iPAddress:
                    return (ASN1OctetString) inner.getInnerType();
                case registeredID:
                    return (ASN1ObjectIdentifier) inner.getInnerType();
                default:
                    throw new UnsupportedOperationException("Tag not supported for GeneralName: " + getTag());
            }
        }
        return null;
    }



    @Override
    public String toString()
    {
        if(getInnerType() != null) {
            switch(getTag()) {
                case directoryName:
                    return x500Name.toString();
                case rfc822Name:
                case dNSName:
                case uniformRessourceIdentifier:
                    return ((ASN1IA5String) getGeneralName()).getString();
                case iPAddress:
                    byte[] addr = ((ASN1OctetString) getGeneralName()).getByteArray();
                    return toInetAddress(addr);
            }
            return getGeneralName().toString();
        }
        return null;
    }





    @Override
    public void decode(Decoder decoder)
       throws IOException
    {
        super.decode(decoder);
        if(getTag() == directoryName) {
            ASN1TaggedType inner = (ASN1TaggedType) getInnerType();
            this.x500Name = new X500Principal(AsnUtil.encode(inner.getInnerType()));
        }
    }

    @Override
    public void encode(Encoder encoder)
       throws IOException
    {
        if(getTag() == directoryName) {
            ASN1TaggedType inner = (ASN1TaggedType) getInnerType();
            inner.setInnerType(new ASN1Opaque(x500Name.getEncoded()));
        }
        super.encode(encoder);
    }




    private static byte[] toBytes(String ip)
    {
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch(UnknownHostException e) {
           throw new IllegalArgumentException(ip + " not a valid ip address");
        }
    }


    private static String toInetAddress(byte[] octets)
    {
        StringBuilder builder = new StringBuilder();
        if(octets.length == 4) {
            for(byte octet : octets) {
                int unsigned = octet & 0xFF;
                if(builder.length() > 0) builder.append(".");
                builder.append(unsigned);
            }
        } else {
            for (int i = 0; i < 16; i += 2) {
                int high = (octets[i] & 0xFF) << 8;
                int low = octets[i + 1] & 0xFF;
                int value = high | low;
                builder.append(String.format("%x", value));
                if (i < 14) builder.append(":");
            }
        }
        return builder.toString();
    }


}
