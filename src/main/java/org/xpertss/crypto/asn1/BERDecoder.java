package org.xpertss.crypto.asn1;

import java.util.*;
import java.io.*;

/**
 * Decodes ASN.1/DER encoded types according to the rules set 
 * forth in ITU-T Recommendation X.690.
 * <p>
 * Decoders can be operated in two modi. The first mode just 
 * reads any ASN.1 type encountered in a stream and returns 
 * the instantiated objects. This mode is used if for instance 
 * method {@link #readType() readType()} is called.
 * <p>
 * The second mode matches the decoded data against an 
 * application-specified ASN.1 structure. Violations of the 
 * structure definition causes an exception being thrown.
 */
public class BERDecoder extends DERDecoder {

   /**
    * Creates an instance that reads from the given input
    * stream.
    *
    * @param in The input stream to read from.
    */
   public BERDecoder(InputStream in)
   {
      super(in);
   }


   /**
    * Reads in a sequence of ASN.1 types and stores them in the
    * given collection. This method overrides a method in the
    * parent class in order to handle indefinite length encodings
    * as required by BER. Indefinite length encodings are detected
    * by checking the {@link #indefinite_ indefinite_} field in
    * this instance. This field is initialized by method {@link
    * DERDecoder#readNext() readNext()} when the identifier and
    * length octets of the next ASN.1 type in the stream are parsed.
    *
    * @param c The ASN.1 collection in which decoded types are
    *   stored.
    * @exception IOException if guess what...
    */
   protected void readTypes(ASN1Collection c)
      throws IOException
   {
      if (indefinite_) {
         ASN1Type o;
         while ((o = readType()) != null) {
            c.add(o);
         }
      } else {
         super.readTypes(c);
      }
   }


   public void readBitString(ASN1BitString t)
      throws IOException
   {
      match1(t);
      skipNext(true);

      if (primitive_) {
         super.readBitString(t);
         return;
      }
      /* We now make the decoder believe it encountered a
       * sequence and tell it to skip reading the next header.
       * Then, we actually decode a SEQUENCE OF BIT STRING.
       * After decoding the consecutive segments of bit strings
       * we assemble them back into a single one while checking
       * the constraints. All necessary flags are still in
       * place.
       */
      ASN1SequenceOf seq = new ASN1SequenceOf(ASN1BitString.class);
      tag_ = ASN1.TAG_SEQUENCE;
      tagclass_ = ASN1.CLASS_UNIVERSAL;

      seq.decode(this);

      int pad = 0;
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try {
         Iterator i = null;
         for (i = seq.iterator(); i.hasNext();) {
            ASN1BitString v = (ASN1BitString) i.next();
            bos.write(v.getBytes());

            int n = pad;
            pad = v.getPadCount();

            if (pad != 0 && n != 0) {
               throw new ASN1Exception("Pad count mismatch in BIT STRING segment!");
            }
         }
         t.setBits(bos.toByteArray(), pad);
         bos.close();
      } catch (ClassCastException e) {
         throw new ASN1Exception("Type mismatch in BER encoded BIT STRING segment!");
      }
   }


   public void readOctetString(ASN1OctetString t)
      throws IOException
   {
      match1(t);

      /* We have to skip in any case. Either in order to
       * allow our super class to match once again or to
       * let the SEQUENCE match the faked type if we
       * came across a CONSTRUCTED encoding (BER).
       */
      skipNext(true);

      if (primitive_) {
         super.readOctetString(t);
         return;
      }
      /* We now make the decoder believe it encountered a
       * sequence and tell it to skip reading the next header.
       * Then, we actually decode a SEQUENCE OF OCTET STRING.
       * After decoding the consecutive segments of octet strings
       * we assemble them back into a single one while checking
       * the constraints. All necessary flags are still in
       * place.
       */
      ASN1SequenceOf seq = new ASN1SequenceOf(ASN1OctetString.class);
      tag_ = ASN1.TAG_SEQUENCE;
      tagclass_ = ASN1.CLASS_UNIVERSAL;
      seq.decode(this);

      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try {
         Iterator i = null;
         for (i = seq.iterator(); i.hasNext();) {
            ASN1OctetString v = (ASN1OctetString) i.next();
            bos.write(v.getByteArray());
         }
         t.setByteArray(bos.toByteArray());
         bos.close();
      } catch (ClassCastException e) {
         throw new ASN1Exception("Type mismatch in BER encoded OCTET STRING segment!");
      }
   }


   public void readString(ASN1String t)
      throws IOException
   {
      match1(t);
      skipNext(true);

      if (primitive_) {
         super.readString(t);
         return;
      }
      /* String types are encoded always as if they were declared
       * [UNIVERSAL x] IMPLICIT OCTET STRING. BER decoding strings
       * thus is reduced to parsing the (potentially constructed)
       * encoding of an octet string.
       *
       * For this reason, we make the decoder believe that it
       * encountered an OCTET STRING and delegate decoding to
       * the appropriate method. Apart from the tag, all flags
       * and values such as length_ and indefinite_ are already
       * set correctly.
       */
      ASN1OctetString v = new ASN1OctetString();
      tag_ = ASN1.TAG_OCTETSTRING;
      tagclass_ = ASN1.CLASS_UNIVERSAL;

      v.decode(this);
      t.setString(t.convert(v.getByteArray()));
   }


   public void readCollection(ASN1Collection t)
      throws IOException
   {
      ASN1Type o;

      match0(t, false);

      int end = pos_ + length_;
      boolean vlen = indefinite_;
      Iterator i = t.iterator();
      int n = 0;

      /* The first loop is to check whether all types defined
       * in the collection are actually present in the
       * encoding. Mismatches caused by OPTIONAL elements of
       * the given collection are ignored. Exceptions are
       * triggered only if a length mismatch is detected.
       */
      while (i.hasNext()) {
         if (!readNext()) {
            break;
         }
         skipNext(true);
         o = (ASN1Type) i.next();
         n++;

         if (o.isType(tag_, tagclass_)) {
            o.decode(this);
            o.setOptional(false);

            if (vlen) continue;
            if (pos_ == end) break;
            if (pos_ > end) {
               throw new ASN1Exception("Length short by " + (pos_ - end) + " octets!");
            }
         } else {
            if (!o.isOptional()) {
               throw new ASN1Exception(
                  "ASN.1 type mismatch!" +
                  "\nExpected: " + o.getClass().getName() +
                  "\nIn      : " + t.getClass().getName() +
                  "\nAt index: " + (n - 1) +
                  "\nGot tag : " + tag_ + " and class: " + tagclass_
               );
            }
         }
      }
      /* The second loop checks for remaining elements in the
       * given collection, after the specified number of contents
       * octets are read or the end of the stream was reached.
       */
      while (i.hasNext()) {
         o = (ASN1Type) i.next();
         n++;

         if (!o.isOptional()) {
            throw new ASN1Exception(
               "ASN.1 type missing!" +
               "\nExpected: " + o.getClass().getName() +
               "\nIn      : " + t.getClass().getName() +
               "\nAt index: " + (n - 1)
            );
         }
      }
      /* If we decode definite length encodings then we have
       * to verify the number of contents octets read. If we
       * decode indefinite length encodings then we have to
       * check for the EOC.
       */
      if (vlen) {
         /* This should work fine because the current tag
          * in tag_ is invalidated if the end of stream is
          * reached. Hence, missing EOC cause a mismatch
          * exception even at the end of the stream.
          */
         match2(ASN1.TAG_EOC, ASN1.CLASS_UNIVERSAL);
      } else {
         if (pos_ < end) {
            throw new ASN1Exception("Bad length, " + (end - pos_) + " contents octets left!");
         }
      }
   }


   public void readCollectionOf(ASN1CollectionOf t)
      throws IOException
   {
      ASN1Type o;

      match0(t, false);

      t.clear();

      boolean vlen = indefinite_;
      int end = pos_ + length_;

      while (true) {
         if (!vlen) {
            if (pos_ == end) {
               return;
            }
            if (pos_ > end) {
               throw new ASN1Exception("Read " + (pos_ - end) + " octets too much!");
            }
         }
         if (!readNext()) {
            if (vlen)
               throw new ASN1Exception("EOC missing at EOF!");
            throw new ASN1Exception("Bad length!");
         }
         if (vlen && (tag_ == ASN1.TAG_EOC) && (tagclass_ == ASN1.CLASS_UNIVERSAL)) {
            return;
         }
         try {
            skipNext(true);
            o = t.newElement();
            o.decode(this);
         } catch (IllegalStateException e) {
            throw new ASN1Exception("Cannot create new element! ");
         }
      }
   }


   public void readTaggedType(ASN1TaggedType t)
      throws IOException
   {
      match1(t);

      boolean vlen = indefinite_;
      ASN1Type o = t.getInnerType();

      if (o.isExplicit() && primitive_) {
         throw new ASN1Exception("PRIMITIVE vs. CONSTRUCTED mismatch!");
      }
      /* A nasty trick to make the construction
       * [CLASS TAG] IMPLICIT OCTET STRING work
       * for types that are CONSTRUCTED.
       */
      if (t instanceof ASN1Opaque) {
         if (vlen) {
            throw new ASN1Exception("Cannot decode indefinite length encodings with ASN1Opaque type!");
         }
         primitive_ = true;
      }
      o.decode(this);

      /* If the length encoding is INDEFINITE and the
       * tagging is EXPLICIT then the contents octets
       * of the tagged type must be the complete encoding
       * of the inner type, including the EOC. Otherwise,
       * the contents octets must be the contents octets
       * of the inner type. In that case, the EOC is read
       * by the code that decodes the inner type (if the
       * inner type is CONSTRUCTED). See X.690 for details.
       */
      if (vlen && o.isExplicit()) {
         /* If the encoding is INDEFINITE LENGTH then
          * we have to eat an EOC at the end of the
          * encoding, in addition to the encoding of
          * the underlying type.
          */
         match2(ASN1.TAG_EOC, ASN1.CLASS_UNIVERSAL);
      }
   }
}
