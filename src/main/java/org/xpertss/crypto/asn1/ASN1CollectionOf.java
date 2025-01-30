package org.xpertss.crypto.asn1;


/**
 * The basic interface for Java objects representing
 * a constructed ASN.1 type such as a SEQUENCE or SET
 * as specified in ITU-T Recommendation X.680.
 */
public interface ASN1CollectionOf extends ASN1Collection {

   /**
    * Returns the Java class representing the ASN.1 type
    * of the elements in this collection.
    *
    * @return The ASN.1 type of the elements in this collection.
    */
   public Class getElementType();


   /**
    * Creates and returns a new instance of the class
    * passed to the constructor of this instance. The
    * freshly created instance is added to this
    * instance automatically.<p>
    *
    * If no new instance can be created then an
    * IllegalStateException is thrown.<p>
    *
    * <b>{@link Decoder Decoders} should call this
    * method in order to create additional elements
    * on decoding.</b> Subclasses may use this
    * method to keep track on elements added to
    * them.
    *
    * @return A new instance of the element type of
    *   this sequence.
    * @exception IllegalStateException if no new
    *   instance could be created.
    */
   public ASN1Type newElement();


}
