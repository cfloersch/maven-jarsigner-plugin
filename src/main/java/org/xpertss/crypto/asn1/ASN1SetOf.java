package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * Represents an ASN.1 SEQUENCE OF type as specified in ITU-T
 * Recommendation X.680. The SequenceOf and SetOf types do
 * not have default constructors in contrast to all the other
 * ASN1Types. The reason is that these types are never
 * created directly on decoding ASN.1 structures. The decoding
 * process always decodes Sequence and Set types because
 * creating the appropriate SequenceOf or SetOf type requires
 * explicit knowledge of the syntactic structure definition.
 * On the other hand, if an explicit structure is given for
 * decoding then the SequenceOf and SetOf types are decoded
 * properly (because they do not have to be created and hence
 * the decoder need not know the component type).<p>
 *
 * This implementation does not sort the elements according
 * to their encodings as required (in principle) by the
 * standard. Upon decoding, all decoded elements are kept
 * in the order they appeared in the encoded stream.<p>
 *
 * Constraints are checked after decoding instances of this type.
 */
public class ASN1SetOf extends ASN1Set implements ASN1CollectionOf {
   /**
    * The {@link ASN1Type ASN1Type} from which the
    * component types of this collection are created.
    */
   private Resolver resolver_;


   /**
    * Creates an instance with the given capacity. This
    * constructor is provided for subclasses that wish
    * to handle creation of new elements themselves and
    * do not rely on an application-provided element
    * type.
    *
    * @param capacity The initial capacity of the set.
    */
   protected ASN1SetOf(int capacity)
   {
      super(capacity);
   }


   /**
    * Creates an instance that keeps elements of the given type. The type must be a valid
    * {@link ASN1Type ASN1Type}. The given class must be public and it must have a public
    * default constructor.
    *
    * @param type The class that represents the component type of this SET OF.
    * @exception IllegalArgumentException if the given class does not implement ASN1Type.
    * @exception NullPointerException if <code>type</code> is <code>null</code>.
    */
   public ASN1SetOf(Class type)
   {
      if (type == null)
         throw new NullPointerException("Need a class!");

      resolver_ = new ClassInstanceResolver(type);
   }


   /**
    * Creates an instance with the given capacity.
    *
    * @param capacity The capacity.
    */
   public ASN1SetOf(Class type, int capacity)
   {
      super(capacity);

      if (type == null)
         throw new NullPointerException("Need a class!");

      resolver_ = new ClassInstanceResolver(type);
   }


   /**
    * Creates an instance that uses the given {@link Resolver
    * Resolver} to create new elements.
    *
    * @param resolver The resolver to use for generating
    *   elements.
    */
   public ASN1SetOf(Resolver resolver)
   {
      if (resolver == null)
         throw new NullPointerException("Need a resolver!");
      resolver_ = resolver;
   }


   /**
    * Returns the Java class representing the ASN.1 type of the elements in this
    * collection or <code>ASN1Type.class</code> if the type cannot be determined.
    *
    * @return The ASN.1 type of the elements in this collection.
    */
   public Class getElementType()
   {
      if (resolver_ instanceof ClassInstanceResolver) {
         return ((ClassInstanceResolver) resolver_).getFactoryClass();
      }
      return ASN1Type.class;
   }


   /**
    * Creates and returns a new instance of the element type of this instance. The
    * freshly created instance is added to this instance automatically.
    * <p>
    * New instances are created by invoking the <code>Resolver</code> instance set
    * in this instance.
    * <p>
    * If no new instance can be created then an IllegalStateException is thrown.
    * <p>
    * <b>{@link Decoder Decoders} should call this method in order to create
    * additional elements on decoding.</b> Subclasses may use this method to keep
    * track on elements added to them.
    *
    * @return A new instance of the element type of this set.
    * @exception IllegalStateException if no new instance could be created.
    */
   public ASN1Type newElement()
   {
      try {
         ASN1Type o = resolver_.resolve(this);
         add(o);
         return o;
      } catch (Exception e) {
         throw new IllegalStateException("Caught " + e.getClass().getName() + "(\"" + e.getMessage() + "\")");
      }
   }


   /**
    * Reads this collection from the given decoder.
    *
    * @param dec - The decoder to read from.
    */
   public void decode(Decoder dec)
      throws IOException
   {
      dec.readCollectionOf(this);
      checkConstraints();
   }
}







