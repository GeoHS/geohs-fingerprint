{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
module Data.Fingerprint (
  Fingerprint (..)
, WithFingerprint (..)
, HasFingerprint (..)
, fp
, fromByteString
, toByteString
, fromByteString16
, toByteString16
, sinkFingerprint
) where

import           Control.DeepSeq (NFData(rnf), ($!!))
import           Crypto.Hash
import           Crypto.Hash.Conduit (sinkHash)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BS
import           Data.Int
import           Data.Word
import           Data.Complex
import           Data.Conduit (Consumer)
import           Data.Maybe (fromJust)
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax
import           System.IO.Unsafe
import           Foreign.Marshal.Utils (with)
import           Foreign.C.Types
import           Foreign.Ptr (castPtr)
import           Foreign.Storable (Storable, sizeOf)

newtype Fingerprint = FP { unFP :: Digest SHA256 }
  deriving (Eq, Ord, NFData)

instance Show Fingerprint where show = show . unFP

data WithFingerprint a = WithFingerprint Fingerprint a
  deriving (Eq, Ord, Show)

instance NFData a => NFData (WithFingerprint a) where
  rnf (WithFingerprint f a) = rnf f `seq` rnf a

fromByteString :: BS.ByteString -> Maybe Fingerprint
fromByteString = fmap FP . digestFromByteString

toByteString :: Fingerprint -> BS.ByteString
toByteString (FP h) = unsafeDupablePerformIO $
  BA.withByteArray h (BS.packCStringLen . (,BA.length h))

fromByteString16 :: BS.ByteString -> Maybe Fingerprint
fromByteString16 b16 =
  case B16.decode b16 of
    (bs,bad) | B.null bad -> fromByteString bs
    _                     -> Nothing

toByteString16 :: Fingerprint -> BS.ByteString
toByteString16 = B16.encode . toByteString

sinkFingerprint :: Monad m => Consumer BS.ByteString m Fingerprint
sinkFingerprint = fmap FP sinkHash

class HasFingerprint o where
  fingerprint :: o -> Fingerprint
  default fingerprint :: Storable o => o -> Fingerprint
  fingerprint o = unsafeDupablePerformIO $ with o $ \oPtr -> do
    x <- fingerprint <$> BS.unsafePackCStringLen (castPtr oPtr, sizeOf (undefined :: o))
    return $!! x
  {-# INLINE fingerprint #-}


instance Monoid Fingerprint where
  mempty = FP (hashFinalize hashInit)
  {-# INLINE mempty #-}
  mappend (FP a) (FP b) = FP . hashFinalize $ hashUpdates hashInit [a, b]
  {-# INLINE mappend #-}
  mconcat = FP . hashFinalize . hashUpdates hashInit . map unFP
  {-# INLINE mconcat #-}

instance {-# OVERLAPPABLE #-} (Foldable f, HasFingerprint o) => HasFingerprint (f o) where
  fingerprint = foldMap fingerprint
  {-# INLINE fingerprint #-}

fp ::QuasiQuoter
fp = QuasiQuoter
  { quoteExp = \s -> do
      loc <- location
      let h = fingerprint . BS.pack
            $ concatMap ($ loc) [loc_package, loc_module, show . loc_start, const s]
      [e|WithFingerprint h|]
  , quotePat = const (fail "Cannot apply fp quasiquoter in patterns")
  , quoteType = const (fail "Cannot apply fp quasiquoter in types")
  , quoteDec  = const (fail "Cannot apply fp quasiquoter in declarations")
  }

instance Lift Fingerprint where
  lift fp_ =
    return $ ConE 'FP 
      `AppE` (VarE 'fromJust 
      `AppE` (VarE 'digestFromByteString 
      `AppE` (VarE 'unsafeDupablePerformIO 
      `AppE` (VarE 'BS.unsafePackAddressLen
      `AppE` LitE (IntegerL $ fromIntegral $ BS.length bs)
      `AppE` LitE (StringPrimL (B.unpack bs))))))
    where bs = toByteString fp_

instance HasFingerprint (WithFingerprint a) where
  fingerprint (WithFingerprint f _) = f
  {-# INLINE fingerprint #-}

instance HasFingerprint Fingerprint where
  fingerprint = id
  {-# INLINE fingerprint #-}

instance HasFingerprint BS.ByteString where
  fingerprint = FP . hash
  {-# INLINE fingerprint #-}

instance HasFingerprint String where
  fingerprint = fingerprint . BS.pack
  {-# INLINE fingerprint #-}

instance HasFingerprint ()
instance HasFingerprint Word8
instance HasFingerprint Word16
instance HasFingerprint Word32
instance HasFingerprint Word64
instance HasFingerprint Int8
instance HasFingerprint Int16
instance HasFingerprint Int32
instance HasFingerprint Int64
instance HasFingerprint Int
instance HasFingerprint Float
instance HasFingerprint Double
instance HasFingerprint CInt
instance HasFingerprint CChar
instance HasFingerprint CShort
instance HasFingerprint CLong
instance HasFingerprint CLLong
instance HasFingerprint CUInt
instance HasFingerprint CUChar
instance HasFingerprint CUShort
instance HasFingerprint CULong
instance HasFingerprint CULLong
instance HasFingerprint CFloat
instance HasFingerprint CDouble
instance HasFingerprint (Complex Int)
instance HasFingerprint (Complex Int32)
instance HasFingerprint (Complex Int16)
instance HasFingerprint (Complex Float)
instance HasFingerprint (Complex Double)
