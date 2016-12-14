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
) where

import           Control.DeepSeq (NFData(rnf), ($!!))
import           Crypto.Hash
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BS
import           Data.Int
import           Data.Word
import           Data.Complex
import           Data.Maybe (fromJust)
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax
import           System.IO.Unsafe
import           Foreign.Marshal.Utils (with)
import           Foreign.C.Types
import           Foreign.Ptr (castPtr)
import           Foreign.Storable (Storable, sizeOf)

newtype Fingerprint = FP { unFP :: Digest SHA1 }
  deriving (Eq, Ord, Show, NFData)

data WithFingerprint a = WithFingerprint Fingerprint a
  deriving (Eq, Ord, Show)

instance NFData a => NFData (WithFingerprint a) where
  rnf (WithFingerprint f a) = rnf f `seq` rnf a

class HasFingerprint o where
  fingerprint :: o -> Fingerprint
  default fingerprint :: Storable o => o -> Fingerprint
  fingerprint o = unsafeDupablePerformIO $ with o $ \oPtr -> do
    x <- fingerprint <$> BS.unsafePackCStringLen (castPtr oPtr, sizeOf (undefined :: o))
    return $!! x
  {-# INLINE fingerprint #-}


instance HasFingerprint (WithFingerprint a) where
  fingerprint (WithFingerprint f _) = f
  {-# INLINE fingerprint #-}

instance HasFingerprint Fingerprint where
  fingerprint = id
  {-# INLINE fingerprint #-}

instance HasFingerprint BS.ByteString where
  fingerprint = FP . hash
  {-# INLINE fingerprint #-}

instance Monoid Fingerprint where
  mempty = FP (hashFinalize hashInit)
  {-# INLINE mempty #-}
  mappend (FP a) (FP b) = FP . hashFinalize $ hashUpdates hashInit [a, b]
  {-# INLINE mappend #-}
  mconcat = FP . hashFinalize . hashUpdates hashInit . map unFP
  {-# INLINE mconcat #-}

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
  lift (FP h) =
    return $ ConE 'FP 
      `AppE` (VarE 'fromJust 
      `AppE` (VarE 'digestFromByteString 
      `AppE` (VarE 'unsafeDupablePerformIO 
      `AppE` (VarE 'BS.unsafePackAddressLen
      `AppE` LitE (IntegerL $ fromIntegral $ BS.length bs)
      `AppE` LitE (StringPrimL (B.unpack bs))))))
    where bs = unsafeDupablePerformIO (BA.withByteArray h (BS.packCStringLen . (,BA.length h)))

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
