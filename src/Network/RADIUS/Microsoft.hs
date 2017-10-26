{-# LANGUAGE RecordWildCards #-}
module Network.RADIUS.Microsoft where

import Prelude hiding (zipWith)
import Crypto.Hash.Algorithms    (MD5)
import Crypto.Hash               (Digest, hash)
import Data.Binary.Put           (Put, putByteString, putWord8, putWord16be, runPut)
import Data.Bits                 ((.|.), xor)
import Data.ByteArray            (convert)
import Data.ByteString.Builder   (toLazyByteString, byteStringHex)
import Data.ByteString           (ByteString, pack, zipWith)
import Data.ByteString.Internal  (c2w, w2c)
import Data.Char                 (toUpper)
import Data.Monoid               ((<>))
import Data.Word                 (Word8, Word16)
import Network.RADIUS.Types

import qualified Data.ByteString.Lazy.Char8 as LB
import qualified Data.ByteString.Char8      as B

encodeMPPPESendKeyAttribute :: Word16
                            -> ByteString
                            -> ByteString
                            -> ByteString
                            -> PacketAttribute
encodeMPPPESendKeyAttribute salt key ntHash authenticator =
    let str = runPut $ encodeMPPEKeyAttribute 16 salt key ntHash authenticator
    in VendorSpecificAttribute 26 str

encodeMPPPERecvKeyAttribute :: Word16
                            -> ByteString
                            -> ByteString
                            -> ByteString
                            -> PacketAttribute
encodeMPPPERecvKeyAttribute salt key ntHash authenticator =
    let str = runPut $ encodeMPPEKeyAttribute 17 salt key ntHash authenticator
    in VendorSpecificAttribute 26 str

encodeMPPEKeyAttribute :: Word8
                       -> Word16
                       -> ByteString
                       -> ByteString
                       -> ByteString
                       -> Put
encodeMPPEKeyAttribute vendorType salt key ntHash authenticator = do
  putWord8 vendorType
  let salt'     = LB.toStrict . runPut . putWord16be $ salt .|. 0x8000 -- MSB in salt *must* be set
      keyLength = w2c .fromIntegral $ B.length key
      key'      = fmap toUpper . LB.unpack . toLazyByteString . byteStringHex $ key
      str       = keyLength : key'
      n         = length str `mod` 16
      m         = if n == 0 then 0 else 16 - n
      str'      = str ++ replicate m '\NUL'
      result    = foldl encrypt (authenticator <> salt') $ partition 16 str'
      vendorLen = fromIntegral $ 4 + B.length result
  putWord8 vendorLen
  putByteString result
      where md5                  = convert . (hash :: ByteString -> Digest MD5)
            partition n          = partition' [] n
            partition' acc _ []  = reverse acc
            partition' acc n str =
                let (x, xs) = splitAt n str
                in partition' ((pack . fmap c2w $ x):acc) n xs
            encrypt bytes chunk  = pack $ zipWith xor chunk (md5 $ ntHash <> bytes)
