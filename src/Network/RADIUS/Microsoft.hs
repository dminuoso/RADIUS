{-# LANGUAGE RecordWildCards #-}
module Network.RADIUS.Microsoft where

import Prelude hiding (zipWith)
import Crypto.Hash.Algorithms    (MD5)
import Crypto.Hash               (Digest, hash)
import Data.Binary.Put           (Put, putByteString, putWord8, putWord16be, runPut, putWord32be)
import Data.Bits                 ((.|.), xor)
import Data.ByteArray            (convert)
import Data.ByteString.Builder   (toLazyByteString, byteStringHex)
import Data.ByteString           (ByteString, pack, zipWith)
import Data.ByteString.Internal  (c2w)
import Data.Char                 (toUpper)
import Data.Monoid               ((<>))
import Data.Word                 (Word8, Word16, Word32)
import Network.RADIUS.Types

import qualified Data.ByteString.Lazy.Char8 as LB
import qualified Data.ByteString.Char8      as B

vendorSpecificAttribute :: LB.ByteString -> PacketAttribute
vendorSpecificAttribute =
    VendorSpecificAttribute 311 -- Microsoft SMI Network Management Enterprise Code

encodeMPPESendKeyAttribute :: Word16
                            -> ByteString
                            -> ByteString
                            -> ByteString
                            -> PacketAttribute
encodeMPPESendKeyAttribute salt key ntHash authenticator =
    vendorSpecificAttribute . runPut $ encodeMPPEKeyAttribute 16 salt key ntHash authenticator

encodeMPPERecvKeyAttribute :: Word16
                            -> ByteString
                            -> ByteString
                            -> ByteString
                            -> PacketAttribute
encodeMPPERecvKeyAttribute salt key ntHash authenticator =
    vendorSpecificAttribute . runPut $ encodeMPPEKeyAttribute 17 salt key ntHash authenticator

encodeMPPEKeyAttribute :: Word8
                       -> Word16
                       -> ByteString
                       -> ByteString
                       -> ByteString
                       -> Put
encodeMPPEKeyAttribute vendorType salt key ntHash authenticator = do
  putWord8 vendorType
  let salt'     = LB.toStrict . runPut . putWord16be $ salt .|. 0x8000 -- MSB in salt *must* be set
      keyLength = show $ B.length key
      key'      = fmap toUpper . LB.unpack . toLazyByteString . byteStringHex $ key
      str       = keyLength ++ key'
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

encodeMPPEEncryptionPolicyAttribute :: Word32 -> PacketAttribute
encodeMPPEEncryptionPolicyAttribute policy =
    vendorSpecificAttribute . runPut $ do
      putWord8 7 -- for MS-MPPE-Encryption-Policy.
      putWord8 6 -- fixed length
      putWord32be policy

encodeMPPEEncryptionTypesAttribute :: Word32 -> PacketAttribute
encodeMPPEEncryptionTypesAttribute types =
    vendorSpecificAttribute . runPut $ do
      putWord8 8 -- for MS-MPPE-Encryption-Types.
      putWord8 6 -- fixed length
      putWord32be types
