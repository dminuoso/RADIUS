{-# LANGUAGE RecordWildCards #-}
module Network.RADIUS.Encoding where

import Control.Monad               (when)
import Data.Binary                 (Binary(..), encode, decode)
import Data.Binary.Put             (Put, putLazyByteString, putWord8, putWord16be)
import Data.Binary.Get             (Get, getLazyByteString, getWord8, getWord16be, isEmpty)
import Data.ByteString.Lazy.Char8  (ByteString)
import Data.Int                    (Int64)
import Data.Word                   (Word8, Word16)
import Network.RADIUS.Types

import qualified Data.ByteString.Lazy.Char8 as B

radiusHeaderSize :: Word16
radiusHeaderSize = 20

authenticatorLength :: Int64
authenticatorLength = 16

instance Binary Packet where
    put Packet{..}   = do
      let iD         = fromIntegral getPacketId
          authLen    = B.length getPacketAuthenticator
          attributes = encodeAttributes getPacketAttributes
          attrsLen   = fromIntegral . B.length $ attributes
      when (B.length getPacketAuthenticator /= authenticatorLength) $
           fail $ "RADIUS.Encoding: Invalid Authenticator length " ++ show authLen
      put getPacketType
      putWord8 iD
      putWord16be $ attrsLen + radiusHeaderSize
      putLazyByteString getPacketAuthenticator
      putLazyByteString attributes
    get = do
      packetType     <- get
      iD             <- getWord8
      packetLength   <- getWord16be
      authenticator  <- getLazyByteString authenticatorLength
      let attrsLength = fromIntegral packetLength - fromIntegral radiusHeaderSize
      attributesData <- getLazyByteString attrsLength
      attributes     <- decodeAttributes []
      return Packet { getPacketType          = packetType,
                      getPacketId            = iD,
                      getPacketAuthenticator = authenticator,
                      getPacketAttributes    = attributes }

instance Binary PacketType where
    put = putWord8 . fromIntegral . fromEnum
    get = getWord8 >>= return . toEnum . fromIntegral

encodeAttributes :: [PacketAttribute] -> ByteString
encodeAttributes = B.concat . fmap encode

decodeAttributes :: [PacketAttribute] -> Get [PacketAttribute]
decodeAttributes acc = do
  done <- isEmpty
  if done
    then return . reverse $ acc
    else do
      attribute <- get
      decodeAttributes $ attribute : acc

instance Binary PacketAttribute where
    put (UserNameAttribute str)            = putAttributeStr   1 str
    put (UserPasswordAttribute str)        = putAttributeStr   2 str
    put (CHAPPassword str)                 = putAttributeStr   3 str -- fix me
    put (FramedIPv6Route str)              = putAttributeStr  99 str
    put (FramedIPv6Pool str)               = putAttributeStr 100 str
    put (FilterIdAttribute str)            = putAttributeStr  11 str
    put (ReplyMessageAttribute str)        = putAttributeStr  18 str
    put (CallbackNumberAttribute str)      = putAttributeStr  19 str
    put (CallbackIdAttribute str)          = putAttributeStr  20 str
    put (FramedRouteAttribute str)         = putAttributeStr  22 str
    put (StateAttribute str)               = putAttributeStr  24 str
    put (ClassAttribute str)               = putAttributeStr  25 str
    put (CalledStationIdAttribute str)     = putAttributeStr  30 str
    put (CallingStationIdAttribute str)    = putAttributeStr  31 str
    put (NASIdentifierAttribute str)       = putAttributeStr  32 str
    put (ProxyStateAttribute str)          = putAttributeStr  33 str
    put (LoginLATServiceAttribute str)     = putAttributeStr  34 str
    put (LoginLATNodeAttribute str)        = putAttributeStr  35 str
    put (LoginLATGroupAttribute str)       = putAttributeStr  36 str
    put (FramedAppleTalkZoneAttribute str) = putAttributeStr  39 str
    put (CHAPChallengeAttribute str)       = putAttributeStr  60 str
    put (LoginLATPortAttribute str)        = putAttributeStr  63 str

putAttributeStr :: Word8 -> ByteString -> Put
putAttributeStr code str = do
    putWord8 code
    putWord8 . fromIntegral $ B.length str
    putLazyByteString str
