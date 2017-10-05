{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.RADIUS.Encoding where

import Control.Monad               (when)
import Data.Binary                 (Binary(..), encode)
import Data.Binary.Put             (Put, putLazyByteString, putWord8, putWord16be, putWord32be)
import Data.Binary.Get             (Get, getLazyByteString, getWord8, getWord16be, isEmpty)
import Data.ByteString.Lazy.Char8  (ByteString)
import Data.IP                     (IPv4, IPv6)
import Data.Int                    (Int64)
import Data.Word                   (Word8, Word16, Word32)
import Network.RADIUS.Types
import Debug.Trace

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
      _packetLength  <- getWord16be
      authenticator  <- getLazyByteString authenticatorLength
      attributes     <- decodeAttributes []
      return Packet { getPacketType          = packetType,
                      getPacketId            = iD,
                      getPacketAuthenticator = authenticator,
                      getPacketAttributes    = attributes }

instance Binary PacketType where
    put = putEnum
    get = getEnum

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

instance Binary IPv4
instance Binary IPv6

instance Binary PacketAttribute where
    put (UserNameAttribute str)                 = putAttributeStr   1 str
    put (UserPasswordAttribute str)             = putAttributeStr   2 str
    put (FramedIPv6Route str)                   = putAttributeStr  99 str
    put (FramedIPv6Pool str)                    = putAttributeStr 100 str
    put (FilterIdAttribute str)                 = putAttributeStr  11 str
    put (ReplyMessageAttribute str)             = putAttributeStr  18 str
    put (CallbackNumberAttribute str)           = putAttributeStr  19 str
    put (CallbackIdAttribute str)               = putAttributeStr  20 str
    put (FramedRouteAttribute str)              = putAttributeStr  22 str
    put (StateAttribute str)                    = putAttributeStr  24 str
    put (ClassAttribute str)                    = putAttributeStr  25 str
    put (CalledStationIdAttribute str)          = putAttributeStr  30 str
    put (CallingStationIdAttribute str)         = putAttributeStr  31 str
    put (NASIdentifierAttribute str)            = putAttributeStr  32 str
    put (ProxyStateAttribute str)               = putAttributeStr  33 str
    put (LoginLATServiceAttribute str)          = putAttributeStr  34 str
    put (LoginLATNodeAttribute str)             = putAttributeStr  35 str
    put (LoginLATGroupAttribute str)            = putAttributeStr  36 str
    put (FramedAppleTalkZoneAttribute str)      = putAttributeStr  39 str
    put (CHAPChallengeAttribute str)            = putAttributeStr  60 str
    put (LoginLATPortAttribute str)             = putAttributeStr  63 str
    put (ARAPPasswordAttribute str)             = putAttributeStr  70 str
    put (ARAPFeaturesAttribute str)             = putAttributeStr  71 str
    put (ARAPSecurityDataAttribute str)         = putAttributeStr  74 str
    put (ConnectInfoAttribute str)              = putAttributeStr  77 str
    put (ConfigurationTokenAttribute str)       = putAttributeStr  78 str
    put (EAPMessageAttribute str)               = putAttributeStr  79 str
    put (MessageAuthenticatorAttribute str)     = putAttributeStr  80 str
    put (ARAPChallengeResponseAttribute str)    = putAttributeStr  84 str
    put (NASPortIdAttribute str)                = putAttributeStr  87 str
    put (FramedPoolAttribute str)               = putAttributeStr  88 str
    put (NASPortAttribute value)                = putAttribute      5 value
    put (FramedMTUAttribute value)              = putAttribute     12 value
    put (LoginTCPPortAttribute value)           = putAttribute     16 value
    put (FramedIPXNetworkAttribute value)       = putAttribute     23 value
    put (SessionTimeoutAttribute value)         = putAttribute     27 value
    put (IdleTimeoutAttribute value)            = putAttribute     28 value
    put (FramedAppleTalkLinkAttribute value)    = putAttribute     37 value
    put (FramedAppleTalkNetworkAttribute value) = putAttribute     38 value
    put (PortLimitAttribute value)              = putAttribute     62 value
    put (NASIPAddress value)                    = putAttribute      4 value
    put (NASIPv6Address value)                  = putAttribute     95 value
    put (ServiceTypeAttribute value)            = putAttribute      6 value
    put (FramedProtocolAttribute value)         = putAttribute      7 value
    put (FramedIPAddressAttribute value)        = putAttribute      8 value
    put (FramedIPNetmaskAttribute value)        = putAttribute      9 value
    put (FramedRoutingAttribute value)          = putAttribute     10 value
    put (FramedCompressionAttribute value)      = putAttribute     13 value
    put (FramedInterfaceIdAttribute value)      = putAttribute     96 value
    put (LoginIPHostAttribute value)            = putAttribute     14 value
    put (LoginIPv6HostAttribute value)          = putAttribute     98 value
    put (LoginServiceAttribute value)           = putAttribute     15 value
    put (TerminationActionAttribute value)      = putAttribute     29 value
    put (NASPortTypeAttribute value)            = putAttribute     61 value
    put (AccountInputGigawordsAttribute value)  = putAttribute     52 value
    put (AccountOutputGigawordsAttribute value) = putAttribute     53 value
    put (EventTimeStampAttribute value)         = putAttribute     55 value
    put (ARAPZoneAccessAttribute value)         = putAttribute     72 value
    put (ARAPSecurityAttribute value)           = putAttribute     73 value
    put (PasswordRetryAttribute value)          = putAttribute     75 value
    put (PromptAttribute value)                 = putAttribute     76 value
    put (AcctInterimIntervalAttribute value)    = putAttribute     85 value
    put (FramedIPv6Prefix prefixLength prefix) = do
      let attr    = encode prefix
          attrLen = 4 + (fromIntegral . B.length $ attr)
      putWord8 97 -- Attribute type
      putWord8 attrLen
      putWord8 0  -- reserved
      putWord8 $ fromIntegral prefixLength
      putLazyByteString attr
    put (VendorSpecificAttribute iD str) = do
      let attrLen = (fromIntegral . B.length $ str) + 6 -- Attribute header length + string
      putWord8 26 -- Attribute Type
      putWord8 attrLen
      put iD
      putLazyByteString str
    put (CHAPPassword identity str)           = do
      let attrLen = (fromIntegral . B.length $ str) + 3 -- Attribute header plus string
      when (attrLen /= 19) $ fail $ "Invalid RADIUS CHAP Password length " ++ show attrLen
      putWord8 3 -- Attribute Type
      putWord8 attrLen
      putWord8 identity
      putLazyByteString str

    get = do
      code <- getWord8
      traceM $ "decode attr " ++ show code
      getAttribute code

putAttributeStr :: Word8 -> ByteString -> Put
putAttributeStr code str = do
    putWord8 code
    putWord8 $ (fromIntegral . B.length $ str) + 2 -- attr length + code + len octets
    putLazyByteString str

putAttribute :: (Binary a) => Word8 -> a -> Put
putAttribute code attribute = do
    let attrData = encode attribute
        attrLen  = (fromIntegral . B.length $ attrData) + 2 -- attr length + code + len octets
    putWord8 code
    putWord8 attrLen
    putLazyByteString attrData

getAttribute :: Word8 -> Get PacketAttribute
getAttribute   1 = getAttributeStr >>= return . UserNameAttribute
getAttribute   2 = getAttributeStr >>= return . UserPasswordAttribute
getAttribute  99 = getAttributeStr >>= return . FramedIPv6Route
getAttribute 100 = getAttributeStr >>= return . FramedIPv6Pool
getAttribute  11 = getAttributeStr >>= return . FilterIdAttribute
getAttribute  18 = getAttributeStr >>= return . ReplyMessageAttribute
getAttribute  19 = getAttributeStr >>= return . CallbackNumberAttribute
getAttribute  20 = getAttributeStr >>= return . CallbackIdAttribute
getAttribute  22 = getAttributeStr >>= return . FramedRouteAttribute
getAttribute  24 = getAttributeStr >>= return . StateAttribute
getAttribute  25 = getAttributeStr >>= return . ClassAttribute
getAttribute  30 = getAttributeStr >>= return . CalledStationIdAttribute
getAttribute  31 = getAttributeStr >>= return . CallingStationIdAttribute
getAttribute  32 = getAttributeStr >>= return . NASIdentifierAttribute
getAttribute  33 = getAttributeStr >>= return . ProxyStateAttribute
getAttribute  34 = getAttributeStr >>= return . LoginLATServiceAttribute
getAttribute  35 = getAttributeStr >>= return . LoginLATNodeAttribute
getAttribute  36 = getAttributeStr >>= return . LoginLATGroupAttribute
getAttribute  39 = getAttributeStr >>= return . FramedAppleTalkZoneAttribute
getAttribute  60 = getAttributeStr >>= return . CHAPChallengeAttribute
getAttribute  63 = getAttributeStr >>= return . LoginLATPortAttribute
getAttribute  70 = getAttributeStr >>= return . ARAPPasswordAttribute
getAttribute  71 = getAttributeStr >>= return . ARAPFeaturesAttribute
getAttribute  74 = getAttributeStr >>= return . ARAPSecurityDataAttribute
getAttribute  77 = getAttributeStr >>= return . ConnectInfoAttribute
getAttribute  78 = getAttributeStr >>= return . ConfigurationTokenAttribute
getAttribute  79 = getAttributeStr >>= return . EAPMessageAttribute
getAttribute  80 = getAttributeStr >>= return . MessageAuthenticatorAttribute
getAttribute  84 = getAttributeStr >>= return . ARAPChallengeResponseAttribute
getAttribute  87 = getAttributeStr >>= return . NASPortIdAttribute
getAttribute  88 = getAttributeStr >>= return . FramedPoolAttribute
getAttribute 5  = getAttributeValue >>= return . NASPortAttribute
getAttribute 12 = getAttributeValue >>= return . FramedMTUAttribute
getAttribute 16 = getAttributeValue >>= return . LoginTCPPortAttribute
getAttribute 23 = getAttributeValue >>= return . FramedIPXNetworkAttribute
getAttribute 27 = getAttributeValue >>= return . SessionTimeoutAttribute
getAttribute 28 = getAttributeValue >>= return . IdleTimeoutAttribute
getAttribute 37 = getAttributeValue >>= return . FramedAppleTalkLinkAttribute
getAttribute 38 = getAttributeValue >>= return . FramedAppleTalkNetworkAttribute
getAttribute 62 = getAttributeValue >>= return . PortLimitAttribute
getAttribute 4  = getAttributeValue >>= return . NASIPAddress
getAttribute 95 = getAttributeValue >>= return . NASIPv6Address
getAttribute 6  = getAttributeValue >>= return . ServiceTypeAttribute . fromEnum32
getAttribute 7  = getAttributeValue >>= return . FramedProtocolAttribute . fromEnum32
getAttribute 8  = getAttributeValue >>= return . FramedIPAddressAttribute
getAttribute 9  = getAttributeValue >>= return . FramedIPNetmaskAttribute
getAttribute 10 = getAttributeValue >>= return . FramedRoutingAttribute . fromEnum32
getAttribute 13 = getAttributeValue >>= return . FramedCompressionAttribute . fromEnum32
getAttribute 96 = getAttributeValue >>= return . FramedInterfaceIdAttribute
getAttribute 14 = getAttributeValue >>= return . LoginIPHostAttribute
getAttribute 98 = getAttributeValue >>= return . LoginIPv6HostAttribute
getAttribute 15 = getAttributeValue >>= return . LoginServiceAttribute . fromEnum32
getAttribute 29 = getAttributeValue >>= return . TerminationActionAttribute . fromEnum32
getAttribute 61 = getAttributeValue >>= return . NASPortTypeAttribute . fromEnum32
getAttribute 52 = getAttributeValue >>= return . AccountInputGigawordsAttribute
getAttribute 53 = getAttributeValue >>= return . AccountOutputGigawordsAttribute
getAttribute 55 = getAttributeValue >>= return . EventTimeStampAttribute
getAttribute 72 = getAttributeValue >>= return . ARAPZoneAccessAttribute . fromEnum32
getAttribute 73 = getAttributeValue >>= return . ARAPSecurityAttribute
getAttribute 75 = getAttributeValue >>= return . PasswordRetryAttribute
getAttribute 76 = getAttributeValue >>= return . PromptAttribute
getAttribute 85 = getAttributeValue >>= return . AcctInterimIntervalAttribute
getAttribute 97 = do
  attrLen      <- getWord8
  _reserved    <- getWord8
  prefixLength <- getWord8
  when (attrLen /= 20) $ fail $ "Unsupported RADIUS Framed IPv6 Prefix attribute length "
           ++ show attrLen
  prefix <- get
  return $ FramedIPv6Prefix (fromIntegral prefixLength) prefix
getAttribute 26 = do
  attrLen  <- getWord8
  iD       <- get
  attrData <- getLazyByteString . fromIntegral $ attrLen - 6
  return $ VendorSpecificAttribute iD attrData
getAttribute 3 = do
  attrLen  <- getWord8
  when (attrLen /= 19) $ fail $ "Invalid RADIUS CHAP Password length " ++ show attrLen
  identity <- getWord8
  attrData <- getLazyByteString 16 -- CHAP response is always 16 octets
  return $ CHAPPassword identity attrData
getAttribute n  = fail $ "Unknown RADIUS attribute type " ++ show n

getAttributeStr :: Get ByteString
getAttributeStr = getWord8 >>= getLazyByteString . fromIntegral . (subtract 2) -- minus type + len

getAttributeValue :: (Binary a) => Get a
getAttributeValue = getWord8 >> get

instance Binary ServiceType where
    put = putEnum
    get = getEnum

instance Binary FramedProtocol where
    put = putEnum
    get = getEnum

instance Binary FramedRouting where
    put = putEnum
    get = getEnum

instance Binary FramedCompression where
    put = putEnum
    get = getEnum

instance Binary LoginService where
    put = putEnum
    get = getEnum

instance Binary TerminationAction where
    put = putEnum
    get = getEnum

instance Binary NASPortType where
    put = putEnum
    get = getEnum

instance Binary ARAPZoneAccess where
    put = putEnum
    get = getEnum

putEnum :: (Enum a) => a -> Put
putEnum = putWord32be . fromIntegral . fromEnum

getEnum :: (Enum a) => Get a
getEnum = getWord8 >>= return . toEnum . fromIntegral

fromEnum32 :: (Enum a) => Word32 -> a
fromEnum32 = toEnum . fromIntegral