{-# LANGUAGE DeriveDataTypeable #-}
{-|
Module      : Network.RADIUS.Types
Description : Provides types and definitions for RADIUS as per RFC 2865
Copyright   : (c) Erick Gonzalez, 2017
License     : BSD3
Maintainer  : erick@codemonkeylabs.de
Stability   : experimental
Portability : POSIX

This module compiles the RADIUS packet definitions and different attributes as specified in
RFC 2865. The naming conventions from the RFC have been preserved as much as possible, so
it should be straightforward to look up a particular element and understand what it means etc.

RADIUS extensions in RFC 2869 are also supported, as well as RFC 3162 for IPv6 related attributes

-}
module Network.RADIUS.Types where

import Data.ByteString.Char8         (ByteString)
import Data.Data                     (Data)
import Data.Word                     (Word8, Word16, Word32, Word64)
import Data.IP                       (IPv4, IPv6)
import Data.Int                      (Int8)

data Header = Header { getPacketType          :: !PacketType,
                       getPacketId            :: !Word8,
                       getPacketLength        :: !Word16,
                       getPacketAuthenticator :: !ByteString }
              deriving (Show, Eq)

data Packet = Packet { getHeader           :: !Header,
                       getPacketAttributes :: ![PacketAttribute] }
              deriving (Show, Eq)

data PacketType = AccessRequest
                | AccessAccept
                | AccessReject
                | AccountingRequest
                | AccountingResponse
                | AccessChallenge
                | StatusServer
                | StatusClient
                  deriving (Show, Eq)


instance Enum PacketType where
    fromEnum AccessRequest      = 1
    fromEnum AccessAccept       = 2
    fromEnum AccessReject       = 3
    fromEnum AccountingRequest  = 4
    fromEnum AccountingResponse = 5
    fromEnum AccessChallenge    = 11
    fromEnum StatusServer       = 12
    fromEnum StatusClient       = 13
    toEnum 1  = AccessRequest
    toEnum 2  = AccessAccept
    toEnum 3  = AccessReject
    toEnum 4  = AccountingRequest
    toEnum 5  = AccountingResponse
    toEnum 11 = AccessChallenge
    toEnum 12 = StatusServer
    toEnum 13 = StatusClient
    toEnum x  = error $ "Invalid RADIUS packet type " ++ show x

data PacketAttribute =
    UserNameAttribute               { getUserNameAttribute               :: !ByteString        }
  | UserPasswordAttribute           { getUserPasswordAttribute           :: !ByteString        }
  | CHAPPassword                    { getCHAPIdentity                    :: !Word8,
                                      getCHAPPasswordAttribute           :: !ByteString        }
  | NASIPAddress                    { getNASIPAddress                    :: !IPv4              }
  | NASIPv6Address                  { getNASIPv6Address                  :: !IPv6              }
  | NASPortAttribute                { getNASPortAttribute                :: !Word32            }
  | ServiceTypeAttribute            { getServiceTypeAttribute            :: !ServiceType       }
  | FramedProtocolAttribute         { getFramedProtocolAttribute         :: !FramedProtocol    }
  | FramedIPAddressAttribute        { getFramedIPAddressAttribute        :: !IPv4              }
  | FramedIPNetmaskAttribute        { getFramedIPNetmaskAttribute        :: !IPv4              }
  | FramedRoutingAttribute          { getFramedRoutingAttribute          :: !FramedRouting     }
  | FramedInterfaceIdAttribute      { getFramedInterfaceIdAttribute      :: !Word64            }
  | FramedIPv6Prefix                { getFramedIPv6PrefixLength          :: !Int8,
                                      getFramedIPv6Prefix                :: !IPv6              }
  | FramedIPv6Route                 { getFramedIPv6RouteAttribute        :: !ByteString        }
  | FramedIPv6Pool                  { getFramedIPv6PoolAttribute         :: !ByteString        }
  | FilterIdAttribute               { getFilterIdAttribute               :: !ByteString        }
  | FramedMTUAttribute              { getFramedMTUAttribute              :: !Word32            }
  | FramedCompressionAttribute      { getFramedCompressionAttribute      :: !FramedCompression }
  | LoginIPHostAttribute            { getLoginIPHostAttribute            :: !IPv4              }
  | LoginIPv6HostAttribute          { getLoginIPv6HostAttribute          :: !IPv6              }
  | LoginServiceAttribute           { getLoginServiceAttribute           :: !LoginService      }
  | LoginTCPPortAttribute           { getLoginTCPPortAttribute           :: !Word32            }
  | ReplyMessageAttribute           { getReplyMessageAttribute           :: !ByteString        }
  | CallbackNumberAttribute         { getCallbackNumberAttribute         :: !ByteString        }
  | CallbackIdAttribute             { getCallbackIdAttribute             :: !ByteString        }
  | FramedRouteAttribute            { getFramedRouteAttribute            :: !ByteString        }
  | FramedIPXNetworkAttribute       { getFramedIPXNetworkAttribute       :: !Word32            }
  | StateAttribute                  { getStateAttribute                  :: !ByteString        }
  | ClassAttribute                  { getClassAttribute                  :: !ByteString        }
  | VendorSpecificAttribute         { getVendorIdAttribute               :: !Word32,
                                      getVendorSpecificAttribute         :: !ByteString        }
  | SessionTimeoutAttribute         { getSessionTimeoutAttribute         :: !Word32            }
  | IdleTimeoutAttribute            { getIdleTimeoutAttribute            :: !Word32            }
  | TerminationActionAttribute      { getTerminationActionAttribute      :: !TerminationAction }
  | CalledStationIdAttribute        { getCalledStationIdAttribute        :: !ByteString        }
  | CallingStationIdAttribute       { getCallingStationIdAttribute       :: !ByteString        }
  | NASIdentifierAttribute          { getNASIdentifierAttribute          :: !ByteString        }
  | ProxyStateAttribute             { getProxyStateAttribute             :: !ByteString        }
  | LoginLATServiceAttribute        { getLoginLATServiceAttribute        :: !ByteString        }
  | LoginLATNodeAttribute           { getLoginLATNodeAttribute           :: !ByteString        }
  | LoginLATGroupAttribute          { getLoginLATGroupAttribute          :: !ByteString        }
  | FramedAppleTalkLinkAttribute    { getFramedAppleTalkLinkAttribute    :: !Word32            }
  | FramedAppleTalkNetworkAttribute { getFramedAppleTalkNetworkAttribute :: !Word32            }
  | FramedAppleTalkZoneAttribute    { getFramedAppleTalkZoneAttribute    :: !ByteString        }
  | CHAPChallengeAttribute          { getCHAPChallengeAttribute          :: !ByteString        }
  | NASPortTypeAttribute            { getNASPortTypeAttribute            :: !NASPortType       }
  | PortLimitAttribute              { getPortLimitAttribute              :: !Word32            }
  | LoginLATPortAttribute           { getLoginLATPortAttribute           :: !ByteString        }
  | AccountInputGigawordsAttribute  { getAccountInputGigawordsAttribute  :: !Word32            }
  | AccountOutputGigawordsAttribute { getAccountOutputGigawordsAttribute :: !Word32            }
  | EventTimeStampAttribute         { getEventTimeStampAttribute         :: !Word32            }
  | ARAPPasswordAttribute           { getARAPPasswordAttribute           :: !ByteString        }
  | ARAPFeaturesAttribute           { getARAPFeaturesAttribute           :: !ByteString        }
  | ARAPZoneAccessAttribute         { getARAPZoneAccessAttribute         :: !ARAPZoneAccess    }
  | ARAPSecurityAttribute           { getARAPSecurityAttribute           :: !Word32            }
  | ARAPSecurityDataAttribute       { getARAPSecurityDataAttribute       :: !ByteString        }
  | PasswordRetryAttribute          { getPasswordRetryAttribute          :: !Word32            }
  | PromptAttribute                 { getPromptAttribute                 :: !Word32            }
  | ConnectInfoAttribute            { getConnectInfoAttribute            :: !ByteString        }
  | ConfigurationTokenAttribute     { getConfigurationTokenAttribute     :: !ByteString        }
  | EAPMessageAttribute             { getEAPMessageAttribute             :: !ByteString        }
  | MessageAuthenticatorAttribute   { getMessageAuthenticatorAttribute   :: !ByteString        }
  | ARAPChallengeResponseAttribute  { getARAPChallengeResponseAttribute  :: !ByteString        }
  | AcctInterimIntervalAttribute    { getAcctInterimIntervalAttribute    :: !Word32            }
  | NASPortIdAttribute              { getNASPortIdAttribute              :: !ByteString        }
  | FramedPoolAttribute             { getFramedPoolAttribute             :: !ByteString        }
  deriving (Show, Eq, Data)


data ServiceType = LoginService
                 | FramedService
                 | CallbackLoginService
                 | CallbackFramedService
                 | OutboundService
                 | AdministrativeService
                 | NASPromptService
                 | AuthenticateOnlyService
                 | CallbackNASPrompt
                 | CallCheckService
                 | CallbackAdministrativeService
                   deriving (Show, Eq, Data)

instance Enum ServiceType where
    fromEnum LoginService                  = 1
    fromEnum FramedService                 = 2
    fromEnum CallbackLoginService          = 3
    fromEnum CallbackFramedService         = 4
    fromEnum OutboundService               = 5
    fromEnum AdministrativeService         = 6
    fromEnum NASPromptService              = 7
    fromEnum AuthenticateOnlyService       = 8
    fromEnum CallbackNASPrompt             = 9
    fromEnum CallCheckService              = 10
    fromEnum CallbackAdministrativeService = 11
    toEnum 1  = LoginService
    toEnum 2  = FramedService
    toEnum 3  = CallbackLoginService
    toEnum 4  = CallbackFramedService
    toEnum 5  = OutboundService
    toEnum 6  = AdministrativeService
    toEnum 7  = NASPromptService
    toEnum 8  = AuthenticateOnlyService
    toEnum 9  = CallbackNASPrompt
    toEnum 10 = CallCheckService
    toEnum 11 = CallbackAdministrativeService
    toEnum x  = error $ "Invalid RADIUS service type " ++ show x

data FramedProtocol = PPPFramedProtocol
                    | SLIPFramedProtocol
                    | ARAPFramedProtocol
                    | GandalfFramedProtocol
                    | XylogicsFramedProtocol
                    | X75FramedProtocol
                      deriving (Show, Eq, Data)

instance Enum FramedProtocol where
    fromEnum PPPFramedProtocol      = 1
    fromEnum SLIPFramedProtocol     = 2
    fromEnum ARAPFramedProtocol     = 3
    fromEnum GandalfFramedProtocol  = 4
    fromEnum XylogicsFramedProtocol = 5
    fromEnum X75FramedProtocol      = 6
    toEnum 1 = PPPFramedProtocol
    toEnum 2 = SLIPFramedProtocol
    toEnum 3 = ARAPFramedProtocol
    toEnum 4 = GandalfFramedProtocol
    toEnum 5 = XylogicsFramedProtocol
    toEnum 6 = X75FramedProtocol
    toEnum x = error $ "Invalid framed protocol " ++ show x

data FramedRouting = NoneFramedRouting
                   | SendFramedRouting
                   | ListenFramedRouting
                   | SendAndListenFramedRouting
                     deriving (Show, Eq, Enum, Data)

data FramedCompression = NoCompression
                       | VJTCPIPHeaderCompression
                       | IPXHeaderCompression
                       | StacLZSCompression
                         deriving (Show, Eq, Enum, Data)

data LoginService = TelnetService
                  | RloginService
                  | TCPClearService
                  | PortMasterService
                  | LATService
                  | X25PADService
                  | X25T3POSService
                  | UnusedService
                  | TCPClearQuietService
                    deriving (Show, Eq, Enum, Data)

data TerminationAction = DefaultTerminationAction | RADIUSRequestTerminationAction
                       deriving (Show, Eq, Enum, Data)

data NASPortType = AsyncNASPort
                 | SyncNASPort
                 | ISDNSyncPort
                 | ISDNAsyncV120Port
                 | ISDNAsyncV110Port
                 | VirtualNASPort
                 | PIAFSNASPort
                 | HDLCClearChannelNASPort
                 | X25NASPort
                 | X75NASPort
                 | G3FaxNASPort
                 | SDSLNASPort
                 | ADSLCAPNASPort
                 | ADSLDMTNASPort
                 | IDSLNASPort
                 | EthernetNASPort
                 | XDSLNASPort
                 | CableNASPort
                 | WirelessOtherNASPort
                 | WirelessIEEE80211NASPort
                   deriving (Show, Eq, Enum, Data)

data ARAPZoneAccess = DefaultZoneOnlyARAPAccess
                    | UseZoneFilterInclusivelyARAPAccess
                    | UseZoneFilterExclusivelyARAPAccess
                    deriving (Show, Eq, Data)

instance Enum ARAPZoneAccess where
    toEnum 1 = DefaultZoneOnlyARAPAccess
    toEnum 2 = UseZoneFilterInclusivelyARAPAccess
    toEnum 4 = UseZoneFilterExclusivelyARAPAccess
    toEnum n = error $ "Invalid RADIUS ARAP Zone Access " ++ show n
    fromEnum DefaultZoneOnlyARAPAccess = 1
    fromEnum UseZoneFilterInclusivelyARAPAccess = 2
    fromEnum UseZoneFilterExclusivelyARAPAccess = 4
