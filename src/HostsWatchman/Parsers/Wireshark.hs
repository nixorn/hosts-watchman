{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
module HostsWatchman.Parsers.Wireshark
    ( hostMapsParser
    ) where

import           Control.Applicative       ((<|>))
import           Control.Monad.Combinators (many)
import           Data.Text                 (Text, pack)
import           Data.Void                 (Void)
import           Text.Megaparsec           (Parsec, try)
import           Text.Megaparsec.Char      (alphaNumChar, char, digitChar,
                                            newline, printChar, punctuationChar,
                                            space1, string, symbolChar)

-- | webdav.yandex.ru == Domain [ "ru", "yandex", "webdav" ]
newtype Domain = Domain [Text]
  deriving (Show, Ord, Eq)

-- | Only IPv4 for now. We does drop AAAA dns responces.
data IP = IP Text
  deriving (Show, Ord, Eq)

data HostMap = HostMap
  Domain
  IP
  deriving (Show, Ord, Eq)

type Parser = Parsec Void Text

hostMapsParser :: Parser [HostMap]
hostMapsParser = concat <$> many (try rowParser <|> dumbRowParser)

-- Row contains zero usable info for us but match any string
dumbRowParser :: Parser [HostMap]
dumbRowParser = do
  _ <- many printChar
  _ <- newline
  return []

-- Desired strings look like
-- Jan  7 21:10:35 nixorn-Lenovo-G50-70 tshark[7873]:  1200 76.489068007  192.168.1.1 → 192.168.1.40 DNS 336 Standard query response 0xfce2 A webdav.yandex.ru A 213.180.204.148 NS ns9.z5h64q92x9.net NS ns2.yandex.ru NS ns1.yandex.ru A 154.47.36.189 A 80.239.201.9 AAAA 2001:978:7401::78 AAAA 2001:2030:0:40:8000::78 A 213.180.193.1 AAAA 2a02:6b8::1 A 93.158.134.1 AAAA 2a02:6b8:0:1::1
rowParser :: Parser [HostMap]
rowParser = do
  _ <- textParser -- Jan
  _ <- space1
  _ <- intParser  -- 7
  _ <- space1
  _ <- textParser -- 21:10:35
  _ <- space1
  _ <- textParser -- nixorn-Lenovo-G50-70
  _ <- space1
  _ <- textParser -- tshark[7873]:
  _ <- space1
  _ <- intParser  -- 1200
  _ <- space1
  _ <- textParser -- 76.489068007
  _ <- space1
  _ <- ipParser   -- 192.168.1.1
  _ <- space1
  _ <- symbolChar -- →
  _ <- space1
  _ <- ipParser   -- 192.168.1.1
  _ <- space1
  _ <- string "DNS"
  _ <- space1
  _ <- intParser  -- 336
  _ <- space1
  _ <- string "Standard query response"
  _ <- space1
  _ <- textParser -- 0xfce2
  _ <- space1
  results <- dnsResponseParser
  return results

dnsResponseParser :: Parser [HostMap]
dnsResponseParser = do
  _ <- string "A"
  _ <- space1
  domain <- domainParser
  _ <- space1
  ips <- many aRecordParser
  _ <- many printChar -- skip rest of line
  _ <- newline
  return $ map (HostMap domain) ips

domainParser :: Parser Domain
domainParser = do
  topLevelName <- pack <$> many alphaNumChar
  restNames <- many $ do
    _ <- char '.'
    pack <$> many alphaNumChar
  return . Domain . reverse $ topLevelName : restNames

aRecordParser :: Parser IP
aRecordParser = do
  _ <- char 'A'
  _ <- space1
  ip <- ipParser
  return ip

ipParser :: Parser IP
ipParser = do
  one <- intParser
  _ <- char '.'
  two <- intParser
  _ <- char '.'
  three <- intParser
  _ <- char '.'
  four <- intParser
  return (IP $ one <> "." <> two <> "." <> three <> "." <> four)

intParser :: Parser Text
intParser = pack <$> many digitChar

textParser :: Parser Text
textParser = pack <$> many (alphaNumChar <|> punctuationChar)
