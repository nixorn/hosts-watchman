{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
module HostsWatchman.Parsers.Wireshark
    ( Domain (..)
    , domainsParser
    ) where

import           Control.Applicative       ((<|>))
import           Control.Monad.Combinators (many)
import           Data.Maybe                (catMaybes)
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Void                 (Void)
import           Text.Megaparsec           (Parsec, try)
import           Text.Megaparsec.Char      (alphaNumChar, char, digitChar,
                                            newline, printChar, punctuationChar,
                                            space1, string, symbolChar)

newtype Domain = Domain { unDomain :: Text }
  deriving newtype (Show, Ord, Eq, Read)

-- | Only IPv4 for now. We does drop AAAA dns responces.
newtype IP = IP Text
  deriving newtype (Show, Ord, Eq)

type Parser = Parsec Void Text

domainsParser :: Parser [Domain]
domainsParser = catMaybes <$> many (try rowParser <|> dumbRowParser)

-- Row contains zero usable info for us but match any string
dumbRowParser :: Parser (Maybe Domain)
dumbRowParser = do
  _ <- many printChar
  _ <- newline
  pure Nothing

-- Desired strings look like
-- Jan 12 15:20:11 nixorn-Lenovo-G50-70 tshark[6323]: 22272 602.102713466 192.168.1.40 → 192.168.1.1  DNS 85 Standard query 0x5be1 A www.google.com OPT
-- Jan 12 15:20:11 nixorn-Lenovo-G50-70 tshark[6323]: 22273 602.102872063 192.168.1.40 → 192.168.1.1  DNS 85 Standard query 0xaa45 AAAA www.google.com OPT
rowParser :: Parser (Maybe Domain)
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
  _ <- string "Standard query"
  _ <- space1
  _ <- textParser -- 0xfce2
  _ <- space1
  _ <- string "AAAA" <|> string "A"
  _ <- space1
  domain <- domainParser
  _ <- newline
  return $ Just domain

domainParser :: Parser Domain
domainParser = do
  topLevelName <- T.pack <$> many alphaNumChar
  restNames <- many $ do
    _ <- char '.'
    T.pack <$> many alphaNumChar
  return . Domain $ T.intercalate "." (topLevelName : restNames)

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
intParser = T.pack <$> many digitChar

textParser :: Parser Text
textParser = T.pack <$> many (alphaNumChar <|> punctuationChar)
