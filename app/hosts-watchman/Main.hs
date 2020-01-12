module Main where

import           Data.Set                        (Set, (\\))
import qualified Data.Set                        as S
import qualified Data.Text                       as T
import qualified Data.Text.IO                    as T
import           System.Process                  (readProcess)
import           Text.Megaparsec                 (parse)

import           HostsWatchman.Parsers.Wireshark

tsharkServiceName :: String
tsharkServiceName = "tshark"

trustedHostsPath :: String
trustedHostsPath = "./trusted_hosts"

untrustedHostsPath :: String
untrustedHostsPath = "./untrusted_hosts"

uncheckedHostsPath :: String
uncheckedHostsPath = "./unchecked_hosts"

readDomains :: FilePath -> IO (Set Domain)
readDomains path = S.fromList . map Domain . T.lines <$> T.readFile path

main :: IO ()
main = do
  trusted   <- readDomains trustedHostsPath
  untrusted <- readDomains untrustedHostsPath
  unchecked <- readDomains uncheckedHostsPath
  forParse  <- T.pack <$> readProcess "journalctl" ["-t", tsharkServiceName] ""
  let Right parsed  = S.fromList <$> parse domainsParser "tshark.log" forParse
  T.writeFile uncheckedHostsPath
    $ T.unlines
    $ map unDomain
    $ S.toList
    $ S.union unchecked
    $ (parsed \\ trusted) \\ untrusted
