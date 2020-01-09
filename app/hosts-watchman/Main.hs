module Main where

import qualified Data.Set                        as S
import qualified Data.Text.IO                    as T
import           Text.Megaparsec                 (parse)

import           HostsWatchman.Parsers.Wireshark

main :: IO ()
main = do
  forParse <- T.readFile "/var/log/tshark.log"
  let Right result = S.fromList <$> parse hostMapsParser "/var/log/tshark.log" forParse
  print result
