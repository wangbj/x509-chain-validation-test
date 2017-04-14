module CA (
    newCA
  , X509CA
  , x509CertRaw
  , X509Subj (..)
  ) where

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)

import Control.Concurrent
import Control.Exception
import System.Process
import System.Posix.Temp
import System.IO
import System.Directory
import System.Exit
import Data.Maybe
import Data.List (intercalate, find)

keysizeinbits :: Int
keysizeinbits = 2048

publicexponent :: Int
publicexponent = 65537

mkstempFile prefix = bracket (mkstemp prefix) (hClose . snd) (return . fst)

withTempFile :: String -> (FilePath -> IO a) -> IO a
withTempFile prefix f = bracket (mkstempFile prefix) removeFile f

mayThrowIO :: Maybe Handle -> IO a
mayThrowIO (Nothing) = exitFailure
mayThrowIO (Just h) = hGetContents h >>= die

withProcess :: CreateProcess -> (ProcessHandle -> IO a) -> IO a
withProcess p f = bracket (createProcess p) (\(inh, outh, errh, ph) -> (mapM_ hClose (catMaybes [inh, outh, errh]) >> terminateProcess ph)) (\(_, _, errh, ph) -> waitForProcess ph >>= \exitcode -> if exitcode == ExitSuccess then f ph else mayThrowIO errh)

newtype RawRsaKey = RawRsaKey ByteString
newtype RawX509Crt = RawX509Crt ByteString
newtype RawCsr = RawCsr ByteString

data X509Subj = X509Subj {
    subjCountry     :: String
  , subjState       :: String
  , subjCity        :: String
  , subjOrgnization :: String
  , subjCName       :: String
  , subjOU          :: [String]
  }

quoted s = case find isSpace s of
  Nothing -> s
  Just _  -> "\"" ++ s ++ "\""
  where isSpace c = c `elem` " \t"

instance Show X509Subj where
  show (X509Subj c st l o cn ous) = "/C=" ++ quoted c ++ "/ST=" ++ quoted st ++ "/L=" ++ quoted l ++ "/O=" ++ quoted o ++ "/CN=" ++ quoted cn ++ concatMap (\ou -> "/OU=" ++ quoted ou) ous

instance Show RawRsaKey where
  show (RawRsaKey k) = show k

instance Show RawX509Crt where
  show (RawX509Crt c) = show c

instance Show RawCsr where
  show (RawCsr c) = show c

data X509CA = X509CA {
    _x509Cert :: RawX509Crt
  , _x509CertKey :: RawRsaKey
  , _x509Serial  :: Int
  }

instance Show X509CA where
  show (X509CA issuer _ _) = show issuer

x509CertRaw :: X509CA -> ByteString
x509CertRaw (X509CA (RawX509Crt cert) _ _) = cert

silent s = (shell s) { std_in = NoStream, std_out = NoStream, std_err = CreatePipe }

sslGenRsa :: IO RawRsaKey
sslGenRsa = 
  withTempFile "rootca" $ \rootca ->
    withProcess (silent ("openssl genrsa -out " ++ rootca ++ " > /dev/null 2>&1 ")) $ \ph ->
      withFile rootca ReadMode (fmap RawRsaKey . S.hGetContents)

sslGenX509 :: RawRsaKey -> X509Subj -> IO RawX509Crt
sslGenX509 (RawRsaKey key) subj = 
  withTempFile "rootKey" $ \rootKey ->
    withTempFile "rootcrt" $ \rootcrt -> do
      S.writeFile rootKey key
      withProcess (silent ("openssl req -new -key " ++ rootKey ++ " -x509 -out " ++ rootcrt ++ " -outform DER -subj " ++ show subj ++ " -days 365")) $ \ph ->
        withFile rootcrt ReadMode (fmap RawX509Crt . S.hGetContents)

sslGenCsr :: RawRsaKey -> X509Subj -> IO RawCsr
sslGenCsr (RawRsaKey key) subj = 
  withTempFile "csrkey" $ \csrkey ->
    withTempFile "csr" $ \csr -> do
      S.writeFile csrkey key
      withProcess (silent ("openssl req -new -key " ++ csrkey ++ " -out " ++ csr ++ " -subj " ++ show subj ++ " -days 365")) $ \ph ->
        withFile csr ReadMode (fmap RawCsr . S.hGetContents)

sslNewCAWithCsr :: RawCsr -> X509CA -> IO (RawX509Crt, Int)
sslNewCAWithCsr (RawCsr csr) (X509CA (RawX509Crt issuer) (RawRsaKey issuerKey) serial) =
  withTempFile "csr" $ \csrFile ->
  withTempFile "issuer" $ \issuerCA ->
  withTempFile "issuerKey" $ \issuerCAKey ->
  withTempFile "newcert" $ \newcert -> do
    S.writeFile csrFile csr
    S.writeFile issuerCAKey issuerKey
    S.writeFile issuerCA issuer
    let serial' = 1 + serial
    withProcess (silent ("openssl x509 -req -in " ++ csrFile ++ " -CA " ++ issuerCA ++ " -CAform DER " ++ " -CAkey " ++ issuerCAKey ++ " -out " ++ newcert ++ " -outform DER -days 365 -set_serial " ++ show serial')) $ \ph -> withFile newcert ReadMode (\h -> S.hGetContents h >>= \crt -> return (RawX509Crt crt, serial'))

newCA :: X509Subj        -- ^ x509 subject
      -> Maybe X509CA    -- ^ issuer, Nothing means self-signed
      -> IO X509CA       -- ^ issued new certificate
newCA subj Nothing = do
  key <- sslGenRsa
  crt <- sslGenX509 key subj
  return (X509CA crt key 1)
newCA subj (Just ca) = do
  key <- sslGenRsa
  csr <- sslGenCsr key subj
  (crt, serial') <- sslNewCAWithCsr csr ca
  return (X509CA crt key serial')
