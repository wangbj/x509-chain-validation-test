{-# LANGUAGE TemplateHaskell #-}

module Main where

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)
import Data.Either

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Control.Monad
import Data.Monoid
import Data.X509.Validation
import Data.X509.CertificateStore
import Data.X509

import CA

mapLeft :: (e -> e') -> Either e a -> Either e' a
mapLeft f (Left e) = Left (f e)
mapLeft f (Right a) = Right a

defaultSubj = X509Subj "US" "CA" "San Diego" "none" "rootca" []
ouSubj      = X509Subj "US" "CA" "San Diego" "none" "attest" [ "attest" ]

makeRootCA = newCA defaultSubj Nothing

makeSizedChainHelper :: Int -> Int -> X509CA -> IO [ByteString]
makeSizedChainHelper n k issuer
  | k == n = return mempty
  | k  < n = do
      ca <- newCA ouSubj {subjCName = "attest" ++ show k} (Just issuer)
      liftM (x509CertRaw ca:) (makeSizedChainHelper n (succ k) ca)

makeSizedChainOrdered k ca = liftM (reverse) (makeSizedChainHelper k 1 ca)

newtype SmallChainSize = SmallChainSize Int deriving (Show, Eq, Ord)

instance Arbitrary SmallChainSize where
  arbitrary = SmallChainSize <$> choose (1, 10)

defaultChecksNoFQDN :: ValidationChecks
defaultChecksNoFQDN = ValidationChecks
    { checkTimeValidity   = True
    , checkAtTime         = Nothing
    , checkStrictOrdering = False
    , checkCAConstraints  = True
    , checkExhaustive     = True
    , checkLeafV3         = True
    , checkLeafKeyUsage   = []
    , checkLeafKeyPurpose = []
    , checkFQHN           = False
    }

prop_ordered_chain_can_be_validate (SmallChainSize chainsize) = monadicIO $ do
  root <- run makeRootCA
  chainRaw <- run (makeSizedChainOrdered chainsize root)
  let chain_ = decodeCertificateChain (CertificateChainRaw (chainRaw ++ [x509CertRaw root]))
  assert (isRight chain_)
  let Right cs@(CertificateChain chain) = chain_
  let rootca      = last chain
      trusted = makeCertificateStore [rootca]
      nocache = exceptionValidationCache []
  failedReason <- run (validate HashSHA256 defaultHooks defaultChecksNoFQDN trusted nocache ("ignored", mempty) cs)
  when (not (null failedReason)) (run (mapM_ print failedReason))
  assert (null failedReason)

return []
runTests = $quickCheckAll

main :: IO ()
main = runTests >> return ()
