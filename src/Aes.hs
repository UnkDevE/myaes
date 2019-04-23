module Aes (
    encrypt,
    decrypt
) where

import qualified Data.Vector as V
import qualified Data.Matrix as M
import System.Random (randomRIO)
import Control.Monad (replicateM)
import Data.Word8
import Data.List
import Data.Bits

decrypt :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
decrypt ciphertext key iv = V.concat $ V.last $ V.scanl (\t ikey -> 
    let text = take (length key) $ drop ikey ciphertext
    in xorVec iv $ (iterate (invSubBytes $ invShiftRows $ invMixColumns $ xorVec key) 
        invSubBytes $ invShiftRows $ xorVec text key) !! [(length key / 4) + 5])
    (V.fromList [iv]) $ V.fromList [(length key), (length key) * 2, (length ciphertext)]


invShiftRows :: (Any a) => M.Matrix a -> M.Matrix a
invShiftRows = shiftRows invRotWord

invRotWord :: V.Vector Word8 -> V.Vector Word8
invRotWord xs = V.last xs:(V.init xs)

invMixColumns :: (Any a) => M.Matrix a -> M.Matrix a 
invMixColumns = mixColumns invMixColumnsConst 

invMixCoulmnsConst :: M.Matrix Word8
invMixColumnsConst = M.fromList [[14, 11, 13, 9],
                                 [9, 14, 11, 13],
                                 [13, 9, 14, 11],
                                 [11, 13, 9, 14]]

invSubBytes :: V.Vector Word8 -> V.Vector Word8
invSubBytes = V.map invSBox

invSBox :: Word8 -> Word8
invSBox b = 
    (rotateL 1 $ sBox b) `xor` (rotateL 3 $ sBox b) `xor` (rotateL 6 $ sBox b) `xor` 5

encrypt :: V.Vector Word8 -> V.Vector Word8 -> IO(V.Vector Word8, V.VectorWord8)
encrypt plaintext key = do
    ivl <- randList (length pptext)
    let iv = V.fromList ivl 
    return $ (,) iv $ V.concat V.last V.scanl (\t ikey -> 
        let text = xorVec $ take (length key) $ drop ikey pptext
         in 
            xorVec (last t) 
            (matToVec $ exkey ikey $ shiftRows $ vecToMat $ subWord $ iterate 
            (matToVec $ exkey ikey $ mixColumns $ shiftRows $ vecToMat $ subWord) text 
            !! ((length key / 4) + 5)):t) 
        (V.fromList [iv]) $ V.fromList [(length key), (length key) * 2, (length pptext)]
    where pptext = pad plaintext key

exkey :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
exkey ikey t = xorVec $ V.fromList (map (expandKey key) [ikey..(ikey + length key)])

randList :: (Num a) => Int -> IO[a]
randList n = replicateM n $ randomRIO (0, 255)

pad :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
pad text key = text V.++ (repeatedly (rem (length text) (length key)) 0)

xorVec :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
xorVec key = 
        V.map (\(cbit, kbit) -> cbit `xor` kbit) $ zip text key 

shiftRowsFwd :: (Any a) => M.Matrix a -> M.Matrix a 
shiftRowsFwd mat = shiftRows rotWord

shiftRows :: (Any a) => (V.Vector Word8 -> V.Vector Word8) -> M.Matrix a -> M.Matrix a
shiftRows wordRotFn mat = 
    vecToMat $ V.concat $ V.map 
        (\i -> (iterate wordRotFn $ M.getRow i mat) !! i) $ V.fromList [1..(M.nrows mat)] 

mixCoulmnsFwd :: (Any a) => M.Matrix a -> M.Matrix a 
mixColumnsFwd = mixColumns mixCoulmnsConst 

mixColumns :: (Any a) => M.Matrix a -> M.Matrix a -> M.Matrix a
mixColumns const mat = 
    foldl1 
        (\mat i -> mat M.<|> (\i -> multStd const $ M.colVector $ M.getCol i mat)) 
            [1..(ncols mat)]

mixColumnsConst :: Matrix Word8
mixColumnsConst = M.fromList [[2, 3, 1, 1], 
                              [1, 2, 3, 1], 
                              [1, 1, 2, 3], 
                              [3, 1, 1, 2]]

matToVec :: (Any a) => M.Matrix a -> Vector a
matToVec mat = V.concat $ V.map (flip M.getRow mat) $ V.fromList [0..(M.nRows mat)] 

vecToMat :: V.Vector Word8 -> Int -> M.Matrix Word8
vecToMat text bytes = 
    foldr (\vec mat -> mat M.<-> rowVector $ take bytes vec) text

expandKey :: V.Vector Word8 -> Int -> V.Vector Word8
expandKey key i
  | i < n = key
  | i >= n && rem i n == 0 = 
        rCon (i / n) `xor` keyMinusOne `xor` subWord $ rotWord $ keyMinusOne  
  | i >= n && n > 6 && rem i n == 4 = keyMinusOne `xor` subWord $ keyMinusOne 
  | otherwise = keyMinusOne `xor` expandKey key (i - n)
  where n = (length key / 4)
        keyMinusOne = expandKey key (i - 1)

subWord :: V.Vector Word8 -> V.Vector Word8
subWord = V.map sBox

rotWord :: V.Vector Word8 -> V.Vector Word8
rotWord key = tail key ++ [head key]

sBox :: Word8 -> Word8
sBox b = 
  xor 99 
    $ fromIntegral $ rem (fromIntegral b * 31) 257

rCon :: Int -> V.Vector Word8
rCon i = V.fromList $ (rc i):(replicate 3 0)

rc :: Int -> Word8
rc i
  | i > 1 && (fromIntegral (rc (i - 1))) < 128 = 2 * (rc (i - 1))
  | i > 1 = xor 283 (2 * (rc (i - 1)))
  | otherwise = 1

