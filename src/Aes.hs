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

decrypt :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
decrypt ciphertext key iv = V.concat $ tail $ scanl (\t ikey ->
    let text = V.take (V.length key) $ V.drop ikey ciphertext
    in xorVec t $ (iterate (round ikey) (finalRound ikey text)) !! (((V.length key) `quot` 4) + 5))
    iv $ [(V.length key), (V.length key) * 2, (V.length ciphertext)]
    where byteLength = (V.length key `quot` 4)
          round ikey text = invSubBytes $ matToVec $ invShiftRows key $ invMixColumns $ vecToMat byteLength $ addRoundKey key ikey text
          finalRound ikey text = invSubBytes $ matToVec $ invShiftRows key $ vecToMat byteLength $ addRoundKey key ikey text


invShiftRows :: V.Vector Word8 -> M.Matrix Word8 -> M.Matrix Word8
invShiftRows = shiftRows invRotWord

invRotWord :: V.Vector Word8 -> V.Vector Word8
invRotWord xs = V.last xs `V.cons` (V.init xs)

invMixColumns :: M.Matrix Word8 -> M.Matrix Word8
invMixColumns = mixColumns invMixColumnsConst

invMixColumnsConst :: M.Matrix Word8
invMixColumnsConst = M.fromList 4 4 $ map fromIntegral
                                [14, 11, 13, 9,
                                 9, 14, 11, 13,
                                 13, 9, 14, 11,
                                 11, 13, 9, 14]

invSubBytes :: V.Vector Word8 -> V.Vector Word8
invSubBytes = V.map invSBox

invSBox :: Word8 -> Word8
invSBox b =
    (rotateL (sBox b) 1) `xor` (rotateL (sBox b) 3) `xor` (rotateL (sBox b) 6) `xor` 5

encrypt :: V.Vector Word8 -> V.Vector Word8 -> IO(V.Vector Word8, V.Vector Word8)
encrypt plaintext key = do
    ivl <- randList (V.length pptext)
    let iv = V.fromList ivl 
    return $ (,) iv $ V.concat $ tail $ scanl (\t ikey -> 
        let text = xorVec key $ V.take (V.length key) $ V.drop ikey pptext
         in xorVec t $ finalRound ikey $ (iterate (round ikey) text !! ((V.length key `quot` 4) + 5)))
        iv [(V.length key), (V.length key) * 2, (V.length pptext)]
    where pptext = pad plaintext key
          byteLength = V.length key `quot` 4
          finalRound ikey text = addRoundKey key ikey $ matToVec $ 
            shiftRowsFwd key $ vecToMat byteLength $ subWord text
          round ikey text = addRoundKey key ikey $ matToVec $ 
            mixColumnsFwd $ shiftRowsFwd key $ vecToMat byteLength $ subWord text

addRoundKey :: V.Vector Word8 -> Int -> V.Vector Word8 -> V.Vector Word8
addRoundKey key ikey = xorVec $ V.concat (map (expandKey key) [ikey..(ikey + V.length key)])

randList :: Int -> IO [Word8] 
randList n = replicateM n $ randomRIO (0, 255)

pad :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
pad text key = text V.++ V.fromList (replicate (rem (V.length text) (V.length key)) 0)

shiftRowsFwd :: V.Vector Word8 -> M.Matrix Word8 -> M.Matrix Word8
shiftRowsFwd = shiftRows rotWord 

shiftRows :: (V.Vector Word8 -> V.Vector Word8) -> V.Vector Word8 -> M.Matrix Word8 -> M.Matrix Word8
shiftRows wordRotFn key mat = 
    vecToMat ((V.length key) `quot` 4) $ V.concat $ map 
        (\i -> (iterate wordRotFn (M.getRow i mat)) !! i) [1..(M.nrows mat)] 
 
mixColumnsFwd :: M.Matrix Word8 -> M.Matrix Word8 
mixColumnsFwd = mixColumns mixColumnsConst

mixColumns :: M.Matrix Word8 -> M.Matrix Word8 -> M.Matrix Word8 
mixColumns const mat = 
    foldl 
        (\mat i -> mat M.<|> (M.multStd const $ M.colVector $ M.getCol i mat))
            (M.zero 0 0) [1..(M.ncols mat)]

mixColumnsConst :: M.Matrix Word8
mixColumnsConst = M.fromList 4 4 $ map fromIntegral 
                             [2, 3, 1, 1, 
                              1, 2, 3, 1, 
                              1, 1, 2, 3, 
                              3, 1, 1, 2]


matToVec :: M.Matrix a -> V.Vector a
matToVec mat = V.concat $ map (flip M.getRow mat) [0..(M.nrows mat)] 

vecToMat :: Int -> V.Vector Word8 -> M.Matrix Word8
vecToMat bytes text = 
    foldr (\t mat -> mat M.<-> (M.colVector $ V.take bytes $ V.drop t text)) (M.zero 0 0)
        [0..(((V.length text) `quot` bytes) - bytes)]

expandKey :: V.Vector Word8 -> Int -> V.Vector Word8
expandKey key i
  | i < n = key
  | i >= n && rem i n == 0 = 
        rCon (i `quot` n) `xorVec` 
            keyMinusOne `xorVec` (subWord $ rotWord keyMinusOne)
  | i >= n && n > 6 && rem i n == 4 = keyMinusOne `xorVec` 
        subWord keyMinusOne 
  | otherwise = keyMinusOne `xorVec` expandKey key (i - n)
  where n = (V.length key `quot` 4)
        keyMinusOne = expandKey key (i - 1)

xorVec :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
xorVec key text = 
        V.map (\(cbit, kbit) -> cbit `xor` kbit) $ V.zip text key 

subWord :: V.Vector Word8 -> V.Vector Word8
subWord = V.map sBox

rotWord :: V.Vector Word8 -> V.Vector Word8
rotWord key = V.tail key V.++ V.fromList [V.head key]

sBox :: Word8 -> Word8
sBox b = 
  xor 99 
    $ fromIntegral $ rem (fromIntegral b * 31) 257

rCon :: Int -> V.Vector Word8
rCon i = V.fromList $ (rc i):(replicate 3 0)

rc :: Int -> Word8
rc i
  | i > 1 && (fromIntegral (rc (i - 1))) < 128 = 2 * (rc (i - 1))
  | i > 1 = xor 27 (2 * (rc (i - 1)))
  | otherwise = 1

