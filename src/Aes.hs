module Aes (
    encrypt,
    decrypt
) where

import qualified Data.Vector as V
import qualified Data.Matrix as M
import Data.Word8
import Data.List
import Data.Bits

encrypt :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
encrypt plaintext key = 
    last $ scanr1 (\t ikey -> 
        let text = xorVec $ take (length key) $ 
                drop (((length pptext / (length key)) - ikey) * 4) pptext
         in 
            xor (last t) 
            (matToVec $ exkey ikey $ shiftRows $ vecToMat $ subWord $ iterate 
            (matToVec $ exkey ikey $ mixColumns $ shiftRows $ vecToMat $ subWord) text 
            !! ((length key / 4) + 5)):t) 
        [(length key), (length key) * 2, (length pptext)]
    where exkey ikey t = xorVec (map (expandKey key) [(ikey - 4)..(ikey - 1)])
          pptext = pad plaintext key

pad :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
pad text key = text V.++ (repeatedly (rem (length text) (length key)) 0)

xorVec :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
xorVec key = 
        map (\(cbit, kbit) -> cbit `xor` kbit) $ zip text key 

shiftRows :: (Any a) => M.Matrix a -> M.Matrix a 
shiftRows mat = 
    vecToMat $ V.concat $ V.map 
        (\i -> (iterate rotWord $ M.getRow i mat) !! i) $ V.fromList [1..(M.nrows mat)] 

mixColumns :: (Any a) => M.Matrix a -> M.Matrix a
mixColumns mat = 
    foldl1 
        (\mat i -> mat M.<|> (\i -> multStd mixColumnsConst $ M.colVector $ M.getCol i mat)) 
            [1..(ncols mat)]

mixColumnsConst :: Matrix Word8
mixColumnsConst = M.fromList [[2, 3, 1, 1], 
                              [1, 2, 3, 1], 
                              [1, 1, 2, 3], 
                              [3, 1, 1, 2]]

matToVec :: (Any a) => M.Matrix a -> Vector a
matToVec mat = V.concat $ map (flip M.getRow mat) [0..(M.nRows mat)] 

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
subWord = map sBox

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

