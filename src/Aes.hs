module Aes where

import qualified Data.ByteString as B
import qualified Data.Vector as V
import qualified Data.Matrix as M
import System.Random (randomRIO)
import Control.Monad (replicateM)
import Data.Word8
import Data.List
import Data.Bits

decrypt :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString
decrypt ciphertext key iv = B.concat $ tail $ scanl (\t ikey ->
    let text = B.take (B.length key) $ B.drop ikey ciphertext
    in xorStr t $ (iterate (round ikey) (finalRound ikey text)) !! (((B.length key) `quot` 4) + 5))
    iv $ init [0, (B.length key)..(B.length ciphertext)]
    where
          round ikey text = invSubBytes $ matToStr $ invShiftRows key $ invMixColumns $ strToMat $ addRoundKey key ikey text
          finalRound ikey text = invSubBytes $ matToStr $ invShiftRows key $ strToMat $ addRoundKey key ikey text


invShiftRows :: B.ByteString -> M.Matrix Word8 -> M.Matrix Word8
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

invSubBytes :: B.ByteString -> B.ByteString
invSubBytes = B.map invSBox

invSBox :: Word8 -> Word8
invSBox b =
    (rotateL (sBox b) 1) `xor` (rotateL (sBox b) 3) `xor` (rotateL (sBox b) 6) `xor` 5

encrypt :: B.ByteString -> B.ByteString -> IO(B.ByteString, B.ByteString)
encrypt plaintext key = do
    ivl <- randList (B.length pptext)
    let iv = B.pack ivl 
    return $ (,) iv $ B.concat $ tail $ scanl (\t ikey -> 
        let text = xorStr key $ B.take (B.length key) $ B.drop ikey pptext
         in xorStr t $ finalRound ikey $ (iterate (round ikey) text !! 9))
        iv $ init [0, (B.length key)..(B.length pptext)]
    where pptext = pad plaintext key
          finalRound ikey text = addRoundKey key ikey $ matToStr $ 
            shiftRowsFwd key $ strToMat $ subWord text
          round ikey text = addRoundKey key ikey $ matToStr $ 
            mixColumnsFwd $ shiftRowsFwd key $ strToMat $ subWord text

addRoundKey :: B.ByteString -> Int -> B.ByteString -> B.ByteString
addRoundKey key ikey = xorStr $ B.concat (map (expandKey key) [ikey..(ikey + B.length key)])

randList :: Int -> IO [Word8] 
randList n = replicateM n $ randomRIO (0, 255)

pad :: B.ByteString -> B.ByteString -> B.ByteString
pad text key = B.concat [text, B.pack (replicate (rem (B.length key) (B.length text)) 0)]

shiftRowsFwd :: B.ByteString -> M.Matrix Word8 -> M.Matrix Word8
shiftRowsFwd = shiftRows rotWordVec 

shiftRows :: (V.Vector Word8 -> V.Vector Word8) -> B.ByteString -> M.Matrix Word8 -> M.Matrix Word8
shiftRows wordRotFn key mat = 
    strToMat $ B.pack $ V.toList $ V.concat $ map 
        (\i -> (iterate wordRotFn (M.getRow i mat)) !! i) [1..(M.nrows mat)] 
 
mixColumnsFwd :: M.Matrix Word8 -> M.Matrix Word8 
mixColumnsFwd = mixColumns mixColumnsConst

mixColumns :: M.Matrix Word8 -> M.Matrix Word8 -> M.Matrix Word8 
mixColumns const mat = 
        foldl1 (M.<|>) $ 
            map (\i -> M.multStd const $ M.colVector $ M.getCol i mat)
                [1..(M.ncols mat)]

mixColumnsConst :: M.Matrix Word8
mixColumnsConst = M.fromList 4 4 $ map fromIntegral 
                             [2, 3, 1, 1, 
                              1, 2, 3, 1, 
                              1, 1, 2, 3, 
                              3, 1, 1, 2]


matToStr :: M.Matrix Word8 -> B.ByteString 
matToStr mat = B.concat $ map (\i -> B.pack $ V.toList $ M.getRow i mat) [1..(M.nrows mat)] 

strToMat :: B.ByteString -> M.Matrix Word8
strToMat text = M.fromList 4 4 $ B.unpack text

expandKey :: B.ByteString -> Int -> B.ByteString
expandKey key i
  | i < n = key
  | i >= n && rem i n == 0 = 
        rCon (i `quot` n) `xorStr` 
            keyMinusOne `xorStr` (subWord $ rotWord keyMinusOne)
  | i >= n && n > 6 && rem i n == 4 = keyMinusOne `xorStr` 
        subWord keyMinusOne 
  | otherwise = keyMinusOne `xorStr` expandKey key (i - n)
  where n = (B.length key `quot` 4)
        keyMinusOne = expandKey key (i - 1)

xorStr :: B.ByteString -> B.ByteString -> B.ByteString
xorStr key text = 
        B.pack $ map (\(cbit, kbit) -> cbit `xor` kbit) $ B.zip text key 

subWord :: B.ByteString -> B.ByteString
subWord = B.map sBox

rotWord :: B.ByteString -> B.ByteString
rotWord key = B.concat [B.tail key, B.singleton $ B.head key]

rotWordVec :: V.Vector Word8 -> V.Vector Word8
rotWordVec key = V.tail key V.++ (V.singleton $ V.head key)

sBox :: Word8 -> Word8
sBox b = 
  xor 99 
    $ fromIntegral $ rem (fromIntegral b * 31) 257

rCon :: Int -> B.ByteString
rCon i = B.pack $ (rc i):(replicate 3 0)

rc :: Int -> Word8
rc i
  | i > 1 && (fromIntegral (rc (i - 1))) < 128 = 2 * (rc (i - 1))
  | i > 1 = xor 27 (2 * (rc (i - 1)))
  | otherwise = 1

