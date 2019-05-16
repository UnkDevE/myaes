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
sBox b = B.index (fromIntegral b) B.pack [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

rCon :: Int -> B.ByteString
rCon i = B.pack $ (rc i):(replicate 3 0)

rc :: Int -> Word8
rc i
  | i > 1 && (fromIntegral (rc (i - 1))) < 128 = 2 * (rc (i - 1))
  | i > 1 = xor 27 (2 * (rc (i - 1)))
  | otherwise = 1

