module Main where

import qualified Data.Vector as V
import qualified Data.Vector.Binary as VB
import qualified Data.Binary as B
import Data.Word8
import System.Environment 
import Aes

main :: IO ()
main = do
    [encordec, file, keyfile, outfile, ivfile] <- getArgs
    if encordec == "-e" then do
        plaintext <- B.decodeFile file 
        key <- B.decodeFile keyfile 
        (iv, cipher) <- encrypt plaintext key
        B.encodeFile outfile cipher
        B.encodeFile ivfile iv
    else do  
        ciphertext <- B.decodeFile file 
        key <- B.decodeFile keyfile 
        iv <- B.decodeFile ivfile 
        B.encodeFile outfile $ decrypt ciphertext key iv
        
 
       
        
       
    
