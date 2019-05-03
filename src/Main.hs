module Main where

import qualified Data.ByteString as B
import Data.Word8
import System.Environment 
import Aes

main :: IO ()
main = do
    [encordec, file, keyfile, outfile, ivfile] <- getArgs
    if encordec == "-e" then do
        plaintext <- B.readFile file 
        key <- B.readFile keyfile 
        (iv, cipher) <- encrypt plaintext (B.init key)
        B.writeFile outfile cipher
        B.writeFile ivfile iv
    else do  
        ciphertext <- B.readFile file 
        key <- B.readFile keyfile 
        iv <- B.readFile ivfile 
        B.writeFile outfile $ decrypt ciphertext (B.init key) iv
        
 
       
        
       
    
