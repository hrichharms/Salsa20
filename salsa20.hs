import Data.Word
import Data.Bits
import qualified Data.ByteString as B


type Bytes = B.ByteString


rotateList :: Int -> [a] -> [a]
rotateList n [] = []
rotateList 1 x = [last x] ++ init x
rotateList n x = rotateList (n - 1) (rotateList 1 x)


quarterround :: (Word32, Word32, Word32, Word32) -> [Word32]
quarterround (y0, y1, y2, y3) = [z0, z1, z2, z3]
    where z1 = y1 `xor` ((y0 + y3) `rotateL` 7)
          z2 = y2 `xor` ((z1 + y0) `rotateL` 9)
          z3 = y3 `xor` ((z2 + z1) `rotateL` 13)
          z0 = y0 `xor` ((z3 + z2) `rotateL` 18)


rowround :: [Word32] -> [Word32]
rowround x = r0 ++ r1 ++ r2 ++ r3
    where r0 = quarterround (x !! 0, x !! 1, x !! 2, x !! 3)
          r1 = rotateList 1 (quarterround (x !! 5, x !! 6, x !! 7, x !! 4))
          r2 = rotateList 2 (quarterround (x !! 10, x !! 11, x !! 8, x !! 9))
          r3 = rotateList 3 (quarterround (x !! 15, x !! 12, x !! 13, x !! 14))


colround :: [Word32] -> [Word32]
colround x = [c0 !! 0, c1 !! 0, c2 !! 0, c3 !! 0,
              c0 !! 1, c1 !! 1, c2 !! 1, c3 !! 1,
              c0 !! 2, c1 !! 2, c2 !! 2, c3 !! 2,
              c0 !! 3, c1 !! 3, c2 !! 3, c3 !! 3]
    where c0 = quarterround (x !! 0, x !! 4, x !! 8, x !! 12)
          c1 = rotateList 1 (quarterround (x !! 5, x !! 9, x !! 13, x !! 1))
          c2 = rotateList 2 (quarterround (x !! 10, x !! 14, x !! 2, x !! 6))
          c3 = rotateList 3 (quarterround (x !! 15, x !! 3, x !! 7, x !! 11))


doubleround :: [Word32] -> [Word32]
doubleround x = rowround (colround x)


littleendian :: Bytes -> Word32
littleendian b = b0 + (b1 `shiftL` 8) + (b2 `shiftL` 16) + (b3 `shiftL` 24)
    where b0 = fromIntegral (B.index b 0)
          b1 = fromIntegral (B.index b 1)
          b2 = fromIntegral (B.index b 2)
          b3 = fromIntegral (B.index b 3)


littleendian_inv :: Word32 -> Bytes
littleendian_inv x = B.pack [b0, b1, b2, b3]
    where b0 = fromIntegral x
          b1 = fromIntegral (x `shiftR` 8)
          b2 = fromIntegral (x `shiftR` 16)
          b3 = fromIntegral (x `shiftR` 24)


chunk :: Int -> Bytes -> [Bytes]
chunk n b = if B.length b > n then
                [B.take n b] ++ chunk n (B.drop n b)
            else
                [B.take n b]


s20Hash :: Bytes -> Bytes
s20Hash s = B.concat (map littleendian_inv (map a (zip z x)))
    where a = \ (a, b) -> a + b
          x = map littleendian (chunk 4 s)
          z = (iterate doubleround x) !! 10


s20Expansion :: Bytes -> Bytes -> Bytes
s20Expansion k n = if B.length k == 32 then
                       let (k0, k1) = B.splitAt 16 k in
                       s20Hash(B.concat [s0, k0, s1, n, s2, k1, s3])
                   else
                       s20Hash(B.concat [t0, k, t1, n, t2, k, t3])
    where s0 = B.pack [101, 120, 112,  97] -----
          s1 = B.pack [110, 100,  32,  51] --
          s2 = B.pack [ 50,  45,  98, 121] -- Constants for 256-bit keys
          s3 = B.pack [116, 101,  32, 107] --
          t0 = B.pack [101, 120, 112,  97] -----
          t1 = B.pack [110, 100,  32,  49] --
          t2 = B.pack [ 54,  45,  98, 121] -- Constants for 128-bit keys
          t3 = B.pack [116, 101,  32, 107] --


s20Keystream :: Int -> Bytes -> Bytes -> Bytes
s20Keystream n k v = B.concat [s20Expansion k nv, s20Keystream (n + 8) k v]
    where nv = B.concat [v, littleendian_inv (fromIntegral n)]


xorMask :: Bytes -> Bytes -> Bytes
xorMask x y = B.pack (map t_xor (zip a b))
    where t_xor = \ (c, d) -> c `xor` d
          a = B.unpack x
          b = B.unpack y


s20Encrypt :: Bytes -> Bytes -> Bytes -> Bytes
s20Encrypt k v m = xorMask (s20Keystream 0 k v) m


main :: IO()
main = do

    -- print( quarterround (0, 0, 0, 0) )
    -- print( quarterround (1, 0, 0, 0) )
    -- print( quarterround (0, 1, 0, 0) )
    -- print( quarterround (0, 0, 1, 0) )
    -- print( quarterround (0, 0, 0, 1) )
    -- print( quarterround(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137) )
    -- print( quarterround(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b) )

    -- print( rowround [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0] )
    -- print( rowround [0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365, 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6, 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e, 0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a] )

    -- print( doubleround [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    -- print( littleendian (B.pack [0, 0, 0, 0]) )
    -- print( littleendian (B.pack [86, 75, 30, 9]) )
    -- print( littleendian (B.pack [255, 255, 255, 250]) )

    -- print( littleendian_inv 0 )
    -- print( littleendian_inv 152980310 )
    -- print( littleendian_inv 4211081215 )

    -- print( B.pack [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] )
    -- print( chunk 4 (B.pack [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) )

    -- print( s20Hash (B.pack [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) )

    -- print( s20Hash (B.pack [211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49, 237, 179, 48,  1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54]) )

    -- print( s20Expansion (B.pack [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216]) (B.pack [101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116]) )
