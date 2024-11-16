package cn.com.msca.util;

import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * PIN码相关工具
 *
 * @author TangHaoKai
 * @version V1.0 2024/11/16 16:37
 */
public class PinUtil {

    /**
     * 生成公钥和私钥
     *
     * @param pin        PIN码
     * @param keyType    密钥类型：RSA|SM2
     * @param keyLength  密钥长度：1024|2048|4096|256
     * @param pinPriFile 报错路径
     * @return 公钥和私钥
     */
    public static String createPriAndPub(String pin, String keyType, int keyLength, File pinPriFile) {
        KeyPair keyPair = cn.com.mcsca.pki.core.util.KeyUtil.generateKeyPair(keyType, keyLength);
        String priBase64 = Base64.toBase64String(keyPair.getPrivate().getEncoded());
        String pubBase64 = Base64.toBase64String(keyPair.getPublic().getEncoded());
        String priAndPub = priBase64 + "," + pubBase64;
        // 用pin码加密priAndPub
        // DESede
        byte[] aesKey = pinToKey(pin);
        byte[] pinPriBytes = KeyUtil.desEncrypt(priAndPub.getBytes(StandardCharsets.UTF_8), aesKey);
        MscaScap2.write(pinPriFile.getParentFile(), pinPriFile.getName(), pinPriBytes);
        return priAndPub;
    }

    /**
     * PIN码解析加密了的私钥和公钥
     *
     * @param pin      PIN码
     * @param priBytes 加密了的私钥和公钥
     * @return 私钥和公钥
     */
    public static byte[] pinDecodePriAndPub(String pin, byte[] priBytes) {
        return KeyUtil.desDecrypt(priBytes, pinToKey(pin));
    }

    /**
     * 将PIN码转为对称密钥
     *
     * @param pin PIN码
     * @return 对称密钥
     */
    public static byte[] pinToKey(String pin) {
        // 摘要一下
        byte[] hashInBytes = md5(pin);
        // 将摘要作为密钥（这里位数不足，循环填充）
        // 填充24位的DESede
        byte[] aesKey = new byte[24];
        fillArray(aesKey, hashInBytes);
        return aesKey;
    }

    //************************************************************************************//

    private static byte[] md5(String pin) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("摘要异常" + e.getMessage());
        }
        return md.digest(pin.getBytes(StandardCharsets.UTF_8));
    }

    private static void fillArray(byte[] A, byte[] B) {
        int lengthB = B.length;
        int lengthA = A.length;
        // 逐个填充A
        for (int i = 0; i < lengthA; i++) {
            A[i] = B[i % lengthB];
        }
    }

}
