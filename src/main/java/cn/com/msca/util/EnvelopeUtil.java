package cn.com.msca.util;

import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1BitString;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1Integer;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1ObjectIdentifier;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1OctetString;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1Sequence;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1Set;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1TaggedObject;
import cn.com.mcsca.pki.core.bouncycastle.asn1.DERBitString;
import cn.com.mcsca.pki.core.bouncycastle.asn1.DEROctetString;
import cn.com.mcsca.pki.core.bouncycastle.crypto.InvalidCipherTextException;
import cn.com.mcsca.pki.core.bouncycastle.crypto.engines.SM2Engine;
import cn.com.mcsca.pki.core.bouncycastle.crypto.engines.SM4Engine;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECPrivateKeyParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.KeyParameter;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import cn.com.mcsca.pki.core.bouncycastle.jce.provider.BouncyCastleProvider;
import cn.com.mcsca.pki.core.bouncycastle.util.Arrays;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author TangHaoKai
 * @version V1.0 2024/8/14 15:00
 */
public class EnvelopeUtil {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    /**
     * 解大陆云盾自己的加密密钥数字信封
     *
     * @param envelope 信封结构Base64
     * @param priHex   私钥HEX编码t
     * @return 私钥d
     * @throws NoSuchAlgorithmException   EC
     * @throws InvalidKeySpecException    私钥异常
     * @throws InvalidKeyException        私钥异常
     * @throws IOException                转换字节异常
     * @throws InvalidCipherTextException sm2解密异常
     * @throws NoSuchPaddingException     sm4解密异常
     * @throws IllegalBlockSizeException  sm4解密异常
     * @throws BadPaddingException        sm4解密异常
     */
    public static String openTheEnvelope(String envelope, String priHex) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, InvalidCipherTextException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        ASN1Sequence asn1_epk = (ASN1Sequence) ASN1Sequence.fromByteArray(Base64.decode(envelope));
        ASN1ObjectIdentifier pkcs7type = (ASN1ObjectIdentifier) asn1_epk.getObjectAt(0);
        if (pkcs7type.getId().equals("1.2.156.10197.6.1.4.2.4") || pkcs7type.getId().equals("1.2.156.10197.6.1.4.2.3")) {
            KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            //初始化sm2解密
            BCECPrivateKey pri = (BCECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(priHex)));
            ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(pri);
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(false, aPriv);

            ASN1TaggedObject dtos = (ASN1TaggedObject) asn1_epk.getObjectAt(1);
            ASN1Sequence asn1_encdata = (ASN1Sequence.getInstance(dtos.getObjectParser(16, true)));
            ASN1Set d1_pubkeyencs = (ASN1Set) asn1_encdata.getObjectAt(1);
            ASN1Sequence asn1_pubkeyenc = (ASN1Sequence) d1_pubkeyencs.getObjectAt(0);
            DEROctetString dertostr = (DEROctetString) asn1_pubkeyenc.getObjectAt(3);
            ASN1Sequence dd = (ASN1Sequence) ASN1Sequence.fromByteArray(dertostr.getOctets());
            ASN1Integer x = (ASN1Integer) dd.getObjectAt(0);
            byte[] xbyte = x.getPositiveValue().toByteArray();
            ASN1Integer y = (ASN1Integer) dd.getObjectAt(1);
            byte[] ybyte = y.getPositiveValue().toByteArray();
            DEROctetString hash = (DEROctetString) dd.getObjectAt(2);
            DEROctetString pubencdata = (DEROctetString) dd.getObjectAt(3);

            byte[] xy = new byte[65];
            xy[0] = 4;
            System.arraycopy(xbyte, xbyte.length == 32 ? 0 : 1, xy, 1, 32);
            System.arraycopy(ybyte, ybyte.length == 32 ? 0 : 1, xy, 1 + 32, 32);
            byte[] c2 = new byte[16];
            System.arraycopy(pubencdata.getOctets(), 0, c2, 0, 16);
            byte[] c3 = new byte[32];
            System.arraycopy(hash.getOctets(), 0, c3, 0, 32);
            byte[] c4 = Arrays.concatenate(xy, c2, c3);
            // sm2解密得到对称密钥的key
            byte[] sm4key = sm2Engine.processBlock(c4, 0, c4.length);

            ASN1Sequence encdata = (ASN1Sequence) asn1_encdata.getObjectAt(3);
            ASN1TaggedObject sm4encdatadto = (ASN1TaggedObject) encdata.getObjectAt(2);
            ASN1OctetString dstr_sm4encdata = (DEROctetString.getInstance(sm4encdatadto.getObjectParser(4, false)));
            byte[] sm4encdata = dstr_sm4encdata.getOctets();

            // sm4解密
            SecretKeySpec newKey = new SecretKeySpec(sm4key, "SM4");
            KeyParameter key = new KeyParameter(sm4key);

            byte[] bytes = SM4EngineDecrypt(sm4encdata, key);
            return Hex.toHexString(Arrays.copyOfRange(bytes, 32, bytes.length));
        } else {
            throw new RuntimeException("无效的SM2数字信封格式");
        }

    }

    public static String openEnvelopeBy35276(String encryptedPrivateKey, String signPri) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidCipherTextException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] envelopBytes = Base64.decode(encryptedPrivateKey);
        ASN1Sequence envelopeSequence = ASN1Sequence.getInstance(envelopBytes);
        // 这里是对称密钥密文
        ASN1Sequence symmetricKeyCipherSequence = ASN1Sequence.getInstance(envelopeSequence.getObjectAt(1));
        // 签名私钥
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        BCECPrivateKey pri = (BCECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(signPri)));
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(pri);

        // 解出对称密钥
        byte[] symmetricKeyBytes = decryptSM2Asn1SequenceStructCipher(aPriv, symmetricKeyCipherSequence);

        ASN1BitString encPriCipherBitString = DERBitString.getInstance(envelopeSequence.getObjectAt(3));
        byte[] encPriCipherBytes = encPriCipherBitString.getBytes();

        // sm4解密 解出加密私钥d
        KeyParameter key = new KeyParameter(symmetricKeyBytes);
        byte[] encPri = SM4EngineDecrypt(encPriCipherBytes, key);

        return Hex.toHexString(encPri);
    }

    /**
     * 解密Asn1结构的SM2密文
     *
     * @param pri      私钥
     * @param instance Asn1结构的SM2密文
     * @return 明文
     * @throws InvalidCipherTextException 非法密文
     */
    private static byte[] decryptSM2Asn1SequenceStructCipher(ECPrivateKeyParameters pri, ASN1Sequence instance) throws InvalidCipherTextException {
        ASN1Integer xCoord = ASN1Integer.getInstance(instance.getObjectAt(0));
        ASN1Integer yCoord = ASN1Integer.getInstance(instance.getObjectAt(1));
        ASN1OctetString c3 = DEROctetString.getInstance(instance.getObjectAt(2));
        ASN1OctetString c2 = DEROctetString.getInstance(instance.getObjectAt(3));

        byte[] xCorrected = removeLeadingZero(xCoord.getValue().toByteArray());
        byte[] yCorrected = removeLeadingZero(yCoord.getValue().toByteArray());
        // thk's todo 2024/7/30 11:22 这里有特殊情况，有时候会有00开头的坐标
        xCorrected = padTo32Bytes(xCorrected);
        yCorrected = padTo32Bytes(yCorrected);

        byte[] c3Bytes = c3.getOctets();
        byte[] c2Bytes = c2.getOctets();

        // 点编码应以0x04开头
        byte[] c1c3c2 = new byte[1 + xCorrected.length + yCorrected.length + c3Bytes.length + c2Bytes.length];
        c1c3c2[0] = 0x04; // 未压缩点指示器

        System.arraycopy(xCorrected, 0, c1c3c2, 1, xCorrected.length);
        System.arraycopy(yCorrected, 0, c1c3c2, 1 + xCorrected.length, yCorrected.length);
        System.arraycopy(c3Bytes, 0, c1c3c2, 1 + xCorrected.length + yCorrected.length, c3Bytes.length);
        System.arraycopy(c2Bytes, 0, c1c3c2, 1 + xCorrected.length + yCorrected.length + c3Bytes.length, c2Bytes.length);

        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(false, pri);
        return engine.processBlock(c1c3c2, 0, c1c3c2.length);
    }

    /**
     * 去掉首位0
     *
     * @param bytes Integer
     * @return Integer
     */
    private static byte[] removeLeadingZero(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
        return bytes;
    }

    /**
     * 00开头的坐标
     *
     * @param input Integer
     * @return Integer
     */
    private static byte[] padTo32Bytes(byte[] input) {
        if (input.length >= 32) {
            return input;
        }

        byte[] padded = new byte[32];
        int paddingLength = 32 - input.length;

        // 将输入数组复制到新数组的适当位置
        System.arraycopy(input, 0, padded, paddingLength, input.length);

        return padded;
    }

    /**
     * SM4解密
     *
     * @param ciphertext 密文
     * @param key        对称密钥
     * @return 明文
     */
    private static byte[] SM4EngineDecrypt(byte[] ciphertext, KeyParameter key) {
        SM4Engine engine = new SM4Engine();
        engine.init(false, key); // false 表示解密

        byte[] decryptedText = new byte[ciphertext.length];
        int offset = 0;

        // 分组解密，每次解密 16 字节
        while (offset < ciphertext.length) {
            engine.processBlock(ciphertext, offset, decryptedText, offset);
            offset += engine.getBlockSize();
        }

        return decryptedText;
    }

}