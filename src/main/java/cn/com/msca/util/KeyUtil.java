package cn.com.msca.util;


import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1Integer;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1ObjectIdentifier;
import cn.com.mcsca.pki.core.bouncycastle.asn1.ASN1Sequence;
import cn.com.mcsca.pki.core.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import cn.com.mcsca.pki.core.bouncycastle.crypto.CryptoException;
import cn.com.mcsca.pki.core.bouncycastle.crypto.digests.SM3Digest;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECDomainParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECPrivateKeyParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECPublicKeyParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.signers.DSAEncoding;
import cn.com.mcsca.pki.core.bouncycastle.crypto.signers.SM2Signer;
import cn.com.mcsca.pki.core.bouncycastle.crypto.signers.StandardDSAEncoding;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import cn.com.mcsca.pki.core.bouncycastle.jce.provider.BouncyCastleProvider;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECParameterSpec;
import cn.com.mcsca.pki.core.bouncycastle.pkcs.PKCS10CertificationRequest;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 密钥工具类（pki-core版本）
 *
 * @author TangHaoKai
 * @version V1.0 2024/8/7 11:40
 */
public class KeyUtil {

    static BouncyCastleProvider BC = new BouncyCastleProvider();

    /**
     * 打包公私密钥
     *
     * @param priStr 私钥
     * @param pubStr 公钥
     * @return KeyPair
     */
    public static KeyPair packagePriAndPub(String priStr, String pubStr) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PublicKey aPublic = KeyUtil.parsePubKey(pubStr);
        PrivateKey aPrivate = KeyUtil.parsePriKey(priStr);
        return new KeyPair(aPublic, aPrivate);
    }

    /**
     * des解密
     *
     * @param priCipherBytes 密文
     * @param aesKeyBytes    密钥
     * @return 明文
     */
    public static byte[] desDecrypt(byte[] priCipherBytes, byte[] aesKeyBytes) {
        SecretKey key = new SecretKeySpec(aesKeyBytes, "DESede");
        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(priCipherBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException("解密异常" + e.getMessage());
        }
    }

    /**
     * des加密
     *
     * @param text     明文
     * @param keyBytes 密钥
     * @return 密文
     */
    public static byte[] desEncrypt(byte[] text, byte[] keyBytes) {
        SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(text);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException("加密异常" + e.getMessage());
        }
    }

    /**
     * 获取算法从私钥或公钥中
     *
     * @param keyBytes KEY
     * @return KEY算法
     * @throws IOException KEY结构异常
     */
    public static String getAlgFromPriKeyOrPubKey(byte[] keyBytes) throws IOException {
        ASN1Sequence privateSequence = ASN1Sequence.getInstance(keyBytes);
        ASN1Sequence algSequence;
        if (privateSequence.getObjectAt(0) instanceof ASN1Integer) {
            algSequence = ASN1Sequence.getInstance(privateSequence.getObjectAt(1).toASN1Primitive().getEncoded());
        } else {
            algSequence = ASN1Sequence.getInstance(privateSequence.getObjectAt(0).toASN1Primitive().getEncoded());
        }
        ASN1ObjectIdentifier objectIdentifier = ASN1ObjectIdentifier.getInstance(algSequence.getObjectAt(0));
        String objectIdentifierString = objectIdentifier.toString();
        if (objectIdentifierString.equals("1.2.840.113549.1.1.1")) {
            return "RSA";
        } else if (objectIdentifierString.equals("1.2.840.10045.2.1")) {
            return "SM2";
        }
        return "";
    }

    /**
     * 私钥字符串转换对象
     *
     * @param pri 私钥字符串
     * @return 私钥对象
     * @throws NoSuchAlgorithmException 算法异常
     * @throws InvalidKeySpecException  KEY无效
     * @throws IOException              KEY获取算法异常
     */
    public static PrivateKey parsePriKey(String pri) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String alg = getAlgFromPriKeyOrPubKey(Base64.decode(pri));
        if (alg.isEmpty()) {
            throw new RuntimeException("识别算法异常");
        }
        KeyFactory keyFactory;
        if ("RSA".equals(alg)) {
            keyFactory = KeyFactory.getInstance("RSA");
        } else {
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        }
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(pri)));
    }

    /**
     * 公钥字符串转换对象
     *
     * @param pub 公钥
     * @return 公钥对象
     * @throws NoSuchAlgorithmException 算法异常
     * @throws InvalidKeySpecException  KEY无效
     * @throws IOException              KEY获取算法异常
     */
    public static PublicKey parsePubKey(String pub) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String alg = getAlgFromPriKeyOrPubKey(Base64.decode(pub));
        if (alg.isEmpty()) {
            throw new RuntimeException("识别算法异常");
        }
        KeyFactory keyFactory;
        if ("RSA".equals(alg)) {
            keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
        } else {
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        }
        return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decode(pub)));
    }

    /**
     * 获取公钥长度
     *
     * @param publicKey 公钥对象
     * @return 长度
     */
    public static int getKeyLengthFromPublicKey(PublicKey publicKey) {
        if (publicKey instanceof BCRSAPublicKey) {
            BCRSAPublicKey bcrsaPublicKey = (BCRSAPublicKey) publicKey;
            BigInteger modulus = bcrsaPublicKey.getModulus();
            return modulus.bitLength();
        } else if (publicKey instanceof BCECPublicKey) {
            return 256;
        }
        throw new RuntimeException("公钥异常");
    }

    /**
     * 获取公钥长度
     *
     * @param publicKeyStr 公钥对象
     * @return 长度
     * @throws NoSuchAlgorithmException 算法异常
     * @throws InvalidKeySpecException  KEY无效
     * @throws IOException              KEY获取算法异常
     */
    public static int getKeyLengthFromPublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        return getKeyLengthFromPublicKey(parsePubKey(publicKeyStr));
    }

    /**
     * sm2签名
     *
     * @param privateKey 私钥
     * @param message    原文
     * @param encoding   结构
     * @return 密文
     * @throws CryptoException 生成签名异常
     */
    public static byte[] sm2Sign(BCECPrivateKey privateKey, byte[] message, DSAEncoding encoding) throws CryptoException {
        encoding = encoding == null ? StandardDSAEncoding.INSTANCE : encoding;
        ECParameterSpec parameterSpec = privateKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), domainParameters);
        SM2Signer signer = new SM2Signer(encoding);
        signer.init(true, ecPrivateKeyParameters);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /**
     * sm2验签
     *
     * @param publicKey 公钥
     * @param message   签名原文
     * @param signBytes 签名值
     * @param encoding  签名结构
     * @return 验签结果
     */
    public static boolean sm2VerifySign(BCECPublicKey publicKey, byte[] message, byte[] signBytes, DSAEncoding encoding) {
        encoding = encoding == null ? StandardDSAEncoding.INSTANCE : encoding;
        ECParameterSpec parameterSpec = publicKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), domainParameters);
        SM2Signer signer = new SM2Signer(encoding, new SM3Digest());
        signer.init(false, publicKeyParameters);
        signer.update(message, 0, message.length);
        return signer.verifySignature(signBytes);
    }

    /**
     * 匹配SM2公私钥
     *
     * @param privateKey 私钥
     * @param publicKey  公钥
     * @return 是否匹配
     * @throws CryptoException 生成签名异常
     */
    public static boolean matchSM2PriAndPub(BCECPrivateKey privateKey, BCECPublicKey publicKey) throws CryptoException {
        byte[] message = "123".getBytes(StandardCharsets.UTF_8);
        return sm2VerifySign(publicKey, message, sm2Sign(privateKey, message, null), null);
    }

    /**
     * 匹配SM2公私钥
     *
     * @param privateKeyStr 私钥
     * @param publicKeyStr  公钥
     * @return 是否匹配
     * @throws CryptoException          生成签名异常
     * @throws NoSuchAlgorithmException 算法异常
     * @throws InvalidKeySpecException  KEY无效
     * @throws IOException              KEY获取算法异常
     */
    public static boolean matchSM2PriAndPub(String privateKeyStr, String publicKeyStr) throws CryptoException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PrivateKey privateKey = parsePriKey(privateKeyStr);
        PublicKey publicKey = parsePubKey(publicKeyStr);
        if (privateKey instanceof BCECPrivateKey && publicKey instanceof BCECPublicKey) {
            return matchSM2PriAndPub((BCECPrivateKey) privateKey, (BCECPublicKey) publicKey);
        }
        return false;
    }

    /**
     * 从证书中提取公钥
     *
     * @param publicKeyCert 公钥证书
     * @return 公钥
     * @throws CertificateException 证书异常
     */
    public static PublicKey extraPublicKeyFromCert(String publicKeyCert) throws CertificateException {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);
        X509Certificate certificate = (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(Base64.decode(publicKeyCert)));
        return certificate.getPublicKey();
    }

    /**
     * 从证书请求中提取公钥
     *
     * @param certRequest 证书请求
     * @return 公钥
     * @throws IOException              证书请求异常|获取公钥算法异常
     * @throws NoSuchAlgorithmException 提取公钥异常
     * @throws InvalidKeySpecException  提取公钥异常
     */
    public static PublicKey extraPublicKeyFromCSR(String certRequest) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(Base64.decode(certRequest));
        SubjectPublicKeyInfo subjectPublicKeyInfo = pkcs10CertificationRequest.getSubjectPublicKeyInfo();
        String alg = getAlgFromPriKeyOrPubKey(subjectPublicKeyInfo.getEncoded());
        KeyFactory keyFactory;
        if ("RSA".equalsIgnoreCase(alg)) {
            keyFactory = KeyFactory.getInstance("RSA");
        } else if ("SM2".equalsIgnoreCase(alg)) {
            keyFactory = KeyFactory.getInstance("EC", BC);
        } else {
            throw new RuntimeException("CSR公钥算法异常");
        }
        return keyFactory.generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded()));
    }

}
