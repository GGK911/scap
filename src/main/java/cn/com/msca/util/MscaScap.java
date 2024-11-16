package cn.com.msca.util;

import cn.com.mcsca.pki.core.bouncycastle.asn1.x500.RDN;
import cn.com.mcsca.pki.core.bouncycastle.asn1.x500.X500Name;
import cn.com.mcsca.pki.core.bouncycastle.asn1.x500.style.BCStyle;
import cn.com.mcsca.pki.core.bouncycastle.crypto.CryptoException;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECDomainParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECPrivateKeyParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.signers.StandardDSAEncoding;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import cn.com.mcsca.pki.core.bouncycastle.jce.ECNamedCurveTable;
import cn.com.mcsca.pki.core.bouncycastle.jce.provider.BouncyCastleProvider;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECParameterSpec;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECPrivateKeySpec;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Hex;
import cn.com.mcsca.pki.core.util.CertRequestUtil;
import cn.com.mcsca.pki.core.util.CertUtil;
import cn.com.mcsca.pki.core.util.SignatureUtil;
import cn.com.mcsca.pki.core.x509.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 这里将证书，私钥，全放本地，目录结构：
 * ROOT_PATH/
 * ├── PRI/
 * │   └── PIN.key
 * └── certs/
 * x   ├── SINGLE,SN1/
 * x   │   └── SN1.cer
 * x   └── DOUBLE,SN2,ENC-SN3/
 * x       ├── SN2.cer
 * x       ├── SN3.key
 * x       └── SN3.cer
 *
 * @author TangHaoKai
 * @version V1.0 2024/8/9 10:21
 */
public class MscaScap {
    private final String ROOT_PATH;
    private static final String PRI_FILE_PATH = "PRI\\PIN.key";
    private static final String CERTS_PATH = "CERTS\\";

    public MscaScap(String root) {
        ROOT_PATH = root.endsWith("\\") || root.endsWith("/") ? root : root + "\\";
    }

    /**
     * 生成p10
     */
    public String generateCertReq(String certType, String pin, String certSys) {
        // 单双 这里对于我们来说单双都不影响，只是cfca这里是特殊的P10，先不管
        // 这里肯定是拿pin取私钥，私钥生成P10
        if ("SINGLE".equals(certSys)) {

        } else {

        }
        // 检查pin
        String priAndPub;
        try {
            priAndPub = checkPinCode(pin, certType);
            if (priAndPub.isEmpty()) {
                throw new RuntimeException("验证pin失败");
            }
        } catch (IOException e) {
            throw new RuntimeException("检查pin文件异常" + e.getMessage());
        }
        // 证书类型
        try {
            byte[] p10Bytes = genP10(priAndPub);
            return Base64.toBase64String(p10Bytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new RuntimeException("生成P10异常" + e.getMessage());
        }
    }

    /**
     * 导入单证
     */
    public boolean importCertificate(String strCert) {
        X509Certificate cert = new X509Certificate(Base64.decode(strCert));
        String sn = cert.getSerialNumber().toString(16).toUpperCase();
        checkCertsDir();
        checkRepeatCert(sn);
        File cerDir = new File(ROOT_PATH + CERTS_PATH, "SINGLE," + sn);
        if (!cerDir.mkdir()) {
            throw new RuntimeException("创建证书文件目录失败" + sn);
        } else {
            File cerFile = new File(cerDir, sn + ".cer");
            try {
                write(cerFile.getParentFile(), cerFile.getName(), Base64.decode(strCert));
            } catch (Exception e) {
                throw new RuntimeException("保存证书文件失败" + e.getMessage());
            }
            return true;
        }
    }

    /**
     * 导入双证
     */
    public boolean importDoubleCertificate(String strSignCert, String strEncryptCert, String strPri) {
        X509Certificate cert = new X509Certificate(Base64.decode(strSignCert));
        X509Certificate encX509Cert = new X509Certificate(Base64.decode(strEncryptCert));
        String sn = cert.getSerialNumber().toString(16).toUpperCase();
        String encSn = encX509Cert.getSerialNumber().toString(16).toUpperCase();
        checkCertsDir();
        checkRepeatCert(sn);
        File cerDir = new File(ROOT_PATH + CERTS_PATH, "DOUBLE," + sn + "," + encSn);
        if (!cerDir.mkdir()) {
            throw new RuntimeException("创建证书文件目录失败" + sn);
        } else {
            try {
                File cerFile = new File(cerDir, sn + ".cer");
                write(cerFile.getParentFile(), cerFile.getName(), Base64.decode(strSignCert));
                X509Certificate encCert = new X509Certificate(Base64.decode(strEncryptCert));
                String encCertSn = encCert.getSerialNumber().toString(16).toUpperCase();
                File encCerFile = new File(cerDir, encCertSn + ".cer");
                write(encCerFile.getParentFile(), encCerFile.getName(), Base64.decode(strEncryptCert));
                File encKeyFile = new File(cerDir, encCertSn + ".key");
                write(encKeyFile.getParentFile(), encKeyFile.getName(), Base64.decode(strPri));
            } catch (Exception e) {
                throw new RuntimeException("保存证书文件失败" + e.getMessage());
            }
            return true;
        }
    }

    /**
     * 获取所有证书SN
     */
    public List<String> getCertificatesSn() {
        checkCertsDir();
        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        List<String> certSns = new ArrayList<>();
        for (File file : cersDir.listFiles()) {
            if (file.isDirectory() && file.getName().split(",").length == 2) {
                certSns.add(file.getName().split(",")[1]);
            } else if (file.isDirectory() && file.getName().split(",").length == 3) {
                certSns.add(file.getName().split(",")[1]);
                certSns.add(file.getName().split(",")[2]);
            }
        }
        return certSns;
    }

    /**
     * 修改PIN码
     */
    public String changePassword(String oldPin, String newPin, String serialNo) {
        if (updatePinCode(oldPin, newPin)) {
            System.out.println("修改PIN成功");
            // thk's todo 2024/8/12 11:40 这里返回什么？？
            return "true";
        } else {
            return "false";
        }
    }

    /**
     * 获取所有证书
     */
    public List<String> getCertificates() {
        return getAllCerts();
    }

    /**
     * 签名
     */
    public String signMessage(String pinCode, byte[] srcData, String hashType, String signType, String certBase64) {
        String priAndPub;
        try {
            priAndPub = checkPinCode(pinCode, "");
        } catch (IOException e) {
            throw new RuntimeException("PIN验证异常" + e.getMessage());
        }
        String certType = priAndPub.split(",")[0];
        String pri = priAndPub.split(",")[1];
        PrivateKey privateKey;
        try {
            privateKey = KeyUtil.parsePriKey(pri);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new RuntimeException("私钥转换失败" + e.getMessage());
        }
        String rsaAlg = "SHA256withRSA";
        if (certType.contains("RSA")) {
            if (hashType.equals("HASH_SHA1")) {
                rsaAlg = "SHA1withRSA";
            } else if (hashType.equals("HASH_SHA256")) {
                rsaAlg = "SHA256withRSA";
            } else if (hashType.equals("HASH_SHA384")) {
                rsaAlg = "SHA384withRSA";
            } else if (hashType.equals("HASH_SHA512")) {
                rsaAlg = "SHA512withRSA";
            } else if (hashType.equals("HASH_MD5_SHA1")) {
                rsaAlg = "MD5withRSA";
            } else {
                System.out.println("摘要算法为空，默认SHA256");
            }
        }
        if ("SIGN_PKCS1".equals(signType)) {
            if (certType.equalsIgnoreCase("SM2256")) {
                byte[] p1MessageSign = SignatureUtil.P1MessageSign("SM3WITHSM2", srcData, privateKey);
                return new String(p1MessageSign, StandardCharsets.UTF_8);
            } else if (certType.equalsIgnoreCase("RSA1024") || certType.equalsIgnoreCase("RSA2048")) {
                byte[] p1MessageSign = SignatureUtil.P1MessageSign(rsaAlg, srcData, privateKey);
                return new String(p1MessageSign, StandardCharsets.UTF_8);
            }
        } else if ("SIGN_PKCS7_A".equals(signType)) {
            X509Certificate cert = new X509Certificate(Base64.decode(certBase64));
            if (certType.equalsIgnoreCase("SM2256")) {
                byte[] p7MessageSignAttach = SignatureUtil.P7MessageSignAttach("SM3WITHSM2", srcData, privateKey, cert);
                return new String(p7MessageSignAttach, StandardCharsets.UTF_8);
            } else {
                byte[] p7MessageSignAttach = SignatureUtil.P7MessageSignAttach(rsaAlg, srcData, privateKey, cert);
                return new String(p7MessageSignAttach, StandardCharsets.UTF_8);
            }
        } else if ("SIGN_PKCS7_D".equals(signType)) {
            X509Certificate cert = new X509Certificate(Base64.decode(certBase64));
            if (certType.equalsIgnoreCase("SM2256")) {
                byte[] p7MessageSignDetach = SignatureUtil.P7MessageSignDetach("SM3WITHSM2", srcData, privateKey, cert);
                return new String(p7MessageSignDetach, StandardCharsets.UTF_8);
            } else {
                byte[] p7MessageSignAttach = SignatureUtil.P7MessageSignDetach(rsaAlg, srcData, privateKey, cert);
                return new String(p7MessageSignAttach, StandardCharsets.UTF_8);
            }
        }
        throw new RuntimeException("签名异常");
    }

    /**
     * 裸签
     */
    public String signHash(String pinCode, byte[] hashData, String hashType, String signType, String certBase64) {
        // thk's todo 2024/8/13 10:10 有个问题,这里的hash只针对sm2吗? RSA哪来的直接传hash?
        String priAndPub;
        try {
            priAndPub = checkPinCode(pinCode, "");
        } catch (IOException e) {
            throw new RuntimeException("PIN验证异常" + e.getMessage());
        }
        String certType = priAndPub.split(",")[0];
        String pri = priAndPub.split(",")[1];
        PrivateKey privateKey;
        try {
            privateKey = KeyUtil.parsePriKey(pri);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new RuntimeException("私钥转换失败" + e.getMessage());
        }
        String rsaAlg = "SHA256withRSA";
        if (certType.contains("RSA")) {
            if (hashType.equals("HASH_SHA1")) {
                rsaAlg = "SHA1withRSA";
            } else if (hashType.equals("HASH_SHA256")) {
                rsaAlg = "SHA256withRSA";
            } else if (hashType.equals("HASH_SHA384")) {
                rsaAlg = "SHA384withRSA";
            } else if (hashType.equals("HASH_SHA512")) {
                rsaAlg = "SHA512withRSA";
            } else if (hashType.equals("HASH_MD5_SHA1")) {
                rsaAlg = "MD5withRSA";
            } else {
                System.out.println("摘要算法为空，默认SHA256");
            }
        }
        if ("SIGN_PKCS1".equals(signType)) {
            if (certType.equalsIgnoreCase("SM2256")) {
                BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
                ECParameterSpec parameterSpec = bcecPrivateKey.getParameters();
                ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());
                ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), domainParameters);

                SM2SignerEx signer = new SM2SignerEx(StandardDSAEncoding.INSTANCE);
                signer.init(true, ecPrivateKeyParameters);
                byte[] p1MessageSign;
                try {
                    p1MessageSign = signer.generateSignature(hashData);
                } catch (CryptoException e) {
                    throw new RuntimeException("hash签名异常" + e.getMessage());
                }
                return Base64.toBase64String(p1MessageSign);
            } else if (certType.equalsIgnoreCase("RSA1024") || certType.equalsIgnoreCase("RSA2048")) {
                byte[] p1MessageSign = SignatureUtil.P1MessageSign(rsaAlg, hashData, privateKey);
                return new String(p1MessageSign, StandardCharsets.UTF_8);
            }
        } else if ("SIGN_PKCS7_A".equals(signType)) {
            // thk's todo 2024/8/13 10:38
        } else if ("SIGN_PKCS7_D".equals(signType)) {
            // thk's todo 2024/8/13 10:39
        }
        throw new RuntimeException("签名异常");
    }

    /**
     * 数字信封加密
     */
    public String envelopeEncryptMessage(byte[] plaintext, String certBase64, String alg) {
        X509Certificate x509Certificate = new X509Certificate(Base64.decode(certBase64));
        System.out.println(String.format("%-16s", "signAlg>> ") + x509Certificate.getSignatureAlgorithmName());
        String asyAlg;
        if ("1.2.156.10197.1.501".equalsIgnoreCase(x509Certificate.getSignatureAlgorithmName())) {
            asyAlg = "SM4CBC";
        } else {
            if (alg.equals("ALG_RC4")) {
                asyAlg = "RC4";
            } else {
                asyAlg = "DESEDECBC";
            }
        }
        X509Certificate[] certificates = new X509Certificate[]{x509Certificate};
        byte[] envelopeMessage = cn.com.mcsca.pki.core.util.EnvelopeUtil.envelopeMessage(plaintext, asyAlg, certificates);
        return new String(envelopeMessage, StandardCharsets.UTF_8);
    }

    /**
     * 数字信封解密(弃用)
     */
    // public byte[] envelopeDecryptMessage(String pin, String ciphertext, String certBase64) {
    //     // thk's todo 2024/8/13 10:43 解数字信封,这里用msca的结构?? RSA的应该是两段
    //     String priAndPub;
    //     try {
    //         priAndPub = checkPinCode(pin, "");
    //     } catch (IOException e) {
    //         throw new RuntimeException("校验PIN异常" + e.getMessage());
    //     }
    //     String keyType = priAndPub.split(",")[0];
    //     if ("sm2256".equalsIgnoreCase(keyType)) {
    //         String oriTextHex;
    //         try {
    //             oriTextHex = certTest.EnvelopeUtil2.openTheEnvelope(ciphertext, Hex.toHexString(Base64.decode(certBase64)));
    //         } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | IOException |
    //                  InvalidCipherTextException | NoSuchPaddingException | IllegalBlockSizeException |
    //                  BadPaddingException e) {
    //             throw new RuntimeException("解信封异常" + e.getMessage());
    //         }
    //         return Hex.decode(oriTextHex);
    //     }
    //     throw new RuntimeException("非sm2信封结构");
    // }

    /**
     * 数字信封解密
     */
    public byte[] envelopeDecryptMessage2(String pin, String ciphertext, String certBase64) {
        // thk's todo 2024/8/13 10:43 解数字信封,这里用msca的结构?? RSA的应该是两段
        String priAndPub;
        try {
            priAndPub = checkPinCode(pin, "");
        } catch (IOException e) {
            throw new RuntimeException("校验PIN异常" + e.getMessage());
        }
        // 测试
        if ("sm2256".equalsIgnoreCase(priAndPub.split(",")[0])) {
            String oriTextHex;
            try {
                X509Certificate x509Certificate = new X509Certificate(Base64.decode(certBase64));
                // 判断这里的证书是签名证书还是加密证书，才能去拿哪个私钥
                String sn = x509Certificate.getSerialNumber().toString(16).toUpperCase();
                // 根据SN找KEY
                String encPriKeyBase64 = getCertPriKeyWithSn(sn, pin);

                certBase64 = "MIIDYTCCAwWgAwIBAgIQEboPEd6tiTH2nJQOJsGRUDAMBggqgRzPVQGDdQUAMC0xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVNQ1NDQTEOMAwGA1UEAwwFTUNTQ0EwHhcNMjQxMTE2MDUwMDQ3WhcNMjUxMTE2MDUwMDQ3WjCBoDELMAkGA1UEBhMCQ04xIzAhBgkqhkiG9w0BCQEWFHpoYW5nc2FuQGV4YW1wbGUuY29tMWwwagYDVQQDDGM1NmM1MjBjMGQ3YjNiZmYxZDhmYTJkYjhhN2QyMmQ5YkDlpKfpmYbkupHnm77nlLXlrZDorqTor4HmnI3liqHmnInpmZDlhazlj7hATjY0NjQzNDI0NTY0MzQzNDU0NUAwMDEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARcgunsnEAZ608lGv2Gs2Fzu7CjfKpBamrlQJqfQFxOeTyerI5mV6BpqFApXTCct8rPSGwJmSn6N2VyugdlhrF3o4IBjzCCAYswDAYDVR0TBAUwAwEBADAdBgNVHQ4EFgQUPufjp3UPdXr6fa0KuQW01jk/mMgwgboGA1UdHwSBsjCBrzAuoCygKoYoaHR0cDovL3d3dy5tY3NjYS5jb20uY24vc20yL2NybC9jcmwwLmNybDB9oHugeYZ3bGRhcDovL3d3dy5tY3NjYS5jb20uY246Mzg5L0NOPWNybDAsT1U9Q1JMLE89TUNTQ0EsQz1DTj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Y2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwCwYDVR0PBAQDAgQwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMFwGCCsGAQUFBwEBBFAwTjAoBggrBgEFBQcwAoYcaHR0cDovLzEyNy4wLjAuMS9jYWlzc3VlLmh0bTAiBggrBgEFBQcwAYYWaHR0cDovLzEyNy4wLjAuMToyMDQ0MzAfBgNVHSMEGDAWgBTxIgpnmI3147KqwxdrwEIfvku9djAMBggqgRzPVQGDdQUAA0gAMEUCID1iD59k4sIFwS4auFNWQ3Zys9SStTRf7H7Hz77Gu9h8AiEAxrdBW049bJvp1UGVAZUE16AsqJ3ux7hmQ02+Zv+MXms=";
                x509Certificate = new X509Certificate(Base64.decode(certBase64));
                // 加密
                encPriKeyBase64 = "MIICBQIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBBIIBDzCCAQsCAQEEIMiugagYuzeYuWlX1f5aK04KKg6qNeuDWNc5X/7F6Uy+oIHjMIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD//////////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQE=";
                // // 签名
                // // encPriKeyBase64 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgIb/yDFMnJ5hI+x5i5+Pk1CV62/iXwdrK22m9Gm3XpgygCgYIKoEcz1UBgi2hRANCAARNaxGOjcExja8ehiVMJShcXSlDuk6UHi/qTOe3OvlOR6+emFtryxv5aCIL22cyTIKzt+U8o3y9O30cl3nlcrTW";
                ciphertext = "MIAGCiqBHM9VBgEEAgOggDCAAgECMYGoMIGlAgECgBQ+5+OndQ91evp9rQq5BbTWOT+YyDANBgkqgRzPVQGCLQMFAAR7MHkCIFcyw7xnrgCN3PGEfeiqaV+AWx/d9GCQIghRZGnSBiFUAiEAjWlAaWaFFEvm5B4nc6ONENhk+lHfq4tNEuK41IZ4uRwEIO4FYFH6UV0rEqK2PvuXCmU91Zipax55wEZSqjUJtAbMBBBfB8QVV4lnwABgHI5TBmyiMIAGCiqBHM9VBgEEAgEwHAYIKoEcz1UBaAIEECqEz2ALAUJULvNdBxfNHA2ggAQQzoOScrfm/NFeZ3JZP6AIUgAAAAAAAAAAAAA=";
                ciphertext = "MIAGCiqBHM9VBgEEAgOggDCAAgECMYGoMIGlAgECgBQ+5+OndQ91evp9rQq5BbTWOT+YyDANBgkqgRzPVQGCLQMFAAR7MHkCIB/uU8JmYe2s2jnvcOJXs+OB/VbOSrTXokY2qq9aHl+PAiEAzxLgftkArVbSF7v3mF/zwTLEgPPmya7gmGGI2YUC9IIEIF7o3n3BOj2FUNCPG8p4ppzpmJlvh+mMyjMHh3q9oBU1BBBfuYM+BxaJ26ZdQVy/W98vMIAGCiqBHM9VBgEEAgEwHAYIKoEcz1UBaAIEEPJlCxL/HTFrhZP33m+D0KeggAQQBqQvSvsPU1VN50LsoCWFKQAAAAAAAAAAAAA=";

                KeyFactory fact = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
                PrivateKey encPrivateKey = fact.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(encPriKeyBase64)));

                byte[] parseEnvelopedMessage = cn.com.mcsca.pki.core.util.EnvelopeUtil.parseEnvelopedMessage(ciphertext.getBytes(StandardCharsets.UTF_8), encPrivateKey, x509Certificate);
                oriTextHex = Hex.toHexString(parseEnvelopedMessage);
            } catch (Exception e) {
                throw new RuntimeException("解信封异常" + e.getMessage());
            }
            return Hex.decode(oriTextHex);
        }
        throw new RuntimeException("非sm2信封结构");
    }

    /**
     * 解析证书
     */
    public Map<String, Object> parseCertificateBase64(String certificateBase64) {
        return parseCert(certificateBase64);
    }

    /**
     * 根据证书SN查询证书
     */
    public Map<String, Object> getCertificateWithSn(String sn) {
        checkCertsDir();
        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        for (File certDir : cersDir.listFiles()) {
            if (certDir.isDirectory() && (certDir.getName().split(",")[1].equalsIgnoreCase(sn) || certDir.getName().split(",")[2].equalsIgnoreCase(sn))) {
                for (File certFile : certDir.listFiles()) {
                    if (certFile.getName().split("\\.")[0].equalsIgnoreCase(sn)) {
                        byte[] certBytes;
                        try {
                            certBytes = read(certFile.getParentFile(), certFile.getName());
                        } catch (Exception e) {
                            throw new RuntimeException("读取SN证书异常" + e);
                        }
                        return parseCert(Base64.toBase64String(certBytes));
                    }
                }
            }
        }
        return new HashMap<>(0);
    }


    //*****************************************未实现**********************************************//
    public String generateTimestampReq(byte[] src, String hashType) {
        // 没有
        return null;
    }

    public boolean addCertificate(String certType, String pin, String certSys) {
        // thk's todo 2024/8/13 11:10 没懂什么意思??
        return false;
    }

    public boolean generateTimestampResp(String req) {
        // 没有
        return false;
    }

    public String updateTimestampInPKCS7Signature(byte[] pkcs7Signature, byte[] timestampResp) {
        // 没有
        return null;
    }

    public String encodePKCS7SignatureWithTimestamp(byte[] pkcs1Signature, byte[] certificate, byte[] timestampResp, byte[] src, boolean withSrc, String hash) {
        // 没有
        return null;
    }

    public void cancelAddCertificate() {
        // 没有
    }

    public byte[] sm2dh(String certificate, String pin, byte[] ra, byte[] Pb, byte[] Rb, int keylen) {
        // 没有
        return new byte[0];
    }

    public void importCertificate(String sign, String encryption, String key) {
        // 没有
    }

    public void deleteCertificate(String certificate) {
        // 没有
    }

    public void clearCertificates() {
        // 没有
    }

    //***************************************内部方法********************************************//

    /**
     * 根据证书SN找这张证书的私钥
     */
    private String getCertPriKeyWithSn(String sn, String pinCode) {
        checkCertsDir();
        // 先去拿PRI下的key，如果所有双证的加密证书SN都不匹配，再最后返回这个key
        String priAndPub;
        try {
            priAndPub = checkPinCode(pinCode, "");
        } catch (IOException e) {
            throw new RuntimeException("获取单证的KEY异常：" + e.getMessage());
        }
        String signPri = priAndPub.split(",")[1];

        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        for (File certDir : cersDir.listFiles()) {
            // 双证
            if ("DOUBLE".equalsIgnoreCase(certDir.getName().split(",")[0])) {
                // 加密的SN
                if (certDir.isDirectory() && certDir.getName().split(",")[2].equalsIgnoreCase(sn)) {
                    for (File certFile : certDir.listFiles()) {
                        if (sn.equalsIgnoreCase(certFile.getName().split("\\.")[0]) && "key".equalsIgnoreCase(certFile.getName().split("\\.")[1])) {
                            try {
                                // 解加密私钥的信封（不是普通的信封）
                                String encPriEnvelop = Base64.toBase64String(Files.readAllBytes(certFile.toPath()));
                                // thk's todo 2024/11/15 18:14 因为CA互认的加密私钥数字信封是35276特殊格式,之前对的是大陆自己的格式
                                String encD = EnvelopeUtil.openEnvelopeBy35276(encPriEnvelop, Hex.toHexString(Base64.decode(signPri)));
                                // String encD = EnvelopeUtil.openTheEnvelope(encPriEnvelop, Hex.toHexString(Base64.decode(signPri)));
                                ECNamedCurveParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
                                ECParameterSpec ecSpec = new ECParameterSpec(
                                        sm2Spec.getCurve(),
                                        sm2Spec.getG(),
                                        sm2Spec.getN(),
                                        sm2Spec.getH());
                                KeyFactory fact = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
                                BigInteger d1 = new BigInteger(1, Hex.decode(encD));
                                PrivateKey encPrivateKey = fact.generatePrivate(new ECPrivateKeySpec(d1, ecSpec));
                                return Base64.toBase64String(encPrivateKey.getEncoded());
                            } catch (Exception e) {
                                throw new RuntimeException("获取加密证书KEY读取异常：" + e.getMessage());
                            }
                        }
                    }
                    throw new RuntimeException("加密SN相等，却找不到KEY");
                }
            }
        }
        return signPri;
    }

    private void checkCertsDir() {
        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        if (!cersDir.exists()) {
            if (!cersDir.mkdir()) {
                throw new RuntimeException("创建证书列表目录失败");
            }
        }
    }

    private List<String> getAllCerts() {
        checkCertsDir();
        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        if (!cersDir.exists()) {
            return new ArrayList<>(0);
        }
        List<String> certList = new ArrayList<>();
        for (File certDir : cersDir.listFiles()) {
            if (certDir.isDirectory()) {
                String singleOrDouble = certDir.getName().split(",")[0];
                String SN = certDir.getName().split(",")[1];
                for (File certFile : certDir.listFiles()) {
                    if (certFile.isFile() && (certFile.getName().split("\\.")[0].equalsIgnoreCase(SN) || (singleOrDouble.equals("DOUBLE") && certFile.getName().split("\\.")[1].equalsIgnoreCase("cer")))) {
                        byte[] certBytes;
                        try {
                            certBytes = read(certFile.getParentFile(), certFile.getName());
                        } catch (Exception e) {
                            throw new RuntimeException("获取证书文件异常" + e.getMessage());
                        }
                        certList.add(Base64.toBase64String(certBytes));
                    }
                }
            }
        }
        return certList;
    }

    private void checkRepeatCert(String sn) {
        File cersDir = new File(ROOT_PATH + CERTS_PATH);
        for (File file : cersDir.listFiles()) {
            if (file.isDirectory()) {
                if (file.getName().equalsIgnoreCase("SINGLE," + sn) || file.getName().equalsIgnoreCase("DOUBLE," + sn)) {
                    throw new RuntimeException("此证书SN重复导入");
                }
            }
        }
    }

    public boolean updatePinCode(String oldPin, String newPin) {
        if (oldPin.equalsIgnoreCase(newPin)) {
            throw new IllegalArgumentException("重复PIN修改");
        }
        String priAndPub;
        try {
            priAndPub = checkPinCode(oldPin, "");
        } catch (IOException e) {
            throw new RuntimeException("oldPin验证异常" + e.getMessage());
        }
        // 用pin码加密priAndPub
        // DESede
        byte[] aesKey = pinToKey(newPin);
        SecretKey secretKey = new SecretKeySpec(aesKey, "DESede");
        // 对称加密
        byte[] encrypt = DESencrypt(priAndPub.getBytes(StandardCharsets.UTF_8), secretKey);
        File pinPriFile = new File(ROOT_PATH + PRI_FILE_PATH);
        try {
            if (!pinPriFile.delete()) {
                throw new RuntimeException("删除OLDPRI文件异常");
            }
            write(pinPriFile.getParentFile(), pinPriFile.getName(), encrypt);
        } catch (Exception e) {
            throw new RuntimeException("写入私钥文件失败" + e.getMessage());
        }
        return true;
    }

    public String checkPinCode(String PIN, String certType) throws IOException {
        File pinPriFile = new File(ROOT_PATH + PRI_FILE_PATH);
        if (!pinPriFile.exists()) {
            System.out.println("不存在PIN码，开始初始化PIN私钥");
            if (!pinPriFile.getParentFile().exists()) {
                if (!pinPriFile.getParentFile().mkdirs()) {
                    System.out.println("创建目录异常");
                    throw new RuntimeException("创建目录异常");
                }
            }
            if (certType.isEmpty()) {
                throw new IllegalArgumentException("certType为空，不存在现有PIN码，无法操作");
            }
            // 生成私钥
            String alg = certType.substring(0, 3);
            String keyLength = certType.substring(3);
            KeyPair keyPair = cn.com.mcsca.pki.core.util.KeyUtil.generateKeyPair(alg, Integer.parseInt(keyLength));
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();
            String priBase64 = Base64.toBase64String(aPrivate.getEncoded());
            String pubBase64 = Base64.toBase64String(aPublic.getEncoded());
            String priAndPub = certType + "," + priBase64 + "," + pubBase64;
            // 用pin码加密priAndPub
            // DESede
            byte[] aesKey = pinToKey(PIN);
            SecretKey secretKey = new SecretKeySpec(aesKey, "DESede");
            // 对称加密
            byte[] encrypt = DESencrypt(priAndPub.getBytes(StandardCharsets.UTF_8), secretKey);
            // 验证下
            // System.out.println("验证下>> " + new String(DESdecrypt(encrypt, secretKey), StandardCharsets.UTF_8));
            write(pinPriFile.getParentFile(), pinPriFile.getName(), encrypt);
            return priAndPub;
        } else {
            // System.out.println("存在PIN码，开始验证PIN正确性");
            byte[] encData = read(pinPriFile.getParentFile(), pinPriFile.getName());
            // 用pin码解密priAndPub
            // DESede
            byte[] aesKey = pinToKey(PIN);
            SecretKey secretKey = new SecretKeySpec(aesKey, "DESede");
            byte[] decrypt = new byte[0];
            try {
                decrypt = DESdecrypt(encData, secretKey);
            } catch (Exception e) {
                throw new IllegalArgumentException("输入PIN错误");
            }
            String priAndPub = new String(decrypt);
            String keyType = priAndPub.split(",")[0];
            if (!certType.isEmpty() && !keyType.equalsIgnoreCase(certType)) {
                throw new IllegalArgumentException("要操作的密钥类型跟现有密钥类型不一致");
            }
            // System.out.println("解密>> " + priAndPub);
            return priAndPub;
        }
    }

    public void importPriAndPub(String priAndPub, String PIN) {
        File pinPriFile = new File(ROOT_PATH + PRI_FILE_PATH);
        if (!pinPriFile.exists()) {
            System.out.println("不存在PIN码，开始初始化PIN私钥");
            if (!pinPriFile.getParentFile().exists()) {
                if (!pinPriFile.getParentFile().mkdirs()) {
                    System.out.println("创建目录异常");
                    throw new RuntimeException("创建目录异常");
                }
            }
        }

        // 用pin码加密priAndPub
        // DESede
        byte[] aesKey = pinToKey(PIN);
        SecretKey secretKey = new SecretKeySpec(aesKey, "DESede");
        // 对称加密
        byte[] encrypt = DESencrypt(priAndPub.getBytes(StandardCharsets.UTF_8), secretKey);
        // 验证下
        // System.out.println("验证下>> " + new String(DESdecrypt(encrypt, secretKey), StandardCharsets.UTF_8));
        write(pinPriFile.getParentFile(), pinPriFile.getName(), encrypt);
    }

    private static byte[] md5(String pin) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("摘要异常" + e.getMessage());
        }
        byte[] hashInBytes = md.digest(pin.getBytes(StandardCharsets.UTF_8));
        return hashInBytes;
    }

    private static byte[] pinToKey(String pin) {
        // 摘要一下
        byte[] hashInBytes = md5(pin);
        // 将摘要作为密钥（这里位数不足，循环填充）
        // 填充24位的DESede
        byte[] aesKey = new byte[24];
        fillArray(aesKey, hashInBytes);
        return aesKey;
    }

    public static void fillArray(byte[] A, byte[] B) {
        int lengthB = B.length;
        int lengthA = A.length;

        // 逐个填充A
        for (int i = 0; i < lengthA; i++) {
            A[i] = B[i % lengthB];
        }
    }

    private static byte[] DESencrypt(byte[] text, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(text);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException("加密异常" + e.getMessage());
        }
    }

    private static byte[] DESdecrypt(byte[] encryptedText, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException("解密异常" + e.getMessage());
        }
    }

    private static byte[] genP10(String priAndPub) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final String[] priAndPubArray = priAndPub.split(",");
        final String certType = priAndPubArray[0];
        final String priBase64 = priAndPubArray[1];
        final String pubBase64 = priAndPubArray[2];
        String alg;
        if (certType.toUpperCase().contains("RSA")) {
            alg = "SHA1withRSA";
        } else {
            alg = "SM3withSm2";
        }
        final PublicKey aPublic = KeyUtil.parsePubKey(pubBase64);
        final PrivateKey aPrivate = KeyUtil.parsePriKey(priBase64);
        String subjectParam = "CN=MCSCA";
        return Base64.decode(CertRequestUtil.generateP10(alg, subjectParam, new KeyPair(aPublic, aPrivate)));
    }

    private static Map<String, Object> parseCert(String certificateBase64) {
        Map<String, Object> parseCertMap = new HashMap<>();
        byte[] certBytes = Base64.decode(certificateBase64);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certBytes);
        java.security.cert.X509Certificate x509Certificate = CertUtil.getX509Certificate(inputStream);
        parseCertMap.put("notBefore", x509Certificate.getNotBefore());
        parseCertMap.put("notAfter", x509Certificate.getNotAfter());
        try {
            parseCertMap.put("certEncode", Base64.toBase64String(x509Certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("getEncoded异常" + e.getMessage());
        }
        parseCertMap.put("serialNumber", Hex.toHexString(x509Certificate.getSerialNumber().toByteArray()));
        parseCertMap.put("issuerDN", x509Certificate.getIssuerDN().toString());
        String subjectDN = x509Certificate.getSubjectDN().toString();
        parseCertMap.put("subjectDN", subjectDN);
        parseCertMap.put("publicKey", Base64.toBase64String(x509Certificate.getPublicKey().getEncoded()));
        String sigAlgName = x509Certificate.getSigAlgName();
        if (sigAlgName.toLowerCase().contains("sm2")) {
            parseCertMap.put("certType", "SM2");
        } else {
            int keyLength = KeyUtil.getKeyLengthFromPublicKey(x509Certificate.getPublicKey());
            parseCertMap.put("certType", "RSA" + keyLength);
        }
        parseCertMap.put("subjectCN", getCNFromDN(subjectDN));

        parseCertMap.put("certBase64", certificateBase64);
        return parseCertMap;
    }

    /**
     * 从证书DN中获取到CN项
     *
     * @param DN DN字符串
     * @return CN项
     */
    public static String getCNFromDN(String DN) {
        X500Name x500Name = new X500Name(DN);
        return getCNFromX500Name(x500Name);
    }

    /**
     * 从证书DN中获取到CN项
     *
     * @param subject X500Name对象
     * @return CN项
     */
    public static String getCNFromX500Name(X500Name subject) {
        RDN[] rdNs = subject.getRDNs(BCStyle.CN);
        if (rdNs.length > 0) {
            return rdNs[0].getFirst().getValue().toString();
        }
        return subject.toString();
    }

    public static void write(File dir, String fileName, byte[] content) {
        if (dir != null) {
            File file = new File(dir, fileName);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(content);
                fos.flush();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException("写入文件异常");
            }
        }
    }

    public static byte[] read(File dir, String fileName) {
        if (dir == null) {
            return null;
        }
        File file = new File(dir, fileName);
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void printAllCertDir() {
        File dir = new File(ROOT_PATH, CERTS_PATH);
        if (dir.isDirectory()) {
            for (File certFile : dir.listFiles()) {
                if (certFile.isDirectory()) {
                    File[] files = certFile.listFiles();
                    for (File item : files) {
                        System.out.println(certFile.getName() + "/" + item.getName());
                    }
                }
            }
        }
    }

}
