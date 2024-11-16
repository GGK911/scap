package cn.com.msca.util;

import java.util.List;
import java.util.Map;

/**
 * 移动CA需实现的方法(这层方法只接受PIN码)
 *
 * @author TangHaoKai
 * @version V1.0 2024/9/9 14:09
 */
public interface SCAP {

    /**
     * 通过PIN码获取证书申请P10
     *
     * @param pin       PIN码
     * @param keyType   密钥类型：RSA|SM2
     * @param keyLength 密钥长度：1024|2048|4096|256
     * @return 证书申请P10
     */
    String genP10ByPin(String pin, String keyType, String keyLength);

    /**
     * 导入证书
     *
     * @param certBase64 证书Base64
     * @return 是否导入成功
     */
    boolean importCert(String certBase64);

    /**
     * 导入双证
     *
     * @param signCertBase64 签名证书Base64
     * @param encCertBase64  加密证书Base64
     * @param encPriEnvelop  加密私钥数字信封Base64
     * @return 是否导入成功
     */
    boolean importDoubleCert(String signCertBase64, String encCertBase64, String encPriEnvelop);

    /**
     * 通过证书序列号获取证书
     *
     * @param certSN 证书序列号
     * @return 证书Base64
     */
    String getCertByCertSerialNumber(String certSN);

    /**
     * 获取所有证书序列号
     *
     * @return 所有证书序列号
     */
    List<String> getAllCertSerialNumber();

    /**
     * 更换PIN码
     *
     * @param oldPin 老PIN码
     * @param newPin 新PIN码
     * @return 是否更换成功
     */
    boolean changePin(String oldPin, String newPin);

    /**
     * 签名
     *
     * @param pin        PIN码
     * @param inData     签名原文
     * @param hashAlg    摘要算法
     * @param signType   签名类型：P1|P7_ATTACH|P7_DETACH
     * @param certBase64 P7需要用到的公钥证书Base64
     * @return 签名值
     */
    String signMessage(String pin, String inData, String hashAlg, String signType, String certBase64);

    /**
     * 裸签名（传原文的hash值）
     *
     * @param pin        PIN码
     * @param hash       签名原文的摘要值
     * @param hashAlg    摘要算法
     * @param signType   签名类型：P1|P7_ATTACH|P7_DETACH
     * @param certBase64 P7需要用到的公钥证书Base64
     * @return 签名值
     */
    String signHashMessage(String pin, byte[] hash, String hashAlg, String signType, String certBase64);

    /**
     * 数字信封加密
     *
     * @param inData     信封加密原文
     * @param certBase64 公钥证书
     * @param symKeyAlg  对称加密算法
     * @return 数字信封
     */
    String envelopEncryptMessage(byte[] inData, String certBase64, String symKeyAlg);

    /**
     * 解密数字信封
     *
     * @param pin        PIN码
     * @param envelop    数字信封
     * @param certBase64 公钥证书
     * @return 信封里的原文
     */
    byte[] envelopDecryptMessage(String pin, String envelop, String certBase64);

    /**
     * 解析证书
     *
     * @param cert 证书
     * @return 需要解析的有：
     * notBefore起始时间
     * notAfter结束时间
     * serialNumber证书SN
     * issuerDN颁发者DN
     * subjectDN使用者DN
     * publicKey公钥Base64
     * certType证书类型：SM2|RSA
     * subjectCN通用CN项
     * certBase64证书Base64编码
     */
    Map<String, String> parseCert(byte[] cert);

}

