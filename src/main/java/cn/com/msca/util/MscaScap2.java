package cn.com.msca.util;

import cn.com.mcsca.pki.core.util.CertRequestUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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
 * @version V1.0 2024/11/16 15:56
 */
public class MscaScap2 implements SCAP {
    private final String ROOT_PATH;
    private static final String PRI_FILE_PATH = "PRI";
    private static final String RSA_PRI_FILE_PATH = "RSA_PRI";
    private static final String CERTS_PATH = "CERTS";
    private static final String RSA_CERTS_PATH = "RSA_CERTS";

    /**
     * 外部传入根路径
     *
     * @param root 根路径
     */
    public MscaScap2(String root) {
        ROOT_PATH = root.endsWith("\\") || root.endsWith("/") ? root : root + "\\";
    }

    //************************************************************************************//

    @Override
    public String genP10ByPin(String pin, String keyType, String keyLength) {
        String priAndPub = checkPinCode(pin, keyType, keyLength);
        try {
            return genP10(keyType, priAndPub);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new RuntimeException("生成P10异常" + e.getMessage());
        }
    }

    @Override
    public boolean importCert(String certBase64) {
        return false;
    }

    @Override
    public boolean importDoubleCert(String signCertBase64, String encCertBase64, String encPriEnvelop) {
        return false;
    }

    @Override
    public String getCertByCertSerialNumber(String certSN) {
        return null;
    }

    @Override
    public List<String> getAllCertSerialNumber() {
        return null;
    }

    @Override
    public boolean changePin(String oldPin, String newPin) {
        return false;
    }

    @Override
    public String signMessage(String pin, String inData, String hashAlg, String signType, String certBase64) {
        return null;
    }

    @Override
    public String signHashMessage(String pin, byte[] hash, String hashAlg, String signType, String certBase64) {
        return null;
    }

    @Override
    public String envelopEncryptMessage(byte[] inData, String certBase64, String symKeyAlg) {
        return null;
    }

    @Override
    public byte[] envelopDecryptMessage(String pin, String envelop, String certBase64) {
        return new byte[0];
    }

    @Override
    public Map<String, String> parseCert(byte[] cert) {
        return null;
    }

    //************************************************************************************//

    /**
     * 检查指定类型长度的私钥和公钥
     *
     * @param pin       PIN码
     * @param keyType   密钥类型：RSA|SM2
     * @param keyLength 密钥长度：1024|2048|4096|256
     * @return 私钥和公钥
     */
    public String checkPinCode(String pin, String keyType, String keyLength) {
        File pinPriFile = getPriFile(ROOT_PATH, keyType, keyLength);
        // 要检查的key文件是否存在
        if (pinPriFile.exists()) {
            System.out.println("存在PIN码，开始验证PIN正确性");
            // 用pin码解密priAndPub
            String priAndPub = new String(PinUtil.pinDecodePriAndPub(pin, read(pinPriFile.getParentFile(), pinPriFile.getName())), StandardCharsets.UTF_8);
            System.out.println(String.format("%-16s", "priAndPub>> ") + priAndPub);
            return priAndPub;
        } else {
            System.out.println("不存在PIN码，开始初始化PIN私钥");
            return PinUtil.createPriAndPub(pin, keyType, Integer.parseInt(keyLength), pinPriFile);
        }
    }

    //************************************************************************************//

    /**
     * 根据KEY类型和长度获取KEY文件路径
     *
     * @param rootPath  根路径
     * @param keyType   密钥类型：RSA|SM2
     * @param keyLength 密钥长度：1024|2048|4096|256
     * @return KEY文件路径
     */
    public static File getPriFile(String rootPath, String keyType, String keyLength) {
        // 默认SM2 256
        keyType = keyType == null || keyType.isEmpty() ? "SM2" : keyType;
        keyLength = keyLength == null || keyLength.isEmpty() ? "256" : keyLength;
        String priFileParentPath = keyType.equalsIgnoreCase("SM2") ? PRI_FILE_PATH : RSA_PRI_FILE_PATH;
        String priFilePath = keyType + keyLength + ".key";
        return new File(new File(rootPath, priFileParentPath), priFilePath);
    }

    public static void write(File dir, String fileName, byte[] content) {
        if (dir != null) {
            File file = new File(dir, fileName);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(content);
                fos.flush();
            } catch (IOException e) {
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
            return null;
        }
    }

    /**
     * 生成P10
     *
     * @param keyType   密钥类型：RSA|SM2
     * @param priAndPub 私钥和公钥
     * @return P10的Base64字符串
     */
    private String genP10(String keyType, String priAndPub) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String alg;
        if (keyType.equalsIgnoreCase("RSA")) {
            alg = "SHA1withRSA";
        } else {
            alg = "SM3withSm2";
        }
        String[] priAndPubArray = priAndPub.split(",");
        return new String(CertRequestUtil.generateP10(alg, "CN=MSCA", KeyUtil.packagePriAndPub(priAndPubArray[0], priAndPubArray[1])));
    }

}
