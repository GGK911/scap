package com.cn.msca.utl;

import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECDomainParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ECPrivateKeyParameters;
import cn.com.mcsca.pki.core.bouncycastle.crypto.params.ParametersWithID;
import cn.com.mcsca.pki.core.bouncycastle.crypto.signers.StandardDSAEncoding;
import cn.com.mcsca.pki.core.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import cn.com.mcsca.pki.core.bouncycastle.jce.ECNamedCurveTable;
import cn.com.mcsca.pki.core.bouncycastle.jce.provider.BouncyCastleProvider;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECParameterSpec;
import cn.com.mcsca.pki.core.bouncycastle.jce.spec.ECPrivateKeySpec;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Hex;
import cn.com.msca.util.SM2SignerEx;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author TangHaoKai
 * @version V1.0 2024/11/8 16:17
 */
public class SM2SignerExTest {

    private static final Provider BC = new BouncyCastleProvider();

    public static void main(String[] args) throws Exception {
        byte[] message = "abc".getBytes(StandardCharsets.UTF_8);
        // message = Hex.decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

        System.out.println("messageHEX>> " + Hex.toHexString(message));
        KeyFactory keyFact = KeyFactory.getInstance("EC", BC);
        BCECPrivateKey privateKey = (BCECPrivateKey) keyFact.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode("308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104202b3818d2c18042571bf1c5036633c57a8f7db85e3594c2a034c7b0d56bba8193a00a06082a811ccf5501822da1440342000403c97f54590b52fbd3d4e7beebf6e8b777e774c908ebf845875bf254bdbfdef0daa317e184ee64f65712f1b6d5bb98ae4c9371e43364791441d7712ee79e7f9a")));
        privateKey = parsePrivateFromD();
        // privateKey = (BCECPrivateKey) sm2_demo.privateKey;

        ECParameterSpec parameterSpec = privateKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());

        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), domainParameters);
        ParametersWithID parametersWithIDPri = new ParametersWithID(ecPrivateKeyParameters, Hex.decodeStrict("31323334353637383132333435363738"));

        SM2SignerEx signer = new SM2SignerEx(StandardDSAEncoding.INSTANCE);
        // SM2Signer signer = new SM2Signer(PlainDSAEncoding.INSTANCE);
        signer.init(true, ecPrivateKeyParameters);
        // signer.update(message, 0, message.length);
        // byte[] signBytes = signer.generateSignature();
        byte[] signBytes = signer.generateSignature(Hex.decode("d77baa524888f0bc9706a850c35de891e61d281e3039939c72ae52b781d37431"));
        System.out.println("signBase64>> " + Base64.toBase64String(signBytes));
        System.out.println("signHex>> " + Hex.toHexString(signBytes));
    }

    public static BCECPrivateKey parsePrivateFromD() {
        String dHex = "85C951B440045BB1F5CB81BED431AA1404ED8DBF11914EAD33EC16E7B1BDAD1B";
        dHex = "32ecf90216b997b83fb00ab838b1dbf985d714c5e95451a9f2e8a43c6d5c9e6d";
        ECNamedCurveParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECParameterSpec ecSpec = new ECParameterSpec(
                sm2Spec.getCurve(),
                sm2Spec.getG(),
                sm2Spec.getN(),
                sm2Spec.getH());
        BigInteger d2 = new BigInteger(1, Hex.decode(dHex));
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d2, ecSpec);
        BCECPrivateKey ecPriFromD = new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
        System.out.println("ecPriFromD>> " + Base64.toBase64String(ecPriFromD.getEncoded()));
        return ecPriFromD;
    }

}
