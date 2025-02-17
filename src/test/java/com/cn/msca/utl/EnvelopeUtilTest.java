package com.cn.msca.utl;

import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Base64;
import cn.com.mcsca.pki.core.bouncycastle.util.encoders.Hex;
import cn.com.msca.util.EnvelopeUtil;

/**
 * @author TangHaoKai
 * @version V1.0 2024/11/8 16:13
 */
public class EnvelopeUtilTest {
    public static void main(String[] args) throws Exception {
        // String d = openTheEnvelope("MIIEQgYKKoEcz1UGAQQCBKCCBDIwggQuAgEBMYHTMIHQAgEAMEEwLTELMAkGA1UEBhMCQ04xDjAMBgNVBAoMBU1DU0NBMQ4wDAYDVQQDDAVNQ1NDQQIQZVqJYUlGpXieHix1naIv5DALBgkqgRzPVQGCLQMEezB5AiAgK9wa49cBIvO58/qC1nS1Z9/cB6Awh98vZiTtgloEowIhAOrtGTj6iFqlfJoDuKVI2zj0EHVJlDak6UNIPKE5NB4wBCDmDE2XGH9MEaMmczijdbEZZKEvx16MLOyTW3DJr8BNOgQQ3iecE4GecLE+OD32WlKpKjEMMAoGCCqBHM9VAYMRMFkGCiqBHM9VBgEEAgEwCQYHKoEcz1UBaIBA1dWxOCmjmEv+swk5PzjiQdXVsTgpo5hL/rMJOT844kGPwwytJnvKxXH1saRj89Chvg/ahKwKuj0v4UIUd/JetaCCAe8wggHrMIIBj6ADAgECAhBmGlO15VIwOaiyxJ6pnaeUMAwGCCqBHM9VAYN1BQAweDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCUNob25ncWluZzE6MDgGA1UECgwxRWFzdC1aaG9uZ3h1biBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPLkxURDEZMBcGA1UEAwwQRWFzdC1aaG9uZ3h1biBDQTAeFw0yMzA4MTcwMTI4MzNaFw0zMzA4MTQwMTI4MzNaMC8xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVNQ1NDQTEQMA4GA1UEAwwHU00yU0lHTjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABCA6bLiYQEN5maqDtr6rfmqg5/v+GhZHlIDdoQ/SWQ+Hc3SedRXcMas5oWfBUAZ+Nko2nc1+1LMWsRJi4DgDr36jQjBAMB8GA1UdIwQYMBaAFAnuuwf+H95XmJJu7j/LUmpL+SYdMB0GA1UdDgQWBBSJqOoC7mJ441HP32hg8CmGbLpezDAMBggqgRzPVQGDdQUAA0gAMEUCIBnnZHGxXcc7Ar6Wzd3NJ+8Da5TwK8Jn8J7S8p4xsPmwAiEAmW7lerdM1A6+7W4BEfLh69J/fC+d+Hzzx2h/ohWLKQkxgfYwgfMCAQEwgYwweDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCUNob25ncWluZzE6MDgGA1UECgwxRWFzdC1aaG9uZ3h1biBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPLkxURDEZMBcGA1UEAwwQRWFzdC1aaG9uZ3h1biBDQQIQZhpTteVSMDmossSeqZ2nlDAKBggqgRzPVQGDETALBgkqgRzPVQGCLQEERjBEAiA4XRuZ24bg5alWcsNJ1GERgLUoo664xGWEeccVq6E14wIgbND2lEEoCuHflcPtKsDJ1v1fgaE3Y4lIkLpg26/J64A=", "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420d873c87879974f477e293da9487907b04046c485820d21e0f0e3c0dd305daa4ca00a06082a811ccf5501822da14403420004e86cf685cc7e32a061435b295dd4b6697a54a965456c9d45df9f314fc594d2df7eb3d1d8dc9e6dbc3403cf4ce22c4a7184f1c8d790084e7c9714185c366651ba");
        // System.out.println(String.format("%-16s", "d>> ") + d);

        // String cipher = "MIH9BgoqgRzPVQYBBAIDoIHuMIHrAgECMYGnMIGkAgECgBQyMvOOpzGo/qOrNpcmAS5Xms5wLTANBgkqgRzPVQGCLQMFAAR6MHgCIGCk/XRAQWREzUfKY9cCZaPrsovhSXU4+VfXqA3N6PGBAiAD4dkcVx+YVjVvAmgC2GxeDX7UuTJgNhWKhwD5g4lBawQgdvIZKmy7UuldupfD5qBBzhMK2duTwR00P19561mS7xUEEDm9F1f+1AxpV1qKaMv2u1wwPAYKKoEcz1UGAQQCATAcBggqgRzPVQFoAgQQMPdqjH2h6wecMRk+JvRyMoAQ9GM/xRa55D7JL3AD7PDmqw==";
        //
        // String certBase64 = "MIICvDCCAmGgAwIBAgIQX/CynFAMUO9dMkp04m65KTAMBggqgRzPVQGDdQUAMC0xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVNQ1NDQTEOMAwGA1UEAwwFTUNTQ0EwHhcNMjQwOTA1MDgzNzU4WhcNMjQwOTE3MDgzNzU4WjB+MQswCQYDVQQGEwJDTjEOMAwGA1UECgwFTUNTQ0ExEDAOBgNVBAsMB2xvY2FsUkExGzAZBgNVBAUMEjkxMzcxNzIxTUEzREs4TTA1RDEwMC4GA1UEAwwnMTc2NTIyNTIyMzAwNDcwMDY3MkDmtYvor5Xop6Plr4ZAMDFAMDA1MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEzMWdsNMbBzgkuuzD0Ilq0XeryO1IBDyjMPEBTehn+0A1p7HNAfUS9EqzRW+QHl1yuK9wzIO/U2+LCJpJZ/9+IqOCAQ4wggEKMAsGA1UdDwQEAwIEMDCBugYDVR0fBIGyMIGvMC6gLKAqhihodHRwOi8vd3d3Lm1jc2NhLmNvbS5jbi9zbTIvY3JsL2NybDAuY3JsMH2ge6B5hndsZGFwOi8vd3d3Lm1jc2NhLmNvbS5jbjozODkvQ049Y3JsMCxPVT1DUkwsTz1NQ1NDQSxDPUNOP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDAdBgNVHQ4EFgQUMjLzjqcxqP6jqzaXJgEuV5rOcC0wHwYDVR0jBBgwFoAU8SIKZ5iN9eOyqsMXa8BCH75LvXYwDAYIKoEcz1UBg3UFAANHADBEAiBcF+z5hVBw3+NwErbYL69AbqpZ5INQ3yZZWhENANdLfgIgUkcv4tatWYaEzHPxlNZmLuLWn3w6Cy9N9pHQt3fCUfU=";
        // String priAndPub = "SM2256,MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyrT/eFL79ntte+R5ERWgr0JWxu3Jnkj/+ku2PTI8KWegCgYIKoEcz1UBgi2hRANCAARTR5lso64vQc+LkzQzpK09/TzlCLQ4e4Mk7WGAESbn/Lr0OqKYUmZahvaU+tyJdg7cIgsXnjRwIz07g3SO6e5X,MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEU0eZbKOuL0HPi5M0M6StPf085Qi0OHuDJO1hgBEm5/y69DqimFJmWob2lPrciXYO3CILF540cCM9O4N0junuVw==";
        // String[] split = priAndPub.split(",");
        // String s = EnvelopeUtil.openTheEnvelope(cipher, Hex.toHexString(Base64.decode(split[1])));

        String envelopStr = "MIHvMAwGCCqBHM9VAWgBBQAweAIgbQSLGtF8oJbVaWLNmSJtYPzJG+BSROAlVuPs4rUkMV0CICG4LbHOgStoBWcT2uC7dPfQQ4AsesScxp3E/xY44qVHBCAh2tnJW1BvBwnvGmMkiiLggYxw+NPfY74Q4AvGSlGigQQQFlZgT8O1uvAfH/szbpxwmQNCAARcgunsnEAZ608lGv2Gs2Fzu7CjfKpBamrlQJqfQFxOeTyerI5mV6BpqFApXTCct8rPSGwJmSn6N2VyugdlhrF3AyEAW7IZghjiA44pU4flSHwZXwsWWjSoQcF6nfmIh+0EmGg=";
        String signPriStr = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042021bff20c5327279848fb1e62e7e3e4d4257adbf897c1dacadb69bd1a6dd7a60ca00a06082a811ccf5501822da144034200044d6b118e8dc1318daf1e86254c25285c5d2943ba4e941e2fea4ce7b73af94e47af9e985b6bcb1bf968220bdb67324c82b3b7e53ca37cbd3b7d1c9779e572b4d6";

        String encPriStr = EnvelopeUtil.openEnvelopeBy35276(envelopStr, signPriStr);
        System.out.println(String.format("%-16s", "encPriStr>> ") + encPriStr);




    }
}
