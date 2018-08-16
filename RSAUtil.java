package com.ai.runner.sdiot.system.utils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

/**
 * 
 * @Description
 * 
 * 				加密：公钥加密，私钥解密
 * 
 *              签名：私钥加密，公钥解密
 * 
 * @author wangdk3@asiainfo.com
 * @date 2018年8月14日
 *
 */
public class RSAUtil {

	// 非对称密钥算法
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * 密钥长度，64的倍数
	 */
	private static final int KEY_SIZE = 2048;
	// 公钥
	private static final String PUBLIC_KEY = "RSAPublicKey";
	// 私钥
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	private static Map<String, Object> keyMap;

	private RSAUtil() {
	}

	public static void initKeys() {
		// 实例化密钥生成器
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			// 初始化密钥生成器
			keyPairGenerator.initialize(KEY_SIZE);
			// 生成密钥对
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			// 甲方公钥
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			// 甲方私钥
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			// 将密钥存储在map中
			keyMap = new HashMap<String, Object>();
			keyMap.put(PUBLIC_KEY, publicKey);
			keyMap.put(PRIVATE_KEY, privateKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new ExceptionInInitializerError(e.getMessage());
		}
	}

	/**
	 * 
	 * @param keyMap
	 * @return 获取公钥
	 */
	public static String getPrivateKey() {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return Base64.encodeBase64String(key.getEncoded());
	}

	/**
	 * 
	 * @param keyMap
	 * @return 获取私钥
	 */
	public static String getPublicKey() {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return Base64.encodeBase64String(key.getEncoded());
	}

	/**
	 * 私钥加密
	 * 
	 */
	public static String encryptByPrivateKey(String data, String privatekey) throws Exception {
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privatekey));
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return Base64.encodeBase64String(cipher.doFinal(data.getBytes()));
	}

	/**
	 * 公钥加密
	 * 
	 */
	public static String encryptByPublicKey(String data, String publickey) throws Exception {

		// 实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// 初始化公钥
		// 密钥材料转换
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publickey));
		// 产生公钥
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		// 数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return Base64.encodeBase64String(cipher.doFinal(data.getBytes()));
	}

	/**
	 * 私钥解密
	 */
	public static String decryptByPrivateKey(String data, String privatekey) throws Exception {
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privatekey));
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(Base64.decodeBase64(data)));
	}

	/**
	 * 公钥解密
	 * 
	 */
	public static String decryptByPublicKey(String data, String publicKey) throws Exception {
		// 实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		// 初始化公钥
		// 密钥材料转换
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
		// 产生公钥
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		// 数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		cipher.init(Cipher.DECRYPT_MODE, pubKey);

		return new String(cipher.doFinal(Base64.decodeBase64(data)));
	}

	public static void main(String[] args) {
		try {
			// 初始化 公钥/私钥
			RSAUtil.initKeys();
			String data1 = "补漏洞";
			String data2 = "打补丁";
			String privateKey = RSAUtil.getPrivateKey();
			String publicKey = RSAUtil.getPublicKey();
			System.out.println("私钥---private:" + privateKey);
			System.out.println("公钥----public:" + publicKey);
			System.out.println("--公钥加密----私钥解密---");
			System.out.println("原文数据：" + data1);
			String publicEncrypt1 = RSAUtil.encryptByPublicKey(data1, publicKey);
			System.out.println("公钥加密结果：" + publicEncrypt1);
			String privateDecrypt1 = RSAUtil.decryptByPrivateKey(publicEncrypt1, privateKey);
			System.out.println("私钥-\\-解密-\\-结果:" + privateDecrypt1);
			System.out.println("##################################################");
			System.err.println("---私钥加密----公钥解密--");
			System.err.println("原文数据：" + data2);
			String publicEncrypt2 = RSAUtil.encryptByPrivateKey(data2, privateKey);
			System.err.println("私钥加密结果：" + publicEncrypt1);
			String privateDecrypt2 = RSAUtil.decryptByPublicKey(publicEncrypt2, publicKey);
			System.err.println("公钥-/-解密-/-结果:" + privateDecrypt2);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
