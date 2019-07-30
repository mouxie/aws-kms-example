package com.yanmouxie.aws.sdk.java.v2;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.apache.ProxyConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

public class DataKeyAwsSDKv2 {

	final static String accessKeyId = "";
	final static String accessKeySecret = "";
	final static String keyArn = "";

	public static void main(String[] args) {

		AwsBasicCredentials awsCreds = AwsBasicCredentials.create(accessKeyId, accessKeySecret);

		ProxyConfiguration.Builder proxyConfig = ProxyConfiguration.builder();

		proxyConfig.endpoint(URI.create("http://proxy.com:8080"));

		ApacheHttpClient.Builder httpClientBuilder = ApacheHttpClient.builder().proxyConfiguration(proxyConfig.build());

		KmsClient kmsClient = KmsClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCreds))
				.region(Region.AP_SOUTHEAST_1).httpClientBuilder(httpClientBuilder).build();

		// Encrypt
		SdkBytes string = SdkBytes.fromUtf8String("ABCEDF");

		try {
			GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder().keyId(keyArn)
					.keySpec(DataKeySpec.AES_128).build();
			GenerateDataKeyResponse generateDataKeyResponse = kmsClient.generateDataKey(generateDataKeyRequest);

			SecretKeySpec key = new SecretKeySpec(generateDataKeyResponse.plaintext().asByteArray(), "AES");
			Cipher cipher;
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encodedSecret = cipher.doFinal(string.asByteArray());

			String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_Data.txt";
			writeToFile(SdkBytes.fromByteArray(encodedSecret), path);
			System.out.println("writeToFile:" + path);
			path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_DataKey.txt";
			writeToFile(generateDataKeyResponse.ciphertextBlob(), path);
			System.out.println("writeToFile:" + path);

			// Encrypt File
			encryptFile(key);

			System.out.println("Encrypt successfully.");
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		// Decrypt
		try {
			String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_DataKey.txt";
			SdkBytes sdkBytes = readFromFile(path);

			DecryptRequest decryptRequest = DecryptRequest.builder().ciphertextBlob(sdkBytes).build();
			DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);

			SecretKeySpec secretKeySpec = new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");

			path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_Data.txt";
			sdkBytes = readFromFile(path);

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			System.out.println("Decrypt successfully.");
			System.out.println(
					"Plaintext: " + SdkBytes.fromByteArray(cipher.doFinal(sdkBytes.asByteArray())).asUtf8String());

			// Decrypt File
			decryptFile(secretKeySpec);

			System.out.println("Done.");
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void writeToFile(SdkBytes bytesToWrite, String path) throws IOException {
		FileChannel fc;

		FileOutputStream outputStream = new FileOutputStream(path);
		fc = outputStream.getChannel();

		fc.write(bytesToWrite.asByteBuffer());
		outputStream.close();
		fc.close();
	}

	public static SdkBytes readFromFile(String path) throws IOException {

		InputStream in2 = new FileInputStream(path);
		return SdkBytes.fromInputStream(in2);
	}

	public static void encryptFile(SecretKeySpec key) {
		String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/1.jpeg";
		FileInputStream file;
		try {
			file = new FileInputStream(path);
			path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_1.jpeg";
			FileOutputStream outStream = new FileOutputStream(path);
			// byte k[]="AbcD3FGH1jKLMn52".getBytes();
			// SecretKeySpec key = new SecretKeySpec(k, "AES");
			Cipher enc = Cipher.getInstance("AES");
			enc.init(Cipher.ENCRYPT_MODE, key);
			CipherOutputStream cos = new CipherOutputStream(outStream, enc);
			byte[] buf = new byte[1024];
			int read;
			while ((read = file.read(buf)) != -1) {
				cos.write(buf, 0, read);
			}
			file.close();
			outStream.flush();
			cos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void decryptFile(SecretKeySpec key) {
		String path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Encrypted_1.jpeg";
		FileInputStream file;
		try {
			file = new FileInputStream(path);
			path = Paths.get(".").toAbsolutePath().normalize().toString() + "/Decrypted_1.jpeg";
			FileOutputStream outStream = new FileOutputStream(path);

			// byte k[]="AbcD3FGH1jKLMn52".getBytes();
			// SecretKeySpec key = new SecretKeySpec(k, "AES");

			Cipher enc = Cipher.getInstance("AES");
			enc.init(Cipher.DECRYPT_MODE, key);
			CipherOutputStream cos = new CipherOutputStream(outStream, enc);
			byte[] buf = new byte[1024];
			int read;
			while ((read = file.read(buf)) != -1) {
				cos.write(buf, 0, read);
			}
			file.close();
			outStream.flush();
			cos.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
