package com.yanmouxie.aws.sdk.java.v2;

import java.net.URI;

import com.amazonaws.encryptionsdk.internal.Utils;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.apache.ProxyConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;

public class KmsAwsSDKJavaV2 {

	final static String accessKeyId = "";
	final static String accessKeySecret = "";
	final static String keyArn = "";
	
	public static void main(String[] args) {
		
		AwsBasicCredentials awsCreds = AwsBasicCredentials.create(accessKeyId,accessKeySecret);
		
		ProxyConfiguration.Builder proxyConfig =
		        ProxyConfiguration.builder();
		
		proxyConfig.endpoint(URI.create("http://proxy.com:8080"));
		

		ApacheHttpClient.Builder httpClientBuilder = 
		        ApacheHttpClient.builder()
		                        .proxyConfiguration(proxyConfig.build());
		
		KmsClient kmsClient = KmsClient.builder()
			       .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
			       .region(Region.AP_SOUTHEAST_1)
			       .httpClientBuilder(httpClientBuilder)
			       .build();
		
		//Encrypt
		SdkBytes string = SdkBytes.fromUtf8String("ABCEDF");
		
		EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyArn).plaintext(string).build();
		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		SdkBytes resultBytes = encryptResponse.ciphertextBlob();
		String base64String = Utils.encodeBase64String(resultBytes.asByteArray());
		System.out.println("Ciphertext: " + base64String);
		
		//Decrypt
		byte[] tmpBytes = Utils.decodeBase64String(base64String);
		DecryptRequest decryptRequest = DecryptRequest.builder().ciphertextBlob(SdkBytes.fromByteArray(tmpBytes)).build();
		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		System.out.println("Plaintext: " + decryptResponse.plaintext().asUtf8String());
		
		System.out.println("Done.");
	}
}
